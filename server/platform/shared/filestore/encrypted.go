// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package filestore

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	pathpkg "path"
	"strings"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/v8/platform/shared/keyring"
)

// Files at rest use segmented streaming AEAD (the Tink AES-GCM-HKDF streaming / age STREAM design):
//
//	header  = magic(8) | kid(8) | salt(32) | noncePrefix(7)
//	segment = AES-256-GCM(key, noncePrefix | counter(4, big endian) | lastFlag(1), plaintext[≤64 KiB], AAD = path)
//	key     = HKDF-SHA256(fileKey, salt, info),  fileKey = keyring purpose "mrpostman/v3/file-blob"
//	info    = "mrpostman/v4/channel/<teamId>/<channelId>" (MMENCF3, scope parsed from the path:
//	          ".../teams/<teamId>/channels/<channelId>/...", anything else "-/-") or "segment" (MMENCF2)
//
// A fresh key per file keeps every key far below GCM's per-key limits, the counter stops segments
// being reordered, the last-segment flag stops a file being silently truncated, and the path as
// AAD stops a blob being swapped with another file's blob. Copy/Move therefore re-encrypt.
// MMENCF3 (current) additionally derives through the team + channel of the path, so a file's key is
// its channel's. MMENCF2 and legacy MMENCF1 files (no kid, no AAD, key = HKDF(master, salt,
// "mattermost files v1")) still decrypt. Files without a magic header are legacy plaintext and are
// passed through unchanged.

const (
	segPlain   = 64 * 1024
	tagSize    = 16
	segCipher  = segPlain + tagSize
	saltSize   = 32
	prefixSize = 7
	kidSize    = 8
	headerSize = len(fileMagic) + kidSize + saltSize + prefixSize
	headerV1   = len(fileMagicV1) + saltSize + prefixSize
)

const (
	fileMagic   = "MMENCF3\x00"
	fileMagicV2 = "MMENCF2\x00"
	fileMagicV1 = "MMENCF1\x00"
)

// pathScope is the v4 scope of a storage path: "<teamId>/<channelId>" from ".../teams/<t>/channels/<c>/...", else "-/-".
func pathScope(path string) string {
	parts := strings.Split(pathpkg.Clean("/"+path), "/")
	for i := 0; i+3 < len(parts); i++ {
		if parts[i] == "teams" && parts[i+2] == "channels" && parts[i+1] != "" && parts[i+3] != "" {
			return parts[i+1] + "/" + parts[i+3]
		}
	}
	return "-/-"
}

type encryptedBackend struct {
	FileBackend
	kid     string
	fileKey map[string][]byte // kid -> file-blob key, current and old
	masters [][]byte          // for MMENCF1
}

// withEncryption wraps backend when ENCRYPTION_KEY is set.
func withEncryption(backend FileBackend) (FileBackend, error) {
	cur, old, err := keyring.Load()
	if err != nil || cur == nil {
		return backend, err
	}
	b := &encryptedBackend{FileBackend: backend, kid: cur.KID(), fileKey: map[string][]byte{}}
	for _, r := range append([]*keyring.Root{cur}, old...) {
		if r.Factor != nil {
			b.fileKey[r.KID()] = r.Key(keyring.PurposeFileBlob)
		}
		b.masters = append(b.masters, r.Master)
	}
	return b, nil
}

func gcmKey(ikm, salt []byte, info string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, ikm, salt, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// fileAAD normalises path so "a//b" and "a/b" bind alike.
func fileAAD(path string) []byte {
	return []byte(pathpkg.Clean("/" + path))
}

func segNonce(prefix []byte, seg uint32, last bool) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[prefixSize:], seg)
	if last {
		n[11] = 1
	}
	return n
}

// encReader turns a plaintext stream into the encrypted file format.
type encReader struct {
	src    *bufio.Reader
	aead   cipher.AEAD
	prefix []byte
	seg    uint32
	out    []byte
	done   bool
	buf    []byte
	aad    []byte
}

func (b *encryptedBackend) newEncReader(src io.Reader, path string) (*encReader, error) {
	header := make([]byte, headerSize)
	copy(header, fileMagic)
	copy(header[len(fileMagic):], b.kid)
	salt := header[len(fileMagic)+kidSize : len(fileMagic)+kidSize+saltSize]
	if _, err := rand.Read(header[len(fileMagic)+kidSize:]); err != nil {
		return nil, err
	}
	aead, err := gcmKey(b.fileKey[b.kid], salt, keyring.ChannelPurposePrefix+pathScope(path))
	if err != nil {
		return nil, err
	}
	return &encReader{
		src:    bufio.NewReaderSize(src, segPlain+1),
		aead:   aead,
		prefix: header[len(fileMagic)+kidSize+saltSize:],
		aad:    fileAAD(path),
		out:    header,
		buf:    make([]byte, segPlain),
	}, nil
}

func (r *encReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.done {
			return 0, io.EOF
		}
		n, err := io.ReadFull(r.src, r.buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return 0, err
		}
		last := n < segPlain
		if !last {
			if _, perr := r.src.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return 0, perr
			}
		}
		r.out = r.aead.Seal(nil, segNonce(r.prefix, r.seg, last), r.buf[:n], r.aad)
		r.seg++
		r.done = last
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

// countingReader counts plaintext bytes so writes report the caller's size, not the ciphertext size.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (b *encryptedBackend) write(fr io.Reader, path string, write func(io.Reader) (int64, error)) (int64, error) {
	counter := &countingReader{r: fr}
	enc, err := b.newEncReader(counter, path)
	if err != nil {
		return 0, err
	}
	if _, err := write(enc); err != nil {
		return 0, err
	}
	return counter.n, nil
}

func (b *encryptedBackend) WriteFile(fr io.Reader, path string) (int64, error) {
	return b.write(fr, path, func(r io.Reader) (int64, error) { return b.FileBackend.WriteFile(r, path) })
}

func (b *encryptedBackend) WriteFileContext(ctx context.Context, fr io.Reader, path string) (int64, error) {
	return b.write(fr, path, func(r io.Reader) (int64, error) { return TryWriteFileContext(ctx, b.FileBackend, r, path) })
}

// AppendFile re-encrypts the whole file: a sealed last segment cannot be extended in place.
// ponytail: O(file size) per append; resumable uploads append a few large chunks, so this is acceptable.
func (b *encryptedBackend) AppendFile(fr io.Reader, path string) (int64, error) {
	old, err := b.Reader(path)
	if err != nil {
		return 0, err
	}
	existing, err := io.ReadAll(old)
	old.Close()
	if err != nil {
		return 0, err
	}
	counter := &countingReader{r: fr}
	if _, err := b.WriteFile(io.MultiReader(bytes.NewReader(existing), counter), path); err != nil {
		return 0, err
	}
	return counter.n, nil
}

func (b *encryptedBackend) Reader(path string) (ReadCloseSeeker, error) {
	inner, err := b.FileBackend.Reader(path)
	if err != nil {
		return nil, err
	}
	r, err := b.decrypting(inner, path)
	if err != nil {
		inner.Close()
		return nil, err
	}
	return r, nil
}

// decrypting returns a reader over inner's plaintext, or inner itself for legacy plaintext files.
func (b *encryptedBackend) decrypting(inner ReadCloseSeeker, path string) (ReadCloseSeeker, error) {
	header := make([]byte, headerSize)
	n, err := io.ReadFull(inner, header)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	header = header[:n]
	var candidates []cipher.AEAD
	var hdr int
	var prefix, aad []byte
	switch {
	case n >= headerSize && (string(header[:len(fileMagic)]) == fileMagic || string(header[:len(fileMagicV2)]) == fileMagicV2):
		hdr, aad = headerSize, fileAAD(path)
		kid := string(header[len(fileMagic) : len(fileMagic)+kidSize])
		key, ok := b.fileKey[kid]
		if !ok {
			return nil, errors.Errorf("encrypted file %s uses unknown key id %q", path, kid)
		}
		info := "segment" // MMENCF2
		if string(header[:len(fileMagic)]) == fileMagic {
			info = keyring.ChannelPurposePrefix + pathScope(path)
		}
		aead, err := gcmKey(key, header[len(fileMagic)+kidSize:len(fileMagic)+kidSize+saltSize], info)
		if err != nil {
			return nil, err
		}
		candidates, prefix = []cipher.AEAD{aead}, header[len(fileMagic)+kidSize+saltSize:]
	case n >= headerV1 && string(header[:len(fileMagicV1)]) == fileMagicV1:
		hdr = headerV1
		for _, m := range b.masters {
			aead, err := gcmKey(m, header[len(fileMagicV1):len(fileMagicV1)+saltSize], "mattermost files v1")
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, aead)
		}
		prefix = header[len(fileMagicV1)+saltSize : headerV1]
	default:
		if _, err := inner.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return inner, nil
	}
	total, err := inner.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	body := total - int64(hdr)
	segs := (body + segCipher - 1) / segCipher
	if segs == 0 {
		return nil, errors.Errorf("encrypted file %s is truncated", path)
	}
	// Legacy files carry no key id: the key that opens the first segment is the one.
	for _, aead := range candidates {
		r := &decReader{inner: inner, aead: aead, prefix: prefix, segs: segs, size: body - segs*tagSize, cur: -1, hdr: int64(hdr), aad: aad}
		if err = r.load(0); err == nil {
			return r, nil
		}
	}
	return nil, errors.Wrapf(err, "encrypted file %s", path)
}

// CopyFile re-encrypts: the destination path is bound into every segment.
func (b *encryptedBackend) CopyFile(oldPath, newPath string) error {
	r, err := b.Reader(oldPath)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = b.WriteFile(r, newPath)
	return err
}

func (b *encryptedBackend) MoveFile(oldPath, newPath string) error {
	if err := b.CopyFile(oldPath, newPath); err != nil {
		return err
	}
	return b.RemoveFile(oldPath)
}

// decReader decrypts one segment at a time and supports Seek.
type decReader struct {
	inner  ReadCloseSeeker
	aead   cipher.AEAD
	prefix []byte
	segs   int64
	size   int64
	pos    int64
	cur    int64
	plain  []byte
	cipher []byte
	hdr    int64
	aad    []byte
}

func (r *decReader) load(seg int64) error {
	if seg == r.cur {
		return nil
	}
	if _, err := r.inner.Seek(r.hdr+seg*segCipher, io.SeekStart); err != nil {
		return err
	}
	if r.cipher == nil {
		r.cipher = make([]byte, segCipher)
	}
	n, err := io.ReadFull(r.inner, r.cipher)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	plain, err := r.aead.Open(r.plain[:0], segNonce(r.prefix, uint32(seg), seg == r.segs-1), r.cipher[:n], r.aad)
	if err != nil {
		return errors.New("encrypted file is corrupt or was tampered with")
	}
	r.plain, r.cur = plain, seg
	return nil
}

func (r *decReader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	seg := r.pos / segPlain
	if err := r.load(seg); err != nil {
		return 0, err
	}
	n := copy(p, r.plain[r.pos-seg*segPlain:])
	r.pos += int64(n)
	return n, nil
}

func (r *decReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekCurrent:
		offset += r.pos
	case io.SeekEnd:
		offset += r.size
	}
	if offset < 0 {
		return 0, errors.New("negative seek position")
	}
	r.pos = offset
	return offset, nil
}

func (r *decReader) Close() error { return r.inner.Close() }

func (b *encryptedBackend) ReadFile(path string) ([]byte, error) {
	r, err := b.Reader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (b *encryptedBackend) FileSize(path string) (int64, error) {
	r, err := b.Reader(path)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	return r.Seek(0, io.SeekEnd)
}

// ZipReader zips the decrypted contents of path (a file or a directory).
func (b *encryptedBackend) ZipReader(path string, deflate bool) (io.ReadCloser, error) {
	files, err := b.ListDirectoryRecursively(path)
	if err != nil || len(files) == 0 {
		files = []string{path}
	}
	method := zip.Store
	if deflate {
		method = zip.Deflate
	}
	pr, pw := io.Pipe()
	go func() {
		zw := zip.NewWriter(pw)
		err := func() error {
			for _, f := range files {
				name := strings.TrimPrefix(strings.TrimPrefix(f, strings.TrimSuffix(path, "/")), "/")
				if name == "" {
					name = f[strings.LastIndex(f, "/")+1:]
				}
				w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
				if err != nil {
					return err
				}
				r, err := b.Reader(f)
				if err != nil {
					return err
				}
				_, err = io.Copy(w, r)
				r.Close()
				if err != nil {
					return err
				}
			}
			return zw.Close()
		}()
		pw.CloseWithError(err)
	}()
	return pr, nil
}
