// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package filestore

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/v8/platform/shared/keyring"
)

func TestEncryptedBackend(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(keyring.KeyEnv, testMaster)
	t.Setenv(keyring.FactorEnv, "test-factor-0123456789")
	b, err := NewFileBackend(FileBackendSettings{DriverName: driverLocal, Directory: dir})
	require.NoError(t, err)

	for _, size := range []int{0, 1, segPlain - 1, segPlain, segPlain + 1, 3*segPlain + 17} {
		data := make([]byte, size)
		_, _ = rand.Read(data)
		n, err := b.WriteFile(bytes.NewReader(data), "f")
		require.NoError(t, err)
		assert.Equal(t, int64(size), n)

		raw, _ := os.ReadFile(filepath.Join(dir, "f"))
		if size > 16 {
			assert.False(t, bytes.Contains(raw, data[:16]), "plaintext must not reach disk")
		}
		got, err := b.ReadFile("f")
		require.NoError(t, err)
		assert.Equal(t, data, got, "size %d", size)
		s, err := b.FileSize("f")
		require.NoError(t, err)
		assert.Equal(t, int64(size), s)
	}

	data := make([]byte, 3*segPlain+100)
	_, _ = rand.Read(data)
	_, err = b.WriteFile(bytes.NewReader(data), "seek")
	require.NoError(t, err)
	r, err := b.Reader("seek")
	require.NoError(t, err)
	_, err = r.Seek(segPlain+5, io.SeekStart)
	require.NoError(t, err)
	part := make([]byte, segPlain)
	_, err = io.ReadFull(r, part)
	require.NoError(t, err)
	assert.Equal(t, data[segPlain+5:2*segPlain+5], part, "reads across a segment boundary after seek")
	r.Close()

	t.Run("append", func(t *testing.T) {
		_, err := b.WriteFile(bytes.NewReader([]byte("hello ")), "a")
		require.NoError(t, err)
		n, err := b.AppendFile(bytes.NewReader([]byte("world")), "a")
		require.NoError(t, err)
		assert.Equal(t, int64(5), n)
		got, _ := b.ReadFile("a")
		assert.Equal(t, "hello world", string(got))
	})

	t.Run("tamper and truncation are detected", func(t *testing.T) {
		p := filepath.Join(dir, "seek")
		raw, _ := os.ReadFile(p)
		flipped := bytes.Clone(raw)
		flipped[headerSize+10] ^= 1
		require.NoError(t, os.WriteFile(p, flipped, 0600))
		_, err := b.ReadFile("seek")
		assert.Error(t, err)

		require.NoError(t, os.WriteFile(p, raw[:headerSize+segCipher], 0600))
		_, err = b.ReadFile("seek")
		assert.Error(t, err, "dropping trailing segments must not yield a shorter valid file")
	})

	t.Run("legacy plaintext passes through", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "old"), []byte("plain old file"), 0600))
		got, err := b.ReadFile("old")
		require.NoError(t, err)
		assert.Equal(t, "plain old file", string(got))
	})

	t.Run("blob bound to its path", func(t *testing.T) {
		_, err := b.WriteFile(bytes.NewReader([]byte("secret A")), "x/a")
		require.NoError(t, err)
		raw, _ := os.ReadFile(filepath.Join(dir, "x/a"))
		assert.Equal(t, fileMagic, string(raw[:len(fileMagic)]))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "x/b"), raw, 0600))
		_, err = b.ReadFile("x/b")
		assert.Error(t, err, "a blob copied to another path must not decrypt")

		require.NoError(t, b.CopyFile("x/a", "x/c"))
		require.NoError(t, b.MoveFile("x/c", "x/d"))
		got, err := b.ReadFile("x/d")
		require.NoError(t, err)
		assert.Equal(t, "secret A", string(got))
		ok, _ := b.FileExists("x/c")
		assert.False(t, ok)
	})

	t.Run("MMENCF3 per-channel key, MMENCF2 still decrypts", func(t *testing.T) {
		assert.Equal(t, "t1/c1", pathScope("teams/t1/channels/c1/users/u1/f1/file.txt"))
		assert.Equal(t, "t1/c1", pathScope("bookmarkfile/teams/t1/channels/c1/x"))
		assert.Equal(t, "-/-", pathScope("teams/t1/x"))
		assert.Equal(t, "-/-", pathScope("brand/image.png"))

		p := "teams/t1/channels/c1/users/u1/f1/file.txt"
		_, err := b.WriteFile(bytes.NewReader([]byte("channel bound")), p)
		require.NoError(t, err)
		raw, _ := os.ReadFile(filepath.Join(dir, p))
		assert.Equal(t, "MMENCF3\x00", string(raw[:8]))
		got, err := b.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, "channel bound", string(got))

		cur, _, err := keyring.Load()
		require.NoError(t, err)
		eb := b.(*encryptedBackend)
		// The same header under the other channel's key must not open: the key, not only the AAD, is per channel.
		other, err := gcmKey(cur.Key(keyring.PurposeFileBlob), raw[8+kidSize:8+kidSize+saltSize], keyring.ChannelPurposePrefix+"t1/c2")
		require.NoError(t, err)
		_, err = other.Open(nil, segNonce(raw[8+kidSize+saltSize:headerSize], 0, true), raw[headerSize:], fileAAD(p))
		assert.Error(t, err)

		// MMENCF2: same layout, key info "segment".
		header := make([]byte, headerSize)
		copy(header, fileMagicV2)
		copy(header[8:], eb.kid)
		_, _ = rand.Read(header[8+kidSize:])
		aead, err := gcmKey(eb.fileKey[eb.kid], header[8+kidSize:8+kidSize+saltSize], "segment")
		require.NoError(t, err)
		data := make([]byte, segPlain+10)
		_, _ = rand.Read(data)
		enc := &encReader{src: bufio.NewReaderSize(bytes.NewReader(data), segPlain+1), aead: aead, prefix: header[8+kidSize+saltSize:], aad: fileAAD("v2"), out: header, buf: make([]byte, segPlain)}
		rawV2, err := io.ReadAll(enc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "v2"), rawV2, 0600))
		got, err = b.ReadFile("v2")
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})

	t.Run("legacy MMENCF1 files still decrypt", func(t *testing.T) {
		master, _ := base64.StdEncoding.DecodeString(testMaster)
		header := make([]byte, headerV1)
		copy(header, fileMagicV1)
		_, _ = rand.Read(header[len(fileMagicV1):])
		aead, err := gcmKey(master, header[len(fileMagicV1):len(fileMagicV1)+saltSize], "mattermost files v1")
		require.NoError(t, err)
		data := make([]byte, segPlain+10)
		_, _ = rand.Read(data)
		enc := &encReader{src: bufio.NewReaderSize(bytes.NewReader(data), segPlain+1), aead: aead, prefix: header[len(fileMagicV1)+saltSize:], out: header, buf: make([]byte, segPlain)}
		raw, err := io.ReadAll(enc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "v1"), raw, 0600))
		got, err := b.ReadFile("v1")
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})
}

const testMaster = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
