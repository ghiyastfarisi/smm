// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	sq "github.com/mattermost/squirrel"
	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/v8/platform/shared/keyring"
)

// Keys come from the keyring package: ENCRYPTION_KEY (master) + ENCRYPTION_KEY_FACTOR (secret salt),
// with retired pairs in ENCRYPTION_KEY_OLD / ENCRYPTION_KEY_FACTOR_OLD (decrypt only).
// When set, Posts.Message and the other sensitive columns are stored AES-256-GCM encrypted and
// searched through HMAC-SHA256 word hashes (blind index) in *SearchTokens tables.
const (
	EncryptionKeyEnv    = keyring.KeyEnv
	EncryptionKeyOldEnv = keyring.KeyOldEnv
)

// Ciphertext formats:
//
//	enc:v1:<b64(nonce|ct)>                         legacy, master-only key, no key id, no AAD (decrypt only)
//	enc:v2:<kid>:<b64(nonce|ct)>                   legacy, master-only key, no AAD (decrypt only)
//	enc:v3:<kid>:<label>:<b64(nonce|ct)>           key = HKDF(master, factor, "mrpostman/v3/db-field"), AAD = label
//	enc:v4:<kid>:<scope>:<label>:<b64(nonce|ct)>   key = HKDF(master, factor, "mrpostman/v4/channel/" + scope), AAD = scope + ":" + label
//
// label = "<table>.<column>#<rowkey>" (see sealed). The label is authenticated as GCM additional
// data, so it cannot be altered, and readers that know the row (any scan into a struct carrying
// the row id) reject a ciphertext whose label names another row or column. Scans into bare
// strings cannot check location; they still get integrity and key binding.
//
// v4 is for channel data (posts, drafts, scheduled posts, file infos): scope = "<teamId>/<channelId>"
// ("-" for no team, e.g. DMs; "-/-" when the row has no channel), so every channel has its own data
// key and the GCM tag binds team, channel, table, column and row. Readers that know the row's channel
// also reject a v4 ciphertext whose scope names another channel. Global data (users, tokens, audits,
// team e-mail) stays v3; the blind-index HMAC key stays global because search spans channels.
const (
	encPrefix   = "enc:v1:"
	encPrefixV2 = "enc:v2:"
	encPrefixV3 = "enc:v3:"
	encPrefixV4 = "enc:v4:"
	noScope     = "-/-"
)

// ponytail: package-level so the sqlx wrapper can decrypt every read path in one place;
// becomes a SqlStore field if two stores with different keys ever share a process.
var (
	msgCipher    *postCipher
	cryptoLogger mlog.LoggerIFace
	decryptFails atomic.Int64
)

type postCipher struct {
	kid      string
	aead     cipher.AEAD
	byKid    map[string]cipher.AEAD   // v3: current and old (master, factor) pairs
	roots    map[string]*keyring.Root // v4: the same pairs, for per-scope derivation
	legacy   map[string]cipher.AEAD   // v2: master-only keys, by legacy kid
	legacyV1 []cipher.AEAD            // v1: tried in order
	hmacKey  []byte

	// teamOf resolves a channel's team id for new v4 writes (injected by SqlStore; nil → "-").
	teamOf func(channelID string) (string, error)
	mu     sync.Mutex
	teams  map[string]string      // channelId → teamId
	scoped map[string]cipher.AEAD // kid + ":" + scope → derived AEAD
}

// ponytail: plain maps dropped wholesale at the cap; an LRU is overkill for ids this small.
const cipherCacheCap = 8192

func isSealed(s string) bool {
	return strings.HasPrefix(s, "enc:v")
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// newPostCipher builds the cipher from raw env values (see keyring.Parse).
func newPostCipher(key, factor, oldKeys, oldFactors string) (*postCipher, error) {
	cur, old, err := keyring.Parse(key, factor, oldKeys, oldFactors)
	if err != nil {
		return nil, err
	}
	return newPostCipherFromRoots(cur, old)
}

func newPostCipherFromRoots(cur *keyring.Root, old []*keyring.Root) (*postCipher, error) {
	c := &postCipher{byKid: map[string]cipher.AEAD{}, roots: map[string]*keyring.Root{}, legacy: map[string]cipher.AEAD{}, hmacKey: cur.Key(keyring.PurposeBlindIndex),
		teams: map[string]string{}, scoped: map[string]cipher.AEAD{}}
	for i, r := range append([]*keyring.Root{cur}, old...) {
		if r.Factor != nil {
			aead, err := newGCM(r.Key(keyring.PurposeDBField))
			if err != nil {
				return nil, err
			}
			if i == 0 {
				c.kid, c.aead = r.KID(), aead
			}
			if _, dup := c.byKid[r.KID()]; !dup {
				c.byKid[r.KID()] = aead
				c.roots[r.KID()] = r
			}
		}
		// Every master key also opens what it sealed before factors existed.
		aead, err := newGCM(r.Legacy("mattermost posts enc v1", nil))
		if err != nil {
			return nil, err
		}
		if _, dup := c.legacy[r.LegacyKID()]; !dup {
			c.legacy[r.LegacyKID()] = aead
			c.legacyV1 = append(c.legacyV1, aead)
		}
	}
	return c, nil
}

// label binds a ciphertext to its location; parts must not contain ':'.
func label(field, rowKey string) string {
	return field + "#" + rowKey
}

// encrypt seals global (non-channel) data as v3.
func (c *postCipher) encrypt(plain, aad string) string {
	if plain == "" {
		return ""
	}
	nonce := make([]byte, c.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return encPrefixV3 + c.kid + ":" + aad + ":" + base64.StdEncoding.EncodeToString(c.aead.Seal(nonce, nonce, []byte(plain), []byte(aad)))
}

// encryptIn seals channel data as v4 under the key of scope (see scopeOf).
func (c *postCipher) encryptIn(plain, scope, aad string) string {
	if plain == "" {
		return ""
	}
	aead, err := c.scopedAEAD(c.kid, scope)
	if err != nil {
		panic(err) // the current root always exists; AES key setup cannot fail for 32 bytes
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	ad := scope + ":" + aad
	return encPrefixV4 + c.kid + ":" + ad + ":" + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plain), []byte(ad)))
}

// scopedAEAD derives (and caches) the v4 AEAD of scope under the root named by kid.
func (c *postCipher) scopedAEAD(kid, scope string) (cipher.AEAD, error) {
	root := c.roots[kid]
	if root == nil {
		return nil, errors.Errorf("unknown key id %q", kid)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if aead := c.scoped[kid+":"+scope]; aead != nil {
		return aead, nil
	}
	aead, err := newGCM(root.ChannelKey(scope))
	if err != nil {
		return nil, err
	}
	if len(c.scoped) >= cipherCacheCap {
		clear(c.scoped)
	}
	c.scoped[kid+":"+scope] = aead
	return aead, nil
}

// scopeOf is the v4 scope of a channel: "<teamId>/<channelId>", "-" for an unknown or absent team
// (DMs/GMs) and "-/-" for no channel. Ids are alphanumeric; anything with ':' or '/' falls back to "-/-".
// ponytail: the team of a channel is cached for the process lifetime; a channel moved to another
// team keeps sealing under its old team id until restart (still decryptable: the scope travels
// with the ciphertext). Add invalidation if channel moves become routine.
func (c *postCipher) scopeOf(channelID string) string {
	if channelID == "" || strings.ContainsAny(channelID, ":/") {
		return noScope
	}
	c.mu.Lock()
	team, ok := c.teams[channelID]
	c.mu.Unlock()
	if !ok && c.teamOf != nil {
		t, err := c.teamOf(channelID)
		if err != nil {
			if cryptoLogger != nil {
				cryptoLogger.Warn("Failed to resolve the team of a channel; sealing without a team id", mlog.String("channel_id", channelID), mlog.Err(err))
			}
		} else if !strings.ContainsAny(t, ":/") {
			team = t
			c.mu.Lock()
			if len(c.teams) >= cipherCacheCap {
				clear(c.teams)
			}
			c.teams[channelID] = t
			c.mu.Unlock()
		}
	}
	if team == "" {
		team = "-"
	}
	return team + "/" + channelID
}

// decrypt returns s unchanged when it is not ciphertext, so legacy plaintext rows keep working.
// Ciphertext that fails to decrypt is logged and returned raw rather than crashing the caller.
func (c *postCipher) decrypt(s string) string {
	return c.decryptAt(s, "", "", "")
}

// decryptAt also checks a v3/v4 label against the reader's location when known (column, row key
// and, for v4, the row's channel).
func (c *postCipher) decryptAt(s, column, rowKey, channelID string) string {
	if !isSealed(s) {
		return s
	}
	plain, scope, aad, ok := c.open(s)
	if ok && aad != "" {
		field, key, _ := strings.Cut(aad, "#")
		_, col, _ := strings.Cut(field, ".")
		// A field must name the label's column ("Message", or an alias ending in it such as
		// "PostMessage"/"UserEmail" in joined exports). Row keys and channels are compared only when
		// the field maps directly to the column, as aliased fields sit next to another table's Id.
		if column != "" && (!strings.HasSuffix(column, col) || (column == col && rowKey != "" && key != rowKey)) {
			ok = false
		}
		if _, ch, _ := strings.Cut(scope, "/"); column == col && channelID != "" && scope != "" && ch != channelID {
			ok = false
		}
	}
	if ok {
		return plain
	}
	// ponytail: logs the 1st and every 1000th failure to avoid flooding; add a metric if ops needs counts.
	if n := decryptFails.Add(1); (n == 1 || n%1000 == 0) && cryptoLogger != nil {
		cryptoLogger.Error("Failed to decrypt stored value: wrong or missing key, corrupt ciphertext, or ciphertext moved from another row",
			mlog.String("prefix", s[:min(len(s), 16)]), mlog.Int("failures", n))
	}
	return s
}

// open returns the plaintext and, for v3/v4, the authenticated label (and the v4 scope).
func (c *postCipher) open(s string) (plain, scope, aad string, ok bool) {
	var aeads []cipher.AEAD
	var body, ad string
	switch {
	case strings.HasPrefix(s, encPrefixV4):
		parts := strings.SplitN(s[len(encPrefixV4):], ":", 4)
		if len(parts) != 4 {
			return "", "", "", false
		}
		aead, err := c.scopedAEAD(parts[0], parts[1])
		if err != nil {
			return "", "", "", false
		}
		scope, aad, body = parts[1], parts[2], parts[3]
		aeads, ad = []cipher.AEAD{aead}, scope+":"+aad
	case strings.HasPrefix(s, encPrefixV3):
		parts := strings.SplitN(s[len(encPrefixV3):], ":", 3)
		if len(parts) != 3 || c.byKid[parts[0]] == nil {
			return "", "", "", false
		}
		aeads, aad, body = []cipher.AEAD{c.byKid[parts[0]]}, parts[1], parts[2]
		ad = aad
	case strings.HasPrefix(s, encPrefixV2):
		kid, rest, found := strings.Cut(s[len(encPrefixV2):], ":")
		if !found || c.legacy[kid] == nil {
			return "", "", "", false
		}
		aeads, body = []cipher.AEAD{c.legacy[kid]}, rest
	case strings.HasPrefix(s, encPrefix):
		aeads, body = c.legacyV1, s[len(encPrefix):]
	default:
		return "", "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", "", "", false
	}
	for _, aead := range aeads {
		ns := aead.NonceSize()
		if len(raw) < ns {
			return "", "", "", false
		}
		var adb []byte
		if ad != "" {
			adb = []byte(ad)
		}
		if p, err := aead.Open(nil, raw[:ns], raw[ns:], adb); err == nil {
			return string(p), scope, aad, true
		}
	}
	return "", "", "", false
}

func (c *postCipher) hashWord(word string) string {
	m := hmac.New(sha256.New, c.hmacKey)
	m.Write([]byte(strings.ToLower(word)))
	return hex.EncodeToString(m.Sum(nil))
}

// tokens returns the distinct word hashes of text. Search is exact-word only.
func (c *postCipher) tokens(text string) []string {
	words := strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	seen := make(map[string]bool, len(words))
	hashes := make([]string, 0, len(words))
	for _, w := range words {
		h := c.hashWord(w)
		if !seen[h] {
			seen[h] = true
			hashes = append(hashes, h)
		}
	}
	return hashes
}

// PrefixSearchEnv set to "true" also indexes word prefixes (3–16 characters), so trailing-wildcard searches
// ("alph*") work on encrypted posts and files. Off by default: the extra hashes show someone holding the
// database which words share a prefix, on top of the word equality the index already shows. Only text
// indexed while it is on gets prefix hashes.
const PrefixSearchEnv = "ENCRYPTION_PREFIX_SEARCH"

const minSearchPrefix, maxSearchPrefix = 3, 16

func prefixSearch() bool { return os.Getenv(PrefixSearchEnv) == "true" }

func searchWords(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
}

// indexTokens is what gets stored for text: its word hashes plus, with prefix search on, its prefix hashes.
func (c *postCipher) indexTokens(text string) []string {
	hashes := c.tokens(text)
	if !prefixSearch() {
		return hashes
	}
	seen := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		seen[h] = true
	}
	for _, w := range searchWords(text) {
		r := []rune(strings.ToLower(w))
		for n := minSearchPrefix; n <= len(r) && n <= maxSearchPrefix; n++ {
			if h := c.hashWord("*" + string(r[:n])); !seen[h] {
				seen[h] = true
				hashes = append(hashes, h)
			}
		}
	}
	return hashes
}

// queryTokens hashes search terms. With prefix search on, "word*" becomes the hash of its prefix (cut to
// maxSearchPrefix; matchesSearchTerms re-checks the whole prefix); everything else its exact word hashes.
func (c *postCipher) queryTokens(terms string) []string {
	var hashes []string
	for _, f := range strings.Fields(terms) {
		words := searchWords(f)
		if !strings.HasSuffix(f, "*") || !prefixSearch() || len(words) == 0 {
			hashes = append(hashes, c.tokens(f)...)
			continue
		}
		for _, w := range words[:len(words)-1] { // "t-shirt*": exact "t", prefix "shirt"
			hashes = append(hashes, c.hashWord(w))
		}
		last := []rune(strings.ToLower(words[len(words)-1]))
		if len(last) < minSearchPrefix {
			hashes = append(hashes, c.hashWord(string(last))) // too short to be indexed as a prefix
		} else {
			hashes = append(hashes, c.hashWord("*"+string(last[:min(len(last), maxSearchPrefix)])))
		}
	}
	return hashes
}

var quotedPhrase = regexp.MustCompile(`"([^"]+)"`)

// matchesSearchTerms re-checks a decrypted message against what the hash index can't express: quoted
// phrases must appear as consecutive words, and long wildcard prefixes must match in full.
func matchesSearchTerms(message, terms string) bool {
	words := searchWords(strings.ToLower(message))
	for _, m := range quotedPhrase.FindAllStringSubmatch(terms, -1) {
		if !containsRun(words, searchWords(strings.ToLower(m[1]))) {
			return false
		}
	}
	for _, f := range strings.Fields(quotedPhrase.ReplaceAllString(terms, " ")) {
		w := searchWords(strings.ToLower(f))
		if !strings.HasSuffix(f, "*") || len(w) == 0 || len([]rune(w[len(w)-1])) <= maxSearchPrefix {
			continue
		}
		prefix, found := w[len(w)-1], false
		for _, x := range words {
			if strings.HasPrefix(x, prefix) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// containsRun reports whether run appears in words as consecutive elements.
func containsRun(words, run []string) bool {
	if len(run) == 0 {
		return true
	}
	for i := 0; i+len(run) <= len(words); i++ {
		match := true
		for j := range run {
			if words[i+j] != run[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// hashtagHashes hashes each "#tag" field; hashtags are indexed alongside words with the '#' kept.
func (c *postCipher) hashtagHashes(text string) []string {
	var hashes []string
	for _, f := range strings.Fields(text) {
		hashes = append(hashes, c.hashWord("#"+strings.TrimLeft(f, "#")))
	}
	return hashes
}

// cipherCap is how many plaintext bytes fit in a column of maxBytes once encrypted:
// prefix + base64(nonce|ciphertext|tag) is 4/3 of the plaintext plus a fixed overhead.
func cipherCap(maxBytes int32) int32 {
	if msgCipher == nil || maxBytes <= 0 {
		return maxBytes
	}
	return maxBytes*3/4 - 192 // prefix, kid, v4 scope and AAD label (~120 bytes) plus nonce and tag
}

// sealPosts returns encrypted clones of posts (the caller's posts are never mutated, so
// concurrent readers never see ciphertext) and the search tokens of the live posts.
func sealPosts(posts ...*model.Post) (sealedPosts []*model.Post, tokenRows [][2]string) {
	if msgCipher == nil {
		return posts, nil
	}
	sealedPosts = make([]*model.Post, len(posts))
	for i, p := range posts {
		if p.DeleteAt == 0 {
			for _, h := range append(msgCipher.indexTokens(p.Message), msgCipher.hashtagHashes(p.Hashtags)...) {
				tokenRows = append(tokenRows, [2]string{p.Id, h})
			}
		}
		c := p.Clone()
		scope := msgCipher.scopeOf(p.ChannelId)
		c.Message = msgCipher.encryptIn(p.Message, scope, label("posts.message", p.Id))
		c.Hashtags = msgCipher.encryptIn(p.Hashtags, scope, label("posts.hashtags", p.Id))
		sealPostProps(c, scope)
		sealedPosts[i] = c
	}
	return sealedPosts, tokenRows
}

// sealFileInfo returns an encrypted copy of info (name and extracted text) and their search tokens.
func sealFileInfo(info *model.FileInfo) (*model.FileInfo, [][2]string) {
	if msgCipher == nil {
		return info, nil
	}
	var tokenRows [][2]string
	for _, h := range msgCipher.indexTokens(info.Name + " " + info.Content) {
		tokenRows = append(tokenRows, [2]string{info.Id, h})
	}
	c := *info
	scope := msgCipher.scopeOf(info.ChannelId)
	c.Name, c.Content = msgCipher.encryptIn(info.Name, scope, label("fileinfo.name", info.Id)), msgCipher.encryptIn(info.Content, scope, label("fileinfo.content", info.Id))
	return &c, tokenRows
}

type builderExecer interface {
	ExecBuilder(builder Builder) (sql.Result, error)
}

func saveSearchTokens(ss *SqlStore, db builderExecer, rows [][2]string) error {
	return saveTokens(ss, db, "PostSearchTokens", "PostId", rows)
}

// replaceFileSearchTokens re-indexes one file; rows are (fileId, tokenHash).
func replaceFileSearchTokens(ss *SqlStore, db builderExecer, fileID string, rows [][2]string) error {
	if msgCipher == nil {
		return nil
	}
	if _, err := db.ExecBuilder(ss.getQueryBuilder().Delete("FileSearchTokens").Where(sq.Eq{"FileId": fileID})); err != nil {
		return errors.Wrap(err, "failed to delete file search tokens")
	}
	return saveTokens(ss, db, "FileSearchTokens", "FileId", rows)
}

func saveTokens(ss *SqlStore, db builderExecer, table, idCol string, rows [][2]string) error {
	for _, chunk := range chunkSlice(rows, 2, ss.getMaxInsertParams()) {
		b := ss.getQueryBuilder().Insert(table).Columns(idCol, "TokenHash").Suffix("ON CONFLICT DO NOTHING")
		for _, r := range chunk {
			b = b.Values(r[0], r[1])
		}
		if _, err := db.ExecBuilder(b); err != nil {
			return errors.Wrap(err, "failed to save search tokens")
		}
	}
	return nil
}

func (s *SqlPostStore) replaceSearchTokens(db builderExecer, postIDs []string, rows [][2]string) error {
	if msgCipher == nil {
		return nil
	}
	if _, err := db.ExecBuilder(s.getQueryBuilder().Delete("PostSearchTokens").Where(sq.Eq{"PostId": postIDs})); err != nil {
		return errors.Wrap(err, "failed to delete post search tokens")
	}
	return saveSearchTokens(s.SqlStore, db, rows)
}

// tokenSearchClause matches rows whose id column (as in sub) has every include hash (any with orTerms)
// and none of the exclude hashes.
func tokenSearchClause(sub string, include, exclude []string, orTerms bool) sq.Sqlizer {
	var match []sq.Sqlizer
	for _, h := range include {
		match = append(match, sq.Expr(sub, h))
	}
	clause := sq.And{}
	if len(match) > 0 {
		if orTerms {
			clause = append(clause, sq.Or(match))
		} else {
			clause = append(clause, sq.And(match))
		}
	}
	for _, h := range exclude {
		clause = append(clause, sq.Expr("NOT "+sub, h))
	}
	return clause
}

// hashToken is how bearer secrets (session and personal access tokens) are stored:
// they are only ever compared, so a database dump yields nothing replayable.
// Unkeyed SHA-256 is enough for 26-char random ids (~130 bits).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sealed returns s encrypted (v3, global key) for column field ("table.column", lowercase) of row
// rowKey when encryption is on. rowKey is the row's Id (or draftKey for drafts).
func sealed(field, rowKey, s string) string {
	if msgCipher == nil {
		return s
	}
	return msgCipher.encrypt(s, label(field, rowKey))
}

// sealedIn is sealed for channel data: v4 under the key of channelID's team + channel.
func sealedIn(channelID, field, rowKey, s string) string {
	if msgCipher == nil {
		return s
	}
	return msgCipher.encryptIn(s, msgCipher.scopeOf(channelID), label(field, rowKey))
}

// draftKey is the row key of a draft (Drafts has no Id column).
func draftKey(userID, channelID, rootID string) string {
	return userID + "_" + channelID + "_" + rootID
}

// encryptLegacyTokens encrypts integration tokens written before ENCRYPTION_KEY was set,
// and re-seals v1/v2 tokens as v3.
func (ss *SqlStore) encryptLegacyTokens() error {
	if msgCipher == nil {
		return nil
	}
	for _, table := range []string{"OutgoingWebhooks", "Commands"} {
		var rows []struct{ Id, Token string }
		if err := ss.GetMaster().Select(&rows, "SELECT Id, Token FROM "+table+" WHERE Token NOT LIKE 'enc:v3:%' AND Token <> ''"); err != nil {
			return errors.Wrapf(err, "failed to read %s tokens", table)
		}
		for _, r := range rows {
			if isSealed(r.Token) {
				continue // undecryptable: leave it rather than double-encrypt
			}
			if _, err := ss.GetMaster().Exec("UPDATE "+table+" SET Token = ? WHERE Id = ?", msgCipher.encrypt(r.Token, label(strings.ToLower(table)+".token", r.Id)), r.Id); err != nil {
				return errors.Wrapf(err, "failed to encrypt %s token", table)
			}
		}
	}
	return nil
}

// decryptDest decrypts, in place, every ciphertext string reachable from a scan destination.
func decryptDest(dest any) {
	if msgCipher != nil {
		decryptValue(reflect.ValueOf(dest), 0, "", "")
	}
}

// rowKeyOf is the row key of a scanned struct (its Id, promoted fields included, or the draft key)
// and its channel id when it carries one.
func rowKeyOf(v reflect.Value) (rowKey, channelID string) {
	str := func(name string) string {
		if f := v.FieldByName(name); f.IsValid() && f.Kind() == reflect.String {
			return f.String()
		}
		return ""
	}
	channelID = str("ChannelId")
	if id := str("Id"); id != "" {
		return id, channelID
	}
	if u := str("UserId"); u != "" && channelID != "" && v.Type() == reflect.TypeFor[model.Draft]() {
		return draftKey(u, channelID, str("RootId")), channelID
	}
	return "", channelID
}

// decryptValue walks a scan destination. Strings inside a struct are checked against the
// struct's row key, channel and their column name; embedded structs inherit the outer location.
func decryptValue(v reflect.Value, depth int, rowKey, channelID string) {
	// Scan destinations are shallow (e.g. *[]*postWithExtra → Post → Message is depth 5).
	if depth > 8 {
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			decryptValue(v.Elem(), depth+1, rowKey, channelID)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < v.Len(); i++ {
			decryptValue(v.Index(i), depth+1, "", "")
		}
	case reflect.Struct:
		if rowKey == "" {
			rowKey, channelID = rowKeyOf(v)
		}
		for i := 0; i < v.NumField(); i++ {
			f, fv := v.Type().Field(i), v.Field(i)
			switch {
			case f.Anonymous:
				decryptValue(fv, depth+1, rowKey, channelID)
			case !f.IsExported():
			case fv.Kind() == reflect.String:
				if fv.CanSet() && isSealed(fv.String()) {
					col := strings.ToLower(f.Name)
					if tag, _, _ := strings.Cut(f.Tag.Get("db"), ","); tag != "" && tag != "-" {
						col = strings.ToLower(tag)
					}
					fv.SetString(msgCipher.decryptAt(fv.String(), col, rowKey, channelID))
				}
			case fv.Kind() == reflect.Map:
				decryptMap(fv, rowKey, channelID)
			default:
				decryptValue(fv, depth+1, "", "")
			}
		}
	case reflect.String:
		if v.CanSet() && isSealed(v.String()) {
			v.SetString(msgCipher.decrypt(v.String()))
		}
	}
}

// EncryptionBackfillEnv set to "true" makes startup encrypt plaintext posts and file infos, re-seal
// v1/v2/v3 ones as v4 (per-channel keys, current root) and rebuild their search tokens with the
// current blind-index key.
const EncryptionBackfillEnv = "ENCRYPTION_BACKFILL"

// backfillPosts encrypts or re-seals posts not yet in v4 under the current kid, 1000 per transaction.
// ponytail: runs synchronously at startup; move to a job if the backlog is large.
func (ss *SqlStore) backfillPosts() error {
	if msgCipher == nil || os.Getenv(EncryptionBackfillEnv) != "true" {
		return nil
	}
	ps := &SqlPostStore{SqlStore: ss}
	current := encPrefixV4 + msgCipher.kid + ":%"
	total, skipped, after := 0, 0, ""
	for {
		var posts []*model.Post
		if err := ss.GetMaster().Select(&posts, "SELECT Id, ChannelId, Message, Hashtags, DeleteAt FROM Posts WHERE Id > ? AND Message <> '' AND Message NOT LIKE ? ORDER BY Id LIMIT 1000", after, current); err != nil {
			return errors.Wrap(err, "failed to read posts to backfill")
		}
		if len(posts) == 0 {
			break
		}
		after = posts[len(posts)-1].Id
		ok := posts[:0]
		for _, p := range posts {
			if isSealed(p.Message) || isSealed(p.Hashtags) {
				skipped++ // undecryptable (missing old key): leave untouched
				continue
			}
			ok = append(ok, p)
		}
		if len(ok) > 0 {
			if err := ps.backfillPostBatch(ok); err != nil {
				return err
			}
		}
		total += len(ok)
	}
	if total > 0 || skipped > 0 {
		ss.Logger().Info("Backfilled post encryption", mlog.Int("count", total), mlog.Int("undecryptable", skipped))
	}
	return ss.backfillFileInfos()
}

// backfillFileInfos re-seals file names/contents not yet in v4 under the current kid and re-indexes them.
func (ss *SqlStore) backfillFileInfos() error {
	total, after := 0, ""
	current := encPrefixV4 + msgCipher.kid + ":%"
	for {
		var infos []*model.FileInfo
		if err := ss.GetMaster().Select(&infos, "SELECT Id, COALESCE(ChannelId, '') AS ChannelId, Name, Content FROM FileInfo WHERE Id > ? AND Name <> '' AND Name NOT LIKE ? ORDER BY Id LIMIT 1000", after, current); err != nil {
			return errors.Wrap(err, "failed to read file infos to backfill")
		}
		if len(infos) == 0 {
			break
		}
		after = infos[len(infos)-1].Id
		for _, info := range infos {
			if isSealed(info.Name) || isSealed(info.Content) {
				continue
			}
			si, rows := sealFileInfo(info)
			if _, err := ss.GetMaster().Exec("UPDATE FileInfo SET Name = ?, Content = ? WHERE Id = ?", si.Name, si.Content, info.Id); err != nil {
				return errors.Wrapf(err, "failed to encrypt file info %s", info.Id)
			}
			if err := replaceFileSearchTokens(ss, ss.GetMaster(), info.Id, rows); err != nil {
				return err
			}
			total++
		}
	}
	if total > 0 {
		ss.Logger().Info("Backfilled file info encryption", mlog.Int("count", total))
	}
	return nil
}

func (s *SqlPostStore) backfillPostBatch(posts []*model.Post) (err error) {
	sealedPosts, tokenRows := sealPosts(posts...)
	tx, err := s.GetMaster().Begin()
	if err != nil {
		return errors.Wrap(err, "begin_transaction")
	}
	defer finalizeTransactionX(tx, &err)
	ids := make([]string, len(posts))
	for i, p := range sealedPosts {
		ids[i] = p.Id
		if _, err = tx.Exec("UPDATE Posts SET Message = ?, Hashtags = ? WHERE Id = ?", p.Message, p.Hashtags, p.Id); err != nil {
			return errors.Wrapf(err, "failed to encrypt post %s", p.Id)
		}
	}
	if err = s.replaceSearchTokens(tx, ids, tokenRows); err != nil {
		return err
	}
	return tx.Commit()
}
