// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/platform/shared/keyring"
)

const (
	testRootKey  = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes
	testRootKey2 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=" // 32 bytes
	testFactor   = "factor-one-0123456789"
	testFactor2  = "factor-two-0123456789"
)

func testCipher(t *testing.T, key, factor string, old ...string) *postCipher {
	t.Helper()
	var oldKeys, oldFactors string
	if len(old) == 2 {
		oldKeys, oldFactors = old[0], old[1]
	}
	c, err := newPostCipher(key, factor, oldKeys, oldFactors)
	require.NoError(t, err)
	return c
}

// legacyEncrypt reproduces the pre-factor v1/v2 formats (master-only key, no AAD).
func legacyEncrypt(t *testing.T, masterB64, plain string, v2 bool) string {
	m, err := base64.StdEncoding.DecodeString(masterB64)
	require.NoError(t, err)
	r := &keyring.Root{Master: m}
	aead, err := newGCM(r.Legacy("mattermost posts enc v1", nil))
	require.NoError(t, err)
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	body := base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plain), nil))
	if v2 {
		return encPrefixV2 + r.LegacyKID() + ":" + body
	}
	return encPrefix + body
}

func TestKeyringDerivation(t *testing.T) {
	cur, _, err := keyring.Parse(testRootKey, testFactor, "", "")
	require.NoError(t, err)
	again, _, _ := keyring.Parse(testRootKey, testFactor, "", "")
	assert.Equal(t, cur.Key(keyring.PurposeDBField), again.Key(keyring.PurposeDBField), "deterministic")

	otherFactor, _, _ := keyring.Parse(testRootKey, testFactor2, "", "")
	otherMaster, _, _ := keyring.Parse(testRootKey2, testFactor, "", "")
	k := cur.Key(keyring.PurposeDBField)
	assert.NotEqual(t, k, otherFactor.Key(keyring.PurposeDBField), "factor changes the key")
	assert.NotEqual(t, k, otherMaster.Key(keyring.PurposeDBField), "master changes the key")
	assert.NotEqual(t, k, cur.Legacy("mattermost posts enc v1", nil), "master alone does not give the key")
	assert.NotEqual(t, k, cur.Key(keyring.PurposeBlindIndex), "purposes are separated")
	assert.NotEqual(t, cur.Key(keyring.PurposeFileBlob), cur.Key(keyring.PurposeBlindIndex))
	assert.NotEqual(t, cur.KID(), otherFactor.KID())

	_, _, err = keyring.Parse(testRootKey, "", "", "")
	assert.Error(t, err, "factor is required")
	_, _, err = keyring.Parse(testRootKey, "short", "", "")
	assert.Error(t, err, "factor must be long enough")
	_, _, err = keyring.Parse("dG9vc2hvcnQ=", testFactor, "", "")
	assert.Error(t, err)
	_, _, err = keyring.Parse(testRootKey, testFactor, "dG9vc2hvcnQ=", "")
	assert.Error(t, err, "bad old key is rejected")
}

func TestPostCipher(t *testing.T) {
	c := testCipher(t, testRootKey, testFactor)
	aad := label("posts.message", "p1")
	enc := c.encrypt("hello wörld", aad)
	assert.True(t, strings.HasPrefix(enc, encPrefixV3+c.kid+":posts.message#p1:"), "writes are v3 with key id and label")
	assert.Len(t, c.kid, 8)
	assert.NotEqual(t, enc, c.encrypt("hello wörld", aad), "nonce must be random")
	assert.Equal(t, "hello wörld", c.decrypt(enc))
	assert.Equal(t, "hello wörld", c.decryptAt(enc, "message", "p1", ""))
	assert.Equal(t, "legacy plaintext", c.decrypt("legacy plaintext"))
	assert.Equal(t, enc[:len(enc)-2]+"AA", c.decrypt(enc[:len(enc)-2]+"AA"), "tampered ciphertext is not decrypted")

	t.Run("AAD binds row and column", func(t *testing.T) {
		assert.Equal(t, enc, c.decryptAt(enc, "message", "p2", ""), "moved to another row")
		assert.Equal(t, enc, c.decryptAt(enc, "hashtags", "p1", ""), "moved to another column")
		forged := strings.Replace(enc, "#p1:", "#p2:", 1)
		assert.Equal(t, forged, c.decrypt(forged), "rewriting the visible label breaks the tag")

		a := []*model.Post{{Id: "a", Message: c.encrypt("for a", label("posts.message", "a"))}, {Id: "b", Message: c.encrypt("for b", label("posts.message", "b"))}}
		a[0].Message, a[1].Message = a[1].Message, a[0].Message
		swapped := []string{a[0].Message, a[1].Message}
		decryptDest(&a) // msgCipher nil → no-op
		msgCipher = c
		defer func() { msgCipher = nil }()
		decryptDest(&a)
		assert.Equal(t, swapped, []string{a[0].Message, a[1].Message}, "swapped rows do not decrypt")

		msg := c.encrypt("post text", label("posts.message", "p9"))
		u := &model.User{Id: "u1", Nickname: msg, Email: c.encrypt("x@y.z", label("users.email", "u2"))}
		decryptDest(u)
		assert.Equal(t, msg, u.Nickname, "post ciphertext copied into a nickname does not decrypt")
		assert.True(t, isSealed(u.Email), "another user's email does not decrypt")

		cp := &model.CompliancePost{PostId: "p9", PostMessage: msg, UserEmail: c.encrypt("x@y.z", label("users.email", "u2"))}
		decryptDest(cp)
		assert.Equal(t, "post text", cp.PostMessage, "aliased join columns decrypt")
		assert.Equal(t, "x@y.z", cp.UserEmail)
	})

	t.Run("v1/v2 still decrypt", func(t *testing.T) {
		assert.Equal(t, "old v2", c.decrypt(legacyEncrypt(t, testRootKey, "old v2", true)))
		assert.Equal(t, "old v1", c.decryptAt(legacyEncrypt(t, testRootKey, "old v1", false), "message", "x", ""))
	})

	assert.Equal(t, c.tokens("Deploy deploy, DEPLOY!"), []string{c.hashWord("deploy")})
	assert.ElementsMatch(t, c.tokens("ship v2 now"), []string{c.hashWord("ship"), c.hashWord("v2"), c.hashWord("now")})
}

func TestPostCipherRotation(t *testing.T) {
	oldC := testCipher(t, testRootKey, testFactor)
	oldV3 := oldC.encrypt("old v3", "posts.message#x")
	oldV2 := legacyEncrypt(t, testRootKey, "old v2", true)
	oldV1 := legacyEncrypt(t, testRootKey, "old v1", false)

	rotated := testCipher(t, testRootKey2, testFactor2, testRootKey, testFactor)
	assert.NotEqual(t, oldC.kid, rotated.kid)
	assert.Equal(t, "old v3", rotated.decrypt(oldV3), "old pair decrypts v3 by kid")
	assert.Equal(t, "old v2", rotated.decrypt(oldV2), "old master decrypts v2")
	assert.Equal(t, "old v1", rotated.decrypt(oldV1), "old master decrypts v1")
	assert.True(t, strings.HasPrefix(rotated.encrypt("x", "a.b#c"), encPrefixV3+rotated.kid+":"), "new writes use the current pair")

	factorOnly := testCipher(t, testRootKey, testFactor2)
	assert.Equal(t, oldV3, factorOnly.decrypt(oldV3), "same master, new factor: old v3 needs the old factor")
	assert.Equal(t, "old v2", factorOnly.decrypt(oldV2), "v2 depends on the master only")

	noOld := testCipher(t, testRootKey2, testFactor2)
	assert.Equal(t, oldV3, noOld.decrypt(oldV3), "without the old pair the value stays raw")
	assert.Equal(t, oldV2, noOld.decrypt(oldV2))
	assert.Equal(t, oldV1, noOld.decrypt(oldV1))
}

func TestSealPostsAndDecryptDest(t *testing.T) {
	c := testCipher(t, testRootKey, testFactor)
	msgCipher = c
	defer func() { msgCipher = nil }()

	live := &model.Post{Id: "a", Message: "secret plan"}
	edited := &model.Post{Id: "b", Message: "old text", DeleteAt: 1}
	sealedPosts, rows := sealPosts(live, edited)
	assert.Len(t, rows, 2, "only the live post is indexed")
	assert.Equal(t, "secret plan", live.Message, "caller's post is not mutated")
	assert.True(t, strings.HasPrefix(sealedPosts[0].Message, encPrefixV4+c.kid+":-/-:posts.message#a:"), "no channel: scope -/-")
	stored := []*model.Post{{Id: "a", Message: sealedPosts[0].Message}}
	joined := []*postWithExtra{{Post: model.Post{Id: "b", Message: sealedPosts[1].Message}}}
	bare := []string{sealedPosts[0].Message}

	decryptDest(&stored)
	decryptDest(&joined)
	decryptDest(&bare)
	assert.Equal(t, "secret plan", stored[0].Message)
	assert.Equal(t, "old text", joined[0].Message, "embedded struct inherits the row id")
	assert.Equal(t, "secret plan", bare[0], "scalar scans decrypt without location")

	legacy := []*model.Post{{Id: "z", Message: legacyEncrypt(t, testRootKey, "from v1", false)}}
	decryptDest(&legacy)
	assert.Equal(t, "from v1", legacy[0].Message)

	sp := &model.ScheduledPost{Id: "s", Draft: model.Draft{UserId: "u", ChannelId: "c", Message: "later"}}
	sp.Message = sealed("scheduledposts.message", sp.Id, sp.Message)
	d := &model.Draft{UserId: "u", ChannelId: "c", Message: sealed("drafts.message", draftKey("u", "c", ""), "draft")}
	decryptDest(sp)
	decryptDest(d)
	assert.Equal(t, "later", sp.Message)
	assert.Equal(t, "draft", d.Message)

	tagged := &model.Post{Id: "c", ChannelId: "chan1", Message: "go #Launch", Hashtags: "#Launch"}
	sealedPosts, rows = sealPosts(tagged)
	assert.True(t, strings.HasPrefix(sealedPosts[0].Hashtags, encPrefixV4+c.kid+":-/chan1:posts.hashtags#c:"))
	assert.Contains(t, rows, [2]string{"c", c.hashtagHashes("#launch")[0]})
	assert.Equal(t, "#Launch", tagged.Hashtags)

	info := &model.FileInfo{Id: "f", ChannelId: "chan1", Name: "q3-report.pdf", Content: "revenue"}
	sealedInfo, rows := sealFileInfo(info)
	assert.True(t, strings.HasPrefix(sealedInfo.Name, encPrefixV4+c.kid+":-/chan1:fileinfo.name#f:"))
	assert.True(t, strings.HasPrefix(sealedInfo.Content, encPrefixV4))
	assert.Contains(t, rows, [2]string{"f", c.hashWord("revenue")})
	assert.Contains(t, rows, [2]string{"f", c.hashWord("report")})
	assert.Equal(t, "q3-report.pdf", info.Name)
	back := []*model.FileInfo{{Id: "f", ChannelId: "chan1", Name: sealedInfo.Name, Content: sealedInfo.Content}}
	decryptDest(&back)
	assert.Equal(t, "q3-report.pdf", back[0].Name)
	assert.Equal(t, "revenue", back[0].Content)
}

func TestPostCipherV4(t *testing.T) {
	c := testCipher(t, testRootKey, testFactor)
	teamLookups := 0
	c.teamOf = func(channelID string) (string, error) {
		teamLookups++
		if channelID == "dm1" {
			return "", nil
		}
		return "team1", nil
	}
	assert.Equal(t, "team1/chanA", c.scopeOf("chanA"))
	assert.Equal(t, "team1/chanA", c.scopeOf("chanA"))
	assert.Equal(t, 1, teamLookups, "team id is cached per channel")
	assert.Equal(t, "-/dm1", c.scopeOf("dm1"), "DM/GM: no team")
	assert.Equal(t, noScope, c.scopeOf(""))
	assert.Equal(t, noScope, c.scopeOf("a:b"), "separators never reach the format")

	scope := c.scopeOf("chanA")
	enc := c.encryptIn("hello", scope, label("posts.message", "p1"))
	assert.True(t, strings.HasPrefix(enc, encPrefixV4+c.kid+":team1/chanA:posts.message#p1:"), enc)
	assert.NotEqual(t, enc, c.encryptIn("hello", scope, label("posts.message", "p1")), "random nonce")
	assert.Equal(t, "hello", c.decrypt(enc), "scalar scan: key derived from the scope in the ciphertext")
	assert.Equal(t, "hello", c.decryptAt(enc, "message", "p1", "chanA"))
	assert.Equal(t, "hello", c.decryptAt(enc, "message", "p1", ""), "channel unknown to the reader: no check")

	t.Run("scope mismatch rejected", func(t *testing.T) {
		assert.Equal(t, enc, c.decryptAt(enc, "message", "p1", "chanB"), "same row key, another channel")
		assert.Equal(t, enc, c.decryptAt(enc, "message", "p2", "chanA"), "another row")
		assert.Equal(t, enc, c.decryptAt(enc, "hashtags", "p1", "chanA"), "another column")
		forged := strings.Replace(enc, ":team1/chanA:", ":team1/chanB:", 1)
		assert.Equal(t, forged, c.decrypt(forged), "rewriting the scope derives another key and breaks the tag")
		forged = strings.Replace(enc, ":team1/chanA:", ":team2/chanA:", 1)
		assert.Equal(t, forged, c.decrypt(forged), "team is part of the key")
		assert.NotEqual(t, enc[:40], c.encryptIn("hello", c.scopeOf("dm1"), label("posts.message", "p1"))[:40])

		msgCipher = c
		defer func() { msgCipher = nil }()
		a := &model.Post{Id: "p1", ChannelId: "chanA", Message: "for A"}
		sealedPosts, _ := sealPosts(a)
		moved := []*model.Post{{Id: "p1", ChannelId: "chanB", Message: sealedPosts[0].Message}}
		decryptDest(&moved)
		assert.Equal(t, sealedPosts[0].Message, moved[0].Message, "post row moved to another channel stays sealed")
		home := []*postWithExtra{{Post: model.Post{Id: "p1", ChannelId: "chanA", Message: sealedPosts[0].Message}}}
		decryptDest(&home)
		assert.Equal(t, "for A", home[0].Message, "embedded struct inherits row and channel")

		d := &model.Draft{UserId: "u", ChannelId: "chanA", Message: sealedIn("chanA", "drafts.message", draftKey("u", "chanA", ""), "draft")}
		decryptDest(d)
		assert.Equal(t, "draft", d.Message)
		sp := &model.ScheduledPost{Id: "s", Draft: model.Draft{UserId: "u", ChannelId: "chanA", Message: sealedIn("chanA", "scheduledposts.message", "s", "later")}}
		decryptDest(sp)
		assert.Equal(t, "later", sp.Message)
		sp.ChannelId, sp.Message = "chanB", sealedIn("chanA", "scheduledposts.message", "s", "later")
		decryptDest(sp)
		assert.True(t, isSealed(sp.Message), "scheduled post moved to another channel stays sealed")
	})

	t.Run("v3 and legacy still open, globals stay v3", func(t *testing.T) {
		v3 := c.encrypt("old v3", label("posts.message", "p1"))
		assert.True(t, strings.HasPrefix(v3, encPrefixV3))
		assert.Equal(t, "old v3", c.decryptAt(v3, "message", "p1", "chanA"), "v3 carries no scope: channel not checked")
		assert.Equal(t, "old v2", c.decryptAt(legacyEncrypt(t, testRootKey, "old v2", true), "message", "p1", "chanA"))
		msgCipher = c
		defer func() { msgCipher = nil }()
		assert.True(t, strings.HasPrefix(sealed("users.email", "u1", "a@b.c"), encPrefixV3), "user PII stays on the global key")
	})

	t.Run("rotation", func(t *testing.T) {
		rotated := testCipher(t, testRootKey2, testFactor2, testRootKey, testFactor)
		assert.Equal(t, "hello", rotated.decrypt(enc), "old root derives the old channel key by kid")
		assert.True(t, strings.HasPrefix(rotated.encryptIn("x", scope, "a.b#c"), encPrefixV4+rotated.kid+":"))
		noOld := testCipher(t, testRootKey2, testFactor2)
		assert.Equal(t, enc, noOld.decrypt(enc), "unknown kid stays raw")
		_, err := noOld.scopedAEAD(c.kid, scope)
		assert.Error(t, err)
	})
}

func TestBackfillPosts(t *testing.T) {
	if testing.Short() || len(storeTypes) == 0 {
		t.Skip("needs a database")
	}
	saved := msgCipher
	defer func() { msgCipher = saved }()
	ss := storeTypes[0].SqlStore

	msgCipher = nil
	plain, err := ss.Post().Save(request.TestContext(t), &model.Post{ChannelId: model.NewId(), UserId: model.NewId(), Message: "legacy backfill words"})
	require.NoError(t, err)
	v2, err := ss.Post().Save(request.TestContext(t), &model.Post{ChannelId: model.NewId(), UserId: model.NewId(), Message: "placeholder"})
	require.NoError(t, err)
	_, err = ss.GetMaster().DB().Exec("UPDATE Posts SET Message = $1 WHERE Id = $2", legacyEncrypt(t, testRootKey, "upgraded from v2", true), v2.Id)
	require.NoError(t, err)
	v3, err := ss.Post().Save(request.TestContext(t), &model.Post{ChannelId: model.NewId(), UserId: model.NewId(), Message: "placeholder"})
	require.NoError(t, err)
	c := testCipher(t, testRootKey, testFactor)
	_, err = ss.GetMaster().DB().Exec("UPDATE Posts SET Message = $1 WHERE Id = $2", c.encrypt("upgraded from v3", label("posts.message", v3.Id)), v3.Id)
	require.NoError(t, err)

	msgCipher = c
	t.Setenv(EncryptionBackfillEnv, "true")
	require.NoError(t, ss.backfillPosts())

	for id, want := range map[string]string{plain.Id: "legacy backfill words", v2.Id: "upgraded from v2", v3.Id: "upgraded from v3"} {
		var raw string
		require.NoError(t, ss.GetMaster().DB().Get(&raw, "SELECT Message FROM Posts WHERE Id = $1", id))
		assert.True(t, strings.HasPrefix(raw, encPrefixV4+c.kid+":-/"), "stored message is v4 under the current kid: %s", raw[:40])
		var n int
		require.NoError(t, ss.GetMaster().DB().Get(&n, "SELECT COUNT(*) FROM PostSearchTokens WHERE PostId = $1", id))
		assert.Equal(t, 3, n, "re-indexed with the current blind-index key")
		got, err := ss.Post().GetSingle(request.TestContext(t), id, false)
		require.NoError(t, err)
		assert.Equal(t, want, got.Message)
	}
}

func TestEncryptedSearchTerms(t *testing.T) {
	c := testCipher(t, testRootKey, testFactor)
	has := func(index []string, h string) bool { return strings.Contains(strings.Join(index, " "), h) }

	t.Run("prefix hashes only when enabled", func(t *testing.T) {
		t.Setenv(PrefixSearchEnv, "")
		assert.Len(t, c.indexTokens("alphabet"), 1)
		assert.Equal(t, c.tokens("alph"), c.queryTokens("alph*"), "off: wildcard falls back to the exact word")

		t.Setenv(PrefixSearchEnv, "true")
		index := c.indexTokens("Alphabet soup")
		for _, q := range []string{"alph*", "ALPHABET*", "alphabet", "sou*"} {
			for _, h := range c.queryTokens(q) {
				assert.True(t, has(index, h), q)
			}
		}
		assert.False(t, has(index, c.queryTokens("alpx*")[0]))
		assert.Equal(t, c.tokens("al"), c.queryTokens("al*"), "shorter than the minimum prefix: exact word")
	})

	t.Run("phrases and long prefixes are re-checked on plaintext", func(t *testing.T) {
		assert.True(t, matchesSearchTerms("the quick brown fox", `"quick brown"`))
		assert.False(t, matchesSearchTerms("brown quick fox", `"quick brown"`))
		assert.True(t, matchesSearchTerms("Quick, brown!", `"quick brown" fox*`))
		assert.True(t, matchesSearchTerms("abcdefghijklmnopqrst rocks", "abcdefghijklmnopqr*"), "over maxSearchPrefix: whole prefix checked")
		assert.False(t, matchesSearchTerms("abcdefghijklmnopqXYZ rocks", "abcdefghijklmnopqr*"))
	})
}

func TestSealChannelAndHeaderProps(t *testing.T) {
	c := testCipher(t, testRootKey, testFactor)
	msgCipher = c
	defer func() { msgCipher = nil }()

	ch := &model.Channel{Id: "chan1", TeamId: "team1", Header: "board only", Purpose: "Q3 merger"}
	s := sealChannel(ch)
	assert.Equal(t, "board only", ch.Header, "caller's channel is not mutated")
	assert.True(t, strings.HasPrefix(s.Header, encPrefixV4+c.kid+":team1/chan1:channels.header#chan1:"))
	assert.True(t, strings.HasPrefix(s.Purpose, encPrefixV4+c.kid+":team1/chan1:channels.purpose#chan1:"))
	assert.Empty(t, sealChannel(&model.Channel{Id: "dm"}).Header, "empty stays empty")

	back := []*model.Channel{{Id: "chan1", Header: s.Header, Purpose: s.Purpose}}
	decryptDest(&back)
	assert.Equal(t, "board only", back[0].Header)
	assert.Equal(t, "Q3 merger", back[0].Purpose)
	moved := []*model.Channel{{Id: "other", Header: s.Header}}
	decryptDest(&moved)
	assert.Equal(t, s.Header, moved[0].Header, "a header copied to another channel row does not decrypt")

	p := &model.Post{Id: "h", ChannelId: "chan1", Type: model.PostTypeHeaderChange, Message: "x"}
	p.SetProps(model.StringInterface{"username": "budi", "old_header": "", "new_header": "board only"})
	sp, _ := sealPosts(p)
	assert.Equal(t, "board only", p.GetProp("new_header"), "caller's props are not mutated")
	assert.True(t, strings.HasPrefix(sp[0].GetProp("new_header").(string), encPrefixV4), "header prop sealed")
	assert.Equal(t, "", sp[0].GetProp("old_header"))
	assert.Equal(t, "budi", sp[0].GetProp("username"), "other props untouched")

	stored := []*model.Post{{Id: "h", ChannelId: "chan1"}}
	stored[0].SetProps(model.StringInterface{"new_header": sp[0].GetProp("new_header")})
	decryptDest(&stored)
	assert.Equal(t, "board only", stored[0].GetProp("new_header"))
}

func TestEncryptLegacyChannels(t *testing.T) {
	if testing.Short() || len(storeTypes) == 0 {
		t.Skip("needs a database")
	}
	saved := msgCipher
	defer func() { msgCipher = saved }()
	ss := storeTypes[0].SqlStore
	rctx := request.TestContext(t)

	msgCipher = nil
	ch, err := ss.Channel().Save(rctx, &model.Channel{TeamId: model.NewId(), Name: "legacy-" + model.NewId()[:8], DisplayName: "Legacy", Type: model.ChannelTypeOpen, Header: "plain header words", Purpose: "plain purpose"}, -1)
	require.NoError(t, err)
	p := &model.Post{ChannelId: ch.Id, UserId: model.NewId(), Type: model.PostTypeHeaderChange, Message: "changed"}
	p.SetProps(model.StringInterface{"old_header": "", "new_header": "plain header words"})
	p, err = ss.Post().Save(rctx, p)
	require.NoError(t, err)

	msgCipher = testCipher(t, testRootKey, testFactor)
	require.NoError(t, ss.encryptLegacyChannels())
	for _, table := range []string{"Channels", "PublicChannels"} {
		var raw struct{ Header, Purpose string }
		require.NoError(t, ss.GetMaster().DB().Get(&raw, "SELECT Header, Purpose FROM "+table+" WHERE Id = $1", ch.Id))
		assert.True(t, strings.HasPrefix(raw.Header, encPrefixV4), "%s header sealed", table)
		assert.True(t, strings.HasPrefix(raw.Purpose, encPrefixV4), "%s purpose sealed", table)
	}
	var props string
	require.NoError(t, ss.GetMaster().DB().Get(&props, "SELECT Props FROM Posts WHERE Id = $1", p.Id))
	assert.NotContains(t, props, "plain header words")

	got, err := ss.Channel().Get(ch.Id, false)
	require.NoError(t, err)
	assert.Equal(t, "plain header words", got.Header)
	assert.Equal(t, "plain purpose", got.Purpose)
	gp, err := ss.Post().GetSingle(rctx, p.Id, false)
	require.NoError(t, err)
	assert.Equal(t, "plain header words", gp.GetProp("new_header"))

	got.Header = "new secret header"
	_, err = ss.Channel().Update(rctx, got)
	require.NoError(t, err)
	var raw string
	require.NoError(t, ss.GetMaster().DB().Get(&raw, "SELECT Header FROM PublicChannels WHERE Id = $1", ch.Id))
	assert.True(t, strings.HasPrefix(raw, encPrefixV4), "update seals PublicChannels too")
}

func TestEncryptLegacyDrafts(t *testing.T) {
	if testing.Short() || len(storeTypes) == 0 {
		t.Skip("needs a database")
	}
	saved := msgCipher
	defer func() { msgCipher = saved }()
	ss := storeTypes[0].SqlStore
	c := testCipher(t, testRootKey, testFactor)
	msgCipher = c

	u, ch := model.NewId(), model.NewId()
	_, err := ss.GetMaster().DB().Exec("INSERT INTO Drafts (CreateAt, UpdateAt, DeleteAt, UserId, ChannelId, RootId, Message, Props, FileIds) VALUES (1, 1, 0, $1, $2, '', $3, '{}', '[]')",
		u, ch, c.encrypt("v3 draft words", label("drafts.message", draftKey(u, ch, ""))))
	require.NoError(t, err)
	require.NoError(t, ss.encryptLegacyDrafts())
	var raw string
	require.NoError(t, ss.GetMaster().DB().Get(&raw, "SELECT Message FROM Drafts WHERE UserId = $1", u))
	assert.True(t, strings.HasPrefix(raw, encPrefixV4+c.kid+":-/"+ch+":drafts.message#"), raw)
	d, err := ss.Draft().Get(u, ch, "", false)
	require.NoError(t, err)
	assert.Equal(t, "v3 draft words", d.Message)
}
