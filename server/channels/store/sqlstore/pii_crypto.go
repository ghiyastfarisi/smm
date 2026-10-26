// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"strings"
	"unicode"

	sq "github.com/mattermost/squirrel"
	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/public/model"
)

// User PII at rest: Email, FirstName, LastName, Nickname, Position and MfaSecret are encrypted.
// Users.EmailHash (HMAC of the lowercased email) serves login, lookups and uniqueness.
// UserSearchTokens holds HMACs of every word prefix of the searchable fields, tagged per field
// so a search that may not match emails never matches email tokens.
// Username stays plaintext: it is the public handle used for mentions, sorting and autocomplete.

const maxPrefixRunes = 32

// piiSearchTag maps a searchable Users column to its token tag.
func piiSearchTag(field string) string {
	switch strings.TrimPrefix(field, "Users.") {
	case "FirstName", "LastName":
		return "n"
	case "Nickname":
		return "k"
	case "Email":
		return "e"
	}
	return ""
}

func emailHash(email string) string {
	if msgCipher == nil || email == "" {
		return ""
	}
	return msgCipher.hashWord("email:" + strings.ToLower(email))
}

// emailEquals matches the user with this email, through EmailHash when encryption is on.
func emailEquals(column, email string) sq.Sqlizer {
	if msgCipher != nil {
		return sq.Eq{strings.TrimSuffix(column, "Email") + "EmailHash": emailHash(email)}
	}
	return sq.Expr(column+" = lower(?)", email)
}

// prefixHashes hashes every prefix of each word and of the whole text, so "f_abc" and "abc" both match.
func prefixHashes(tag, text string) []string {
	text = strings.ToLower(text)
	words := strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	if text != "" {
		words = append(words, text)
	}
	var hashes []string
	for _, w := range words {
		r := []rune(w)
		for i := 1; i <= len(r) && i <= maxPrefixRunes; i++ {
			hashes = append(hashes, msgCipher.hashWord(tag+":"+string(r[:i])))
		}
	}
	return hashes
}

// userSearchTermHash is what a search term is compared against for a field tag.
func userSearchTermHash(tag, term string) string {
	// Terms reach here LIKE-escaped by sanitizeSearchTerm, which strips any literal '*' first.
	term = strings.ReplaceAll(term, "*", "")
	r := []rune(strings.ToLower(strings.TrimLeft(term, "@")))
	if len(r) > maxPrefixRunes {
		r = r[:maxPrefixRunes]
	}
	return msgCipher.hashWord(tag + ":" + string(r))
}

// userPIIClause adds a token match for an encrypted column, or returns false for plaintext ones.
func userPIIClause(field, term string) (string, any, bool) {
	tag := piiSearchTag(field)
	if msgCipher == nil || tag == "" {
		return "", nil, false
	}
	return "Users.Id IN (SELECT UserId FROM UserSearchTokens WHERE TokenHash = ?)", userSearchTermHash(tag, term), true
}

// sealUser returns an encrypted copy of the user's PII, its email hash and search tokens.
func sealUser(u *model.User) (sealedUser *model.User, hash string, tokenRows [][2]string) {
	if msgCipher == nil {
		return u, "", nil
	}
	hash = emailHash(u.Email)
	seen := map[string]bool{}
	add := func(hs []string) {
		for _, h := range hs {
			if !seen[h] {
				seen[h] = true
				tokenRows = append(tokenRows, [2]string{u.Id, h})
			}
		}
	}
	add(prefixHashes("n", u.FirstName))
	add(prefixHashes("n", u.LastName))
	add(prefixHashes("k", u.Nickname))
	add(prefixHashes("e", u.Email))

	c := *u
	for col, f := range map[string]*string{"email": &c.Email, "firstname": &c.FirstName, "lastname": &c.LastName, "nickname": &c.Nickname, "position": &c.Position, "mfasecret": &c.MfaSecret} {
		*f = msgCipher.encrypt(*f, label("users."+col, u.Id))
	}
	return &c, hash, tokenRows
}

func (us SqlUserStore) replaceUserSearchTokens(userID string, rows [][2]string) error {
	if msgCipher == nil {
		return nil
	}
	if _, err := us.GetMaster().ExecBuilder(us.getQueryBuilder().Delete("UserSearchTokens").Where(sq.Eq{"UserId": userID})); err != nil {
		return errors.Wrap(err, "failed to delete user search tokens")
	}
	return saveTokens(us.SqlStore, us.GetMaster(), "UserSearchTokens", "UserId", rows)
}

// encryptLegacyUsers encrypts users written before ENCRYPTION_KEY was set and re-seals v1/v2
// users as v3, recomputing EmailHash and search tokens with the current blind-index key
// (it runs on every start, so login keeps working right after a key or format upgrade).
// ponytail: one pass over plaintext rows at startup; fine for user tables, batch it for millions of users.
func (ss *SqlStore) encryptLegacyUsers() error {
	if msgCipher == nil {
		return nil
	}
	var ids []string
	if err := ss.GetMaster().Select(&ids, "SELECT Id FROM Users WHERE EmailHash = '' OR EmailHash IS NULL OR (Email <> '' AND Email NOT LIKE 'enc:v3:%')"); err != nil {
		return errors.Wrap(err, "failed to find plaintext users")
	}
	us := SqlUserStore{SqlStore: ss}
	for _, id := range ids {
		var u model.User
		if err := ss.GetMaster().Get(&u, "SELECT Id, Email, FirstName, LastName, Nickname, Position, MfaSecret FROM Users WHERE Id = $1", id); err != nil {
			return errors.Wrapf(err, "failed to read user %s", id)
		}
		if isSealed(u.Email) || isSealed(u.FirstName) || isSealed(u.LastName) || isSealed(u.Nickname) || isSealed(u.Position) || isSealed(u.MfaSecret) {
			continue // undecryptable (missing old key): leave untouched
		}
		su, hash, rows := sealUser(&u)
		if _, err := ss.GetMaster().Exec("UPDATE Users SET Email = $1, FirstName = $2, LastName = $3, Nickname = $4, Position = $5, MfaSecret = $6, EmailHash = $7 WHERE Id = $8",
			su.Email, su.FirstName, su.LastName, su.Nickname, su.Position, su.MfaSecret, hash, id); err != nil {
			return errors.Wrapf(err, "failed to encrypt user %s", id)
		}
		if err := us.replaceUserSearchTokens(id, rows); err != nil {
			return err
		}
	}

	// Team contact emails are usually the creator's email.
	var teams []model.Team
	if err := ss.GetMaster().Select(&teams, "SELECT Id, Email FROM Teams WHERE Email <> '' AND Email NOT LIKE 'enc:v3:%'"); err != nil {
		return errors.Wrap(err, "failed to find plaintext team emails")
	}
	for _, t := range teams {
		if isSealed(t.Email) {
			continue
		}
		if _, err := ss.GetMaster().Exec("UPDATE Teams SET Email = $1 WHERE Id = $2", sealed("teams.email", t.Id, t.Email), t.Id); err != nil {
			return errors.Wrapf(err, "failed to encrypt team %s email", t.Id)
		}
	}
	return nil
}
