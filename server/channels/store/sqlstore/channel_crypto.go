// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"maps"
	"os"
	"reflect"
	"strings"

	"github.com/pkg/errors"

	"github.com/mattermost/mattermost/server/public/model"
)

// channelPropKeys are the post props that repeat a channel's header or purpose (system change posts).
var channelPropKeys = []string{"old_header", "new_header", "old_purpose", "new_purpose"}

// channelScope is scopeOf for a channel whose team is known (the row may not exist yet).
func channelScope(teamID, channelID string) string {
	if channelID == "" || strings.ContainsAny(teamID+channelID, ":/") {
		return noScope
	}
	if teamID == "" {
		teamID = "-"
	}
	return teamID + "/" + channelID
}

// sealChannel returns a copy of ch with Header and Purpose sealed (v4, the channel's own key); ch is
// never mutated, so cached channels stay plaintext. Both Channels and PublicChannels store the copy.
func sealChannel(ch *model.Channel) *model.Channel {
	if msgCipher == nil {
		return ch
	}
	c := ch.DeepCopy()
	scope := channelScope(ch.TeamId, ch.Id)
	c.Header = msgCipher.encryptIn(ch.Header, scope, label("channels.header", ch.Id))
	c.Purpose = msgCipher.encryptIn(ch.Purpose, scope, label("channels.purpose", ch.Id))
	return c
}

// sealPostProps seals, on the clone c, the props that carry a channel header or purpose.
func sealPostProps(c *model.Post, scope string) {
	var props model.StringInterface
	for _, k := range channelPropKeys {
		if s, ok := c.GetProp(k).(string); ok && s != "" && !isSealed(s) {
			if props == nil {
				props = maps.Clone(c.GetProps()) // the clone shares the caller's map
			}
			props[k] = msgCipher.encryptIn(s, scope, label("posts."+k, c.Id))
		}
	}
	if props != nil {
		c.SetProps(props)
	}
}

// decryptMap decrypts the string values of a scanned map (post props), checked against key name,
// row and channel like struct fields.
func decryptMap(v reflect.Value, rowKey, channelID string) {
	if v.IsNil() || v.Type().Key().Kind() != reflect.String {
		return
	}
	iter := v.MapRange()
	for iter.Next() {
		val := iter.Value()
		if val.Kind() == reflect.Interface {
			val = val.Elem()
		}
		if val.Kind() == reflect.String && isSealed(val.String()) {
			plain := reflect.ValueOf(msgCipher.decryptAt(val.String(), iter.Key().String(), rowKey, channelID))
			v.SetMapIndex(iter.Key(), plain.Convert(v.Type().Elem()))
		}
	}
}

// encryptLegacyChannels seals channel headers and purposes written in plaintext (before this release
// or without a key) and the header/purpose props of older system posts. It runs on every start and
// touches only plaintext rows; with ENCRYPTION_BACKFILL=true it also re-seals rows not yet v4 under the
// current kid (root rotation, like backfillPosts).
// ponytail: one pass at startup like encryptLegacyUsers; batch it if a deployment has millions of channels.
func (ss *SqlStore) encryptLegacyChannels() error {
	if msgCipher == nil {
		return nil
	}
	done := "enc:%" // LIKE pattern of rows that need nothing
	if os.Getenv(EncryptionBackfillEnv) == "true" {
		done = encPrefixV4 + msgCipher.kid + ":%"
	}
	var chans []model.Channel
	if err := ss.GetMaster().Select(&chans, `SELECT Id, TeamId, COALESCE(Header, '') AS Header, COALESCE(Purpose, '') AS Purpose FROM Channels
		WHERE (Header <> '' AND Header NOT LIKE $1) OR (Purpose <> '' AND Purpose NOT LIKE $1)`, done); err != nil {
		return errors.Wrap(err, "failed to find plaintext channel headers")
	}
	for i := range chans {
		ch := &chans[i]
		if isSealed(ch.Header) || isSealed(ch.Purpose) {
			continue // one field undecryptable (missing old key): leave the row untouched
		}
		s := sealChannel(ch)
		for _, table := range []string{"Channels", "PublicChannels"} {
			if _, err := ss.GetMaster().Exec("UPDATE "+table+" SET Header = $1, Purpose = $2 WHERE Id = $3", s.Header, s.Purpose, ch.Id); err != nil {
				return errors.Wrapf(err, "failed to encrypt %s header of %s", table, ch.Id)
			}
		}
	}

	plainProp := make([]string, len(channelPropKeys))
	for i, k := range channelPropKeys {
		plainProp[i] = "(Props->>'" + k + "' <> '' AND Props->>'" + k + "' NOT LIKE $3)"
	}
	var posts []*model.Post
	if err := ss.GetMaster().Select(&posts, "SELECT Id, ChannelId, Props FROM Posts WHERE Type IN ($1, $2) AND ("+strings.Join(plainProp, " OR ")+")",
		model.PostTypeHeaderChange, model.PostTypePurposeChange, done); err != nil {
		return errors.Wrap(err, "failed to find plaintext header change posts")
	}
	for _, p := range posts {
		c := p.Clone()
		sealPostProps(c, msgCipher.scopeOf(p.ChannelId))
		if _, err := ss.GetMaster().Exec("UPDATE Posts SET Props = $1 WHERE Id = $2", model.StringInterfaceToJSON(c.GetProps()), p.Id); err != nil {
			return errors.Wrapf(err, "failed to encrypt props of post %s", p.Id)
		}
	}
	return nil
}

// encryptLegacyDrafts seals plaintext drafts and scheduled posts and re-seals older formats (v1–v3) as
// v4 under their channel; with ENCRYPTION_BACKFILL=true also v4 rows under an older kid.
func (ss *SqlStore) encryptLegacyDrafts() error {
	if msgCipher == nil {
		return nil
	}
	done := encPrefixV4 + "%"
	if os.Getenv(EncryptionBackfillEnv) == "true" {
		done = encPrefixV4 + msgCipher.kid + ":%"
	}
	var drafts []*model.Draft
	if err := ss.GetMaster().Select(&drafts, "SELECT UserId, ChannelId, RootId, Message FROM Drafts WHERE Message <> '' AND Message NOT LIKE $1", done); err != nil {
		return errors.Wrap(err, "failed to find legacy drafts")
	}
	for _, d := range drafts {
		if isSealed(d.Message) {
			continue // undecryptable (missing old key)
		}
		if _, err := ss.GetMaster().Exec("UPDATE Drafts SET Message = $1 WHERE UserId = $2 AND ChannelId = $3 AND RootId = $4",
			sealedIn(d.ChannelId, "drafts.message", draftKey(d.UserId, d.ChannelId, d.RootId), d.Message), d.UserId, d.ChannelId, d.RootId); err != nil {
			return errors.Wrap(err, "failed to encrypt draft")
		}
	}
	var scheduled []*model.ScheduledPost
	if err := ss.GetMaster().Select(&scheduled, "SELECT Id, ChannelId, Message FROM ScheduledPosts WHERE Message <> '' AND Message NOT LIKE $1", done); err != nil {
		return errors.Wrap(err, "failed to find legacy scheduled posts")
	}
	for _, sp := range scheduled {
		if isSealed(sp.Message) {
			continue
		}
		if _, err := ss.GetMaster().Exec("UPDATE ScheduledPosts SET Message = $1 WHERE Id = $2", sealedIn(sp.ChannelId, "scheduledposts.message", sp.Id, sp.Message), sp.Id); err != nil {
			return errors.Wrapf(err, "failed to encrypt scheduled post %s", sp.Id)
		}
	}
	return nil
}
