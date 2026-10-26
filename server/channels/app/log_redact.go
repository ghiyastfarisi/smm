// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

// emailLogField replaces emailLogField(…): logs must hold no PII (mrpostman ENC-25), so the address is
// logged as a short SHA-256 prefix that still lets operators correlate entries for one user.
func emailLogField(email string) mlog.Field {
	if email == "" {
		return mlog.String("user_email_hash", "")
	}
	sum := sha256.Sum256([]byte(email))
	return mlog.String("user_email_hash", hex.EncodeToString(sum[:])[:12])
}
