// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// Package keyring derives the at-rest data keys shared by the SQL store and the file store.
//
//	dataKey(purpose) = HKDF-SHA256(ikm = ENCRYPTION_KEY, salt = ENCRYPTION_KEY_FACTOR, info = purpose)
//
// Both secrets are required: neither the master key nor the factor alone yields any data key.
// Keys written before the factor existed (formats v1/v2, files MMENCF1) were derived from the
// master key alone; Legacy exposes that for decryption only.
package keyring

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const (
	KeyEnv       = "ENCRYPTION_KEY"            // base64 32-byte master key
	FactorEnv    = "ENCRYPTION_KEY_FACTOR"     // secret salt, any string of at least 16 bytes
	KeyOldEnv    = "ENCRYPTION_KEY_OLD"        // comma-separated retired master keys (decrypt only)
	FactorOldEnv = "ENCRYPTION_KEY_FACTOR_OLD" // comma-separated factors, paired by position with KeyOldEnv
)

// OpenBAO custody: when BaoAddrEnv is set the root secret is read from KV v2 instead of the environment.
const (
	BaoAddrEnv     = "OPENBAO_ADDR"      // e.g. http://openbao:8200
	BaoTokenEnv    = "OPENBAO_TOKEN"     // token auth
	BaoRoleIDEnv   = "OPENBAO_ROLE_ID"   // AppRole auth (used when OPENBAO_TOKEN is empty)
	BaoSecretIDEnv = "OPENBAO_SECRET_ID" //nolint:gosec
	BaoPathEnv     = "OPENBAO_KV_PATH"   // API path of the secret; fields key, factor, old_keys, old_factors
	DefaultBaoPath = "secret/data/mrpostman/root"
)

// Purpose labels; each yields an independent subkey.
const (
	PurposeDBField    = "mrpostman/v3/db-field"
	PurposeBlindIndex = "mrpostman/v3/blind-index"
	PurposeFileBlob   = "mrpostman/v3/file-blob"
	PurposeKID        = "mrpostman/v3/kid"
	// ChannelPurposePrefix + "<teamId>/<channelId>" yields the v4 per-channel data key (see ChannelKey).
	ChannelPurposePrefix = "mrpostman/v4/channel/"
)

const minFactorLen = 16

// Root is one master key with its factor. Factor is nil for a legacy (pre-factor) root.
type Root struct {
	Master []byte
	Factor []byte
}

// Key derives the 32-byte subkey for purpose. Only valid when Factor is set.
func (r *Root) Key(purpose string) []byte {
	k, err := hkdf.Key(sha256.New, r.Master, r.Factor, purpose, 32)
	if err != nil {
		panic(err) // only fails for lengths > 255*32
	}
	return k
}

// KID identifies this (master, factor) pair: 8 hex chars, safe to store next to ciphertext.
func (r *Root) KID() string {
	return hex.EncodeToString(r.Key(PurposeKID))[:8]
}

// LegacyKID is the v2 key id, computed from the master key alone.
func (r *Root) LegacyKID() string {
	m := hmac.New(sha256.New, r.Master)
	m.Write([]byte("kid"))
	return hex.EncodeToString(m.Sum(nil))[:8]
}

// Legacy derives a pre-factor subkey (v1/v2 fields, MMENCF1 files) for decryption only.
func (r *Root) Legacy(info string, salt []byte) []byte {
	k, err := hkdf.Key(sha256.New, r.Master, salt, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// ChannelKey derives the v4 per-team+channel data key: scope is "<teamId>/<channelId>" ("-" for no team).
func (r *Root) ChannelKey(scope string) []byte {
	return r.Key(ChannelPurposePrefix + scope)
}

// Load returns the roots: from OpenBAO when OPENBAO_ADDR is set (fetched once per process; a failed
// fetch is an error, never a silent fallback to the environment), else from the environment.
// cur is nil when no key is configured. old lists retired roots; an old key without a paired factor
// can only decrypt legacy data.
func Load() (cur *Root, old []*Root, err error) {
	if os.Getenv(BaoAddrEnv) != "" {
		baoOnce.Do(func() {
			baoCur, baoOld, baoErr = loadOpenBAO(os.Getenv(BaoAddrEnv), os.Getenv(BaoTokenEnv), os.Getenv(BaoRoleIDEnv), os.Getenv(BaoSecretIDEnv), os.Getenv(BaoPathEnv))
		})
		return baoCur, baoOld, baoErr
	}
	if os.Getenv(KeyEnv) == "" {
		return nil, nil, nil
	}
	return Parse(os.Getenv(KeyEnv), os.Getenv(FactorEnv), os.Getenv(KeyOldEnv), os.Getenv(FactorOldEnv))
}

// Enabled reports whether at-rest encryption is configured (a current root loads).
func Enabled() bool {
	cur, _, err := Load()
	return err == nil && cur != nil
}

var (
	baoOnce          sync.Once
	baoCur           *Root
	baoOld           []*Root
	baoErr           error
	baoClientTimeout = 10 * time.Second
)

// loadOpenBAO reads the root secret from OpenBAO KV v2 at path (default DefaultBaoPath), authenticating
// with token or, when it is empty, with AppRole (roleID + secretID). Field names and encodings match the
// environment variables: key, factor, old_keys, old_factors.
func loadOpenBAO(addr, token, roleID, secretID, path string) (*Root, []*Root, error) {
	if path == "" {
		path = DefaultBaoPath
	}
	addr = strings.TrimRight(addr, "/")
	client := &http.Client{Timeout: baoClientTimeout}
	if token == "" {
		if roleID == "" || secretID == "" {
			return nil, nil, errors.Errorf("OpenBAO: set %s or %s + %s", BaoTokenEnv, BaoRoleIDEnv, BaoSecretIDEnv)
		}
		var login struct {
			Auth struct {
				ClientToken string `json:"client_token"`
			} `json:"auth"`
		}
		if err := baoJSON(client, http.MethodPost, addr+"/v1/auth/approle/login", "", map[string]string{"role_id": roleID, "secret_id": secretID}, &login); err != nil {
			return nil, nil, errors.Wrap(err, "OpenBAO AppRole login")
		}
		if token = login.Auth.ClientToken; token == "" {
			return nil, nil, errors.New("OpenBAO AppRole login returned no client token")
		}
	}
	var secret struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := baoJSON(client, http.MethodGet, addr+"/v1/"+strings.TrimLeft(path, "/"), token, nil, &secret); err != nil {
		return nil, nil, errors.Wrapf(err, "OpenBAO: read root secret at %s", path)
	}
	d := secret.Data.Data
	if d["key"] == "" {
		return nil, nil, errors.Errorf("OpenBAO: secret at %s has no 'key' field", path)
	}
	cur, old, err := Parse(d["key"], d["factor"], d["old_keys"], d["old_factors"])
	return cur, old, errors.Wrap(err, "OpenBAO root secret")
}

func baoJSON(client *http.Client, method, url, token string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return errors.Errorf("%s %s: HTTP %d %s", method, url, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Parse builds roots from raw env values (see Load).
func Parse(key, factor, oldKeys, oldFactors string) (cur *Root, old []*Root, err error) {
	master, err := decodeMaster(key)
	if err != nil {
		return nil, nil, err
	}
	if len(strings.TrimSpace(factor)) < minFactorLen {
		return nil, nil, errors.Errorf("%s must be set to a secret of at least %d bytes when %s is set (openssl rand -base64 32)", FactorEnv, minFactorLen, KeyEnv)
	}
	cur = &Root{Master: master, Factor: []byte(strings.TrimSpace(factor))}
	facs := strings.Split(oldFactors, ",")
	for i, k := range strings.Split(oldKeys, ",") {
		if strings.TrimSpace(k) == "" {
			continue
		}
		m, err := decodeMaster(k)
		if err != nil {
			return nil, nil, err
		}
		r := &Root{Master: m}
		if i < len(facs) && strings.TrimSpace(facs[i]) != "" {
			r.Factor = []byte(strings.TrimSpace(facs[i]))
		}
		old = append(old, r)
	}
	return cur, old, nil
}

func decodeMaster(s string) ([]byte, error) {
	m, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(m) != 32 {
		return nil, errors.New(KeyEnv + " and " + KeyOldEnv + " keys must be 32 bytes, base64-encoded (openssl rand -base64 32)")
	}
	return m, nil
}
