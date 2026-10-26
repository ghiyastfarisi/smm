// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package keyring

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKey    = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes
	testKeyOld = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA="
	testFactor = "factor-one-0123456789"
)

// fakeBao serves KV v2 at secret/data/mrpostman/root for token "root" and for the AppRole pair.
func fakeBao(t *testing.T, data map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["role_id"] != "role" || in["secret_id"] != "secret" {
				http.Error(w, `{"errors":["invalid role or secret ID"]}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "approle-token"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/"+DefaultBaoPath:
			if tok := r.Header.Get("X-Vault-Token"); tok != "root" && tok != "approle-token" {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			if data == nil {
				http.Error(w, `{"errors":[]}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestKeyringOpenBAO(t *testing.T) {
	full := map[string]string{"key": testKey, "factor": testFactor, "old_keys": testKeyOld, "old_factors": "factor-two-0123456789"}
	envCur, envOld, err := Parse(testKey, testFactor, testKeyOld, "factor-two-0123456789")
	require.NoError(t, err)

	t.Run("token", func(t *testing.T) {
		srv := fakeBao(t, full)
		defer srv.Close()
		cur, old, err := loadOpenBAO(srv.URL, "root", "", "", "")
		require.NoError(t, err)
		assert.Equal(t, envCur, cur, "same material as the env vars")
		assert.Equal(t, envOld, old)
		assert.Equal(t, envCur.KID(), cur.KID(), "existing data keeps its kid")
	})

	t.Run("approle", func(t *testing.T) {
		srv := fakeBao(t, full)
		defer srv.Close()
		cur, _, err := loadOpenBAO(srv.URL+"/", "", "role", "secret", DefaultBaoPath)
		require.NoError(t, err)
		assert.Equal(t, envCur, cur)
		_, _, err = loadOpenBAO(srv.URL, "", "role", "wrong", "")
		assert.ErrorContains(t, err, "AppRole login")
	})

	t.Run("failures are errors, never env fallback", func(t *testing.T) {
		t.Setenv(KeyEnv, testKey)
		t.Setenv(FactorEnv, testFactor)
		srv := fakeBao(t, full)
		_, _, err := loadOpenBAO(srv.URL, "bad-token", "", "", "")
		assert.ErrorContains(t, err, "HTTP 403")
		_, _, err = loadOpenBAO(srv.URL, "", "", "", "")
		assert.ErrorContains(t, err, BaoTokenEnv)
		srv.Close()
		_, _, err = loadOpenBAO(srv.URL, "root", "", "", "")
		assert.Error(t, err, "unreachable")

		empty := fakeBao(t, nil)
		defer empty.Close()
		_, _, err = loadOpenBAO(empty.URL, "root", "", "", "")
		assert.ErrorContains(t, err, "HTTP 404")
		missing := fakeBao(t, map[string]string{"factor": testFactor})
		defer missing.Close()
		_, _, err = loadOpenBAO(missing.URL, "root", "", "", "")
		assert.ErrorContains(t, err, "no 'key' field")
		bad := fakeBao(t, map[string]string{"key": testKey, "factor": "short"})
		defer bad.Close()
		_, _, err = loadOpenBAO(bad.URL, "root", "", "", "")
		assert.ErrorContains(t, err, FactorEnv)
	})

	t.Run("Load prefers OpenBAO and caches it", func(t *testing.T) {
		t.Setenv(KeyEnv, testKeyOld) // must be ignored
		t.Setenv(FactorEnv, testFactor)
		srv := fakeBao(t, full)
		defer srv.Close()
		t.Setenv(BaoAddrEnv, srv.URL)
		t.Setenv(BaoTokenEnv, "root")
		cur, _, err := Load()
		require.NoError(t, err)
		assert.Equal(t, envCur, cur)
		assert.True(t, Enabled())
		srv.Close()
		again, _, err := Load()
		require.NoError(t, err, "second Load is served from the process cache")
		assert.Equal(t, cur, again)
	})

	t.Run("env mode unchanged", func(t *testing.T) {
		t.Setenv(BaoAddrEnv, "")
		t.Setenv(KeyEnv, testKey)
		t.Setenv(FactorEnv, testFactor)
		cur, _, err := Load()
		require.NoError(t, err)
		assert.Equal(t, envCur.KID(), cur.KID())
		t.Setenv(KeyEnv, "")
		cur, _, err = Load()
		require.NoError(t, err)
		assert.Nil(t, cur)
		assert.False(t, Enabled())
	})
}

func TestChannelKey(t *testing.T) {
	cur, _, err := Parse(testKey, testFactor, "", "")
	require.NoError(t, err)
	a, b := cur.ChannelKey("team1/chanA"), cur.ChannelKey("team1/chanB")
	assert.NotEqual(t, a, b, "one key per channel")
	assert.NotEqual(t, a, cur.ChannelKey("team2/chanA"), "team is part of the scope")
	assert.NotEqual(t, a, cur.Key(PurposeDBField), "distinct from the global v3 key")
	assert.Equal(t, a, cur.ChannelKey("team1/chanA"), "deterministic")
}
