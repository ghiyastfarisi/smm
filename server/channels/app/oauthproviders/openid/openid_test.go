// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package oauthopenid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

func newProvider() *OpenIDProvider { return &OpenIDProvider{cache: map[string]discoveryEntry{}} }

func TestRegistered(t *testing.T) {
	require.NotNil(t, einterfaces.GetOAuthProvider(model.ServiceOpenid))
}

func TestGetSSOSettingsDiscoveryFillsOnlyEmptyEndpoints(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"authorization_endpoint":"http://idp/auth","token_endpoint":"http://idp/token","userinfo_endpoint":"http://idp/userinfo"}`))
	}))
	defer srv.Close()

	cfg := &model.Config{}
	cfg.SetDefaults()
	cfg.OpenIdSettings.DiscoveryEndpoint = new(srv.URL)
	cfg.OpenIdSettings.AuthEndpoint = new("http://localhost:8180/auth") // explicit value must win
	cfg.OpenIdSettings.TokenEndpoint = new("")
	cfg.OpenIdSettings.UserAPIEndpoint = new("")

	p := newProvider()
	sso, err := p.GetSSOSettings(request.TestContext(t), cfg, model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8180/auth", *sso.AuthEndpoint)
	assert.Equal(t, "http://idp/token", *sso.TokenEndpoint)
	assert.Equal(t, "http://idp/userinfo", *sso.UserAPIEndpoint)
	// live config untouched
	assert.Equal(t, "", *cfg.OpenIdSettings.TokenEndpoint)
	assert.Equal(t, "", *cfg.OpenIdSettings.UserAPIEndpoint)

	_, err = p.GetSSOSettings(request.TestContext(t), cfg, model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, 1, hits, "discovery document is cached")

	// all endpoints explicit: no discovery call at all
	cfg.OpenIdSettings.DiscoveryEndpoint = new("http://127.0.0.1:1/unreachable")
	cfg.OpenIdSettings.TokenEndpoint = new("http://keycloak:8080/token")
	cfg.OpenIdSettings.UserAPIEndpoint = new("http://keycloak:8080/userinfo")
	sso, err = p.GetSSOSettings(request.TestContext(t), cfg, model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, "http://keycloak:8080/token", *sso.TokenEndpoint)

	// discovery failure with missing endpoints is an error
	cfg.OpenIdSettings.TokenEndpoint = new("")
	_, err = p.GetSSOSettings(request.TestContext(t), cfg, model.ServiceOpenid)
	require.Error(t, err)

	// unknown service
	_, err = p.GetSSOSettings(request.TestContext(t), cfg, "nope")
	require.Error(t, err)
}

func TestGetUserFromJSON(t *testing.T) {
	p := newProvider()
	ctx := request.TestContext(t)
	body := `{"sub":"abc-123","email":"Sari@Smm.local","email_verified":true,"name":"Sari Lestari","given_name":"Sari","family_name":"Lestari","preferred_username":"sari@smm.local","picture":"x"}`

	u, err := p.GetUserFromJSON(ctx, strings.NewReader(body), nil, &model.SSOSettings{UsePreferredUsername: new(false)})
	require.NoError(t, err)
	assert.Equal(t, model.ServiceOpenid, u.AuthService)
	assert.Equal(t, "abc-123", *u.AuthData)
	assert.Equal(t, "sari@smm.local", u.Email)
	assert.Equal(t, "sari", u.Username) // local part of the e-mail
	assert.Equal(t, "Sari", u.FirstName)
	assert.Equal(t, "Lestari", u.LastName)

	u, err = p.GetUserFromJSON(ctx, strings.NewReader(body), nil, &model.SSOSettings{UsePreferredUsername: new(true)})
	require.NoError(t, err)
	assert.Equal(t, "sari", u.Username) // preferred_username split at '@'

	u, err = p.GetUserFromJSON(ctx, strings.NewReader(`{"sub":"1","email":"a@b.c","nickname":"Nick Name","name":"Ana Maria Souza"}`), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "nick-name", u.Username)
	assert.Equal(t, "Ana", u.FirstName)
	assert.Equal(t, "Maria Souza", u.LastName)

	// sub taken from the id_token user when the userinfo has none
	u, err = p.GetUserFromJSON(ctx, strings.NewReader(`{"email":"a@b.c"}`), &model.User{AuthData: new("tok-1")}, nil)
	require.NoError(t, err)
	assert.Equal(t, "tok-1", *u.AuthData)

	_, err = p.GetUserFromJSON(ctx, strings.NewReader(`{"email":"a@b.c"}`), nil, nil)
	require.ErrorContains(t, err, "sub")
	_, err = p.GetUserFromJSON(ctx, strings.NewReader(`{"sub":"1"}`), nil, nil)
	require.ErrorContains(t, err, "email")
	_, err = p.GetUserFromJSON(ctx, strings.NewReader(`not json`), nil, nil)
	require.Error(t, err)
}

func TestIsSameUser(t *testing.T) {
	p := newProvider()
	ctx := request.TestContext(t)
	assert.True(t, p.IsSameUser(ctx, &model.User{AuthData: new("x")}, &model.User{AuthData: new("x")}))
	assert.False(t, p.IsSameUser(ctx, &model.User{AuthData: new("x")}, &model.User{AuthData: new("y")}))
	assert.False(t, p.IsSameUser(ctx, &model.User{}, &model.User{AuthData: new("x")}))

	u, err := p.GetUserFromIdToken(ctx, "whatever")
	require.NoError(t, err)
	assert.Nil(t, u)
}
