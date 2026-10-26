// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// Package oauthopenid is the fork's AGPL OpenID Connect provider. Upstream ships OpenID only in the private
// enterprise module (github.com/mattermost/enterprise/oauth/openid); this one works without a licence.
package oauthopenid

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

const discoveryTTL = 10 * time.Minute

// httpClient fetches discovery documents; a package variable so tests can swap it.
var httpClient = &http.Client{Timeout: 10 * time.Second}

type OpenIDProvider struct {
	mu    sync.Mutex
	cache map[string]discoveryEntry // keyed by discovery endpoint URL
}

type discoveryEntry struct {
	doc     discoveryDoc
	fetched time.Time
}

type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// UserInfo is the OpenID Connect standard-claims subset read from the userinfo endpoint.
type UserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
}

func init() {
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, &OpenIDProvider{cache: map[string]discoveryEntry{}})
}

func (ui *UserInfo) IsValid() error {
	if ui.Sub == "" {
		return errors.New("openid: userinfo has no sub claim")
	}
	if ui.Email == "" {
		return errors.New("openid: userinfo has no email claim (add the email scope)")
	}
	return nil
}

func userFromUserInfo(logger mlog.LoggerIFace, ui *UserInfo, settings *model.SSOSettings) *model.User {
	user := &model.User{}

	var username string
	if settings != nil && model.SafeDereference(settings.UsePreferredUsername) && ui.PreferredUsername != "" {
		username = strings.Split(ui.PreferredUsername, "@")[0]
	} else if ui.Nickname != "" {
		username = ui.Nickname
	} else {
		username = strings.Split(ui.Email, "@")[0]
	}
	user.Username = model.CleanUsername(logger, username)

	if ui.GivenName != "" || ui.FamilyName != "" {
		user.FirstName = ui.GivenName
		user.LastName = ui.FamilyName
	} else if splitName := strings.Split(ui.Name, " "); len(splitName) >= 2 {
		user.FirstName = splitName[0]
		user.LastName = strings.Join(splitName[1:], " ")
	} else {
		user.FirstName = ui.Name
	}

	user.Email = strings.ToLower(ui.Email)
	user.AuthData = new(ui.Sub)
	user.AuthService = model.ServiceOpenid
	return user
}

func (p *OpenIDProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, tokenUser *model.User, settings *model.SSOSettings) (*model.User, error) {
	var ui UserInfo
	if err := json.NewDecoder(data).Decode(&ui); err != nil {
		return nil, fmt.Errorf("openid: cannot parse userinfo: %w", err)
	}
	if ui.Sub == "" && tokenUser != nil && tokenUser.AuthData != nil {
		ui.Sub = *tokenUser.AuthData
	}
	if err := ui.IsValid(); err != nil {
		return nil, err
	}
	return userFromUserInfo(rctx.Logger(), &ui, settings), nil
}

// GetSSOSettings returns a copy of the settings of the service that started the flow. When a DiscoveryEndpoint
// is set, the endpoints left empty in the config are filled from the discovery document; explicit values win
// (the dev stack needs the browser-facing auth endpoint on localhost and the server-facing ones on the
// container hostname).
func (p *OpenIDProvider) GetSSOSettings(_ request.CTX, config *model.Config, service string) (*model.SSOSettings, error) {
	src := config.GetSSOService(service)
	if src == nil {
		return nil, fmt.Errorf("openid: no SSO settings for service %q", service)
	}
	sso := *src
	discoveryURL := model.SafeDereference(sso.DiscoveryEndpoint)
	if discoveryURL == "" || (model.SafeDereference(sso.AuthEndpoint) != "" &&
		model.SafeDereference(sso.TokenEndpoint) != "" && model.SafeDereference(sso.UserAPIEndpoint) != "") {
		return &sso, nil
	}
	doc, err := p.discover(discoveryURL)
	if err != nil {
		return nil, err
	}
	if model.SafeDereference(sso.AuthEndpoint) == "" {
		sso.AuthEndpoint = new(doc.AuthorizationEndpoint)
	}
	if model.SafeDereference(sso.TokenEndpoint) == "" {
		sso.TokenEndpoint = new(doc.TokenEndpoint)
	}
	if model.SafeDereference(sso.UserAPIEndpoint) == "" {
		sso.UserAPIEndpoint = new(doc.UserinfoEndpoint)
	}
	return &sso, nil
}

func (p *OpenIDProvider) discover(discoveryURL string) (discoveryDoc, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.cache[discoveryURL]; ok && time.Since(e.fetched) < discoveryTTL {
		return e.doc, nil
	}
	resp, err := httpClient.Get(discoveryURL)
	if err != nil {
		return discoveryDoc{}, fmt.Errorf("openid: discovery %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discoveryDoc{}, fmt.Errorf("openid: discovery %s: status %d", discoveryURL, resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return discoveryDoc{}, fmt.Errorf("openid: discovery %s: %w", discoveryURL, err)
	}
	p.cache[discoveryURL] = discoveryEntry{doc: doc, fetched: time.Now()}
	return doc, nil
}

// GetUserFromIdToken returns nil: the user is read from the userinfo endpoint, which the server calls with the
// access token it just obtained over the back channel, so the identity is already authenticated. Verifying the
// id_token locally would need JWKS fetching and signature checks and is not required for correctness here.
func (p *OpenIDProvider) GetUserFromIdToken(_ request.CTX, _ string) (*model.User, error) {
	return nil, nil
}

func (p *OpenIDProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	return dbUser.AuthData != nil && oauthUser.AuthData != nil && *dbUser.AuthData == *oauthUser.AuthData
}
