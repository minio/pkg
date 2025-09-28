// Copyright (c) 2015-2025 MinIO, Inc.
//
// # This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

/////////// Types and functions for OpenID IAM testing

// OpenIDClientAppParams - contains openID client application params, used in
// testing.
type OpenIDClientAppParams struct {
	ClientID, ClientSecret, ProviderURL, RedirectURL string
	Transport                                        http.RoundTripper
	Debug                                            bool
}

// MockOpenIDTestUserInteraction - tries to login to dex using provided credentials.
// It performs the user's browser interaction to login and retrieves the auth
// code from dex and exchanges it for a JWT.
func MockOpenIDTestUserInteraction(ctx context.Context, pro OpenIDClientAppParams, username, password string) (string, string, string, error) {
	var debug bool

	debug = false
	if pro.Debug {
		debug = true
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if pro.Transport != nil {
		ctx = oidc.ClientContext(ctx, &http.Client{Transport: pro.Transport})
	}

	provider, err := oidc.NewProvider(ctx, pro.ProviderURL)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to create provider: %v", err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     pro.ClientID,
		ClientSecret: pro.ClientSecret,
		RedirectURL:  pro.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "groups", "offline_access"},
	}

	state := fmt.Sprintf("x%dx", time.Now().Unix())
	authCodeURL := oauth2Config.AuthCodeURL(state)

	var lastReq *http.Request
	checkRedirect := func(req *http.Request, _ []*http.Request) error {
		// Save the last request in a redirect chain.
		lastReq = req
		// We do not follow redirect back to client application.
		if req.URL.Path == "/oauth_callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}

	dexClient := http.Client{
		CheckRedirect: checkRedirect,
		Transport:     pro.Transport,
	}

	u, err := url.Parse(authCodeURL)
	if err != nil {
		return "", "", "", fmt.Errorf("url parse err: %v", err)
	}

	// Start the user auth flow. This page would present the login with
	// email or LDAP option.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", "", fmt.Errorf("new request err: %v", err)
	}
	resp, err := dexClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("auth url request err: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("auth url request returned HTTP status: %d", resp.StatusCode)
	}

	// Modify u to choose the ldap option
	u.Path += "/ldap"

	// Pick the LDAP login option. This would return a form page after
	// following some redirects. `lastReq` would be the URL of the form
	// page, where we need to POST (submit) the form.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", "", fmt.Errorf("new request err (/ldap): %v", err)
	}
	resp, err = dexClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("request err: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("ew request (/ldap) returned HTTP status: %d", resp.StatusCode)
	}

	// Fill the login form with our test creds:
	formData := url.Values{}
	formData.Set("login", username)
	formData.Set("password", password)
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, lastReq.URL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return "", "", "", fmt.Errorf("new request err (/login): %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = dexClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("post form err: %v", err)
	}

	if debug {
		fmt.Printf("resp: %#v %#v\n", resp.StatusCode, resp.Header)
		bodyBuf, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", "", "", fmt.Errorf("Error reading body: %v", err)
		}
		fmt.Printf("resp body: %s\n", string(bodyBuf))
		fmt.Printf("lastReq: %#v\n", lastReq.URL.String())
	}

	// On form submission, the last redirect response contains the auth
	// code, which we now have in `lastReq`. Exchange it for a JWT id_token.
	q := lastReq.URL.Query()
	code := q.Get("code")
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to exchange code for id token: %v", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", "", "", fmt.Errorf("id_token not found")
	}

	accessIDToken, ok := oauth2Token.Extra("access_token").(string)
	if !ok {
		return "", "", "", fmt.Errorf("access_token not found")
	}

	refreshToken, ok := oauth2Token.Extra("refresh_token").(string)
	if !ok {
		return "", "", "", fmt.Errorf("refresh_token not found")
	}

	return rawIDToken, accessIDToken, refreshToken, nil
}
