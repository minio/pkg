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
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// CLILoginClaims holds the claims for CLI login tokens.
type CLILoginClaims struct {
	c *cliLoginClaims
}

type cliLoginClaims struct {
	Port   int       `json:"port"`
	ReqID  string    `json:"req_id"`
	Expiry time.Time `json:"expiry"`
}

// NewCLILoginClaims creates a new CLILoginClaims with the given port and request ID.
func NewCLILoginClaims(port int, reqID string) *CLILoginClaims {
	return &CLILoginClaims{
		c: &cliLoginClaims{
			Port:   port,
			ReqID:  reqID,
			Expiry: time.Now().UTC().Add(5 * time.Minute),
		},
	}
}

// ParseCLILoginClaims parses a base64-encoded JWT token string and returns the CLILoginClaims if valid.
func ParseCLILoginClaims(tokenString, secret string) (*CLILoginClaims, error) {
	decodedToken, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, err
	}

	claims := &cliLoginClaims{}
	_, err = jwt.ParseWithClaims(string(decodedToken), claims, func(_ *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	return &CLILoginClaims{c: claims}, nil
}

func (c *cliLoginClaims) Valid() error {
	if time.Now().UTC().After(c.Expiry) {
		return errors.New("token is expired")
	}
	return nil
}

// Port returns the port from the CLI login claims.
func (c *CLILoginClaims) Port() int {
	return c.c.Port
}

// ToTokenString serializes the CLILoginClaims to a base64-encoded JWT token string signed with the given secret.
func (c *CLILoginClaims) ToTokenString(secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c.c)
	sString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(sString)), nil
}

// SignCredentials signs the given credentials using the request ID as the secret and returns a base64-encoded JWT token string.
func (c *CLILoginClaims) SignCredentials(creds credentials.Value) (string, error) {
	claims := &credentialsClaims{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	sString, err := token.SignedString([]byte(c.c.ReqID))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(sString)), nil
}

type credentialsClaims struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token,omitempty"`
	Expiration      time.Time `json:"expiration,omitempty"`
}

func (c *credentialsClaims) Valid() error {
	if !c.Expiration.IsZero() && time.Now().UTC().After(c.Expiration) {
		return errors.New("credentials token is expired")
	}
	return nil
}

// ParseSignedCredentials parses a base64-encoded JWT token string and returns the credentials Value if valid.
func ParseSignedCredentials(tokenString, reqID string) (credentials.Value, error) {
	decodedToken, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return credentials.Value{}, err
	}

	claims := &credentialsClaims{}
	_, err = jwt.ParseWithClaims(string(decodedToken), claims, func(_ *jwt.Token) (any, error) {
		return []byte(reqID), nil
	})
	if err != nil {
		return credentials.Value{}, err
	}

	return credentials.Value{
		AccessKeyID:     claims.AccessKeyID,
		SecretAccessKey: claims.SecretAccessKey,
		SessionToken:    claims.SessionToken,
		Expiration:      claims.Expiration,
	}, nil
}
