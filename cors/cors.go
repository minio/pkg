// Copyright (c) 2015-2024 MinIO, Inc.
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

package cors

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/minio/pkg/v3/wildcard"
)

const defaultXMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

var allowedCORSRuleMethods = map[string]bool{
	http.MethodGet:    true,
	http.MethodPut:    true,
	http.MethodPost:   true,
	http.MethodDelete: true,
	http.MethodHead:   true,
}

// Config is the container for a CORS configuration for a bucket.
type Config struct {
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	XMLName   xml.Name `xml:"CORSConfiguration"`
	CORSRules []Rule   `xml:"CORSRule"`
}

// Rule is a single rule in a CORS configuration.
type Rule struct {
	AllowedHeader []string `xml:"AllowedHeader,omitempty"`
	AllowedMethod []string `xml:"AllowedMethod,omitempty"`
	AllowedOrigin []string `xml:"AllowedOrigin,omitempty"`
	ExposeHeader  []string `xml:"ExposeHeader,omitempty"`
	ID            string   `xml:"ID,omitempty"`
	MaxAgeSeconds int      `xml:"MaxAgeSeconds,omitempty"`
}

// Validate checks the CORS configuration is valid. This has been implemented to return errors that can be transformed
// to match the S3 API externally, while being slightly more informative internally using wrapping.
// Validate copies S3 behavior, and validates one rule at a time, erroring on the first invalid one found.
func (c *Config) Validate() error {
	if len(c.CORSRules) == 0 {
		return fmt.Errorf("no CORS rules found, %w", ErrMalformedXML{})
	}
	if len(c.CORSRules) > 100 {
		return fmt.Errorf("too many CORS rules, max 100 allowed, got: %d, %w", len(c.CORSRules), ErrTooManyRules{})
	}
	for _, rule := range c.CORSRules {
		// Origin validation
		if len(rule.AllowedOrigin) == 0 {
			return fmt.Errorf("no AllowedOrigin found in CORS rule, id: %s, %w", rule.ID, ErrMalformedXML{})
		}
		for _, origin := range rule.AllowedOrigin {
			if strings.Count(origin, "*") > 1 {
				return fmt.Errorf("origin %s in CORS rule, id: %s, %w", origin, rule.ID, ErrAllowedOriginWildcards{Origin: origin})
			}
		}

		// Methods validation
		if len(rule.AllowedMethod) == 0 {
			return fmt.Errorf("no AllowedMethod found in CORS rule, id: %s, %w", rule.ID, ErrMalformedXML{})
		}
		for _, method := range rule.AllowedMethod {
			if !allowedCORSRuleMethods[method] {
				return fmt.Errorf("method %s in CORS rule, id: %s, %w", method, rule.ID, ErrInvalidMethod{Method: method})
			}
		}

		// Headers validation
		for _, header := range rule.AllowedHeader {
			if strings.Count(header, "*") > 1 {
				return fmt.Errorf("header %s in CORS rule, id: %s, %w", header, rule.ID, ErrAllowedHeaderWildcards{Header: header})
			}
		}
	}

	return nil
}

// HasAllowedOrigin returns true if the given origin is allowed by the CORS rule
func (c *Rule) HasAllowedOrigin(origin string) bool {
	// See "AllowedOrigin element" in https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html
	for _, allowedOrigin := range c.AllowedOrigin {
		if wildcard.Match(allowedOrigin, origin) {
			// Only one wildcard character (*) is allowed by S3 spec, but Match does
			// not enforce that, it's done by Validate() function.
			// Origins are case sensitive
			return true
		}
	}
	return false
}

// HasAllowedMethod returns true if the given method is contained in the CORS rule.
func (c *Rule) HasAllowedMethod(method string) bool {
	// See "AllowedMethod element" in https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html
	for _, allowedMethod := range c.AllowedMethod {
		if allowedMethod == method {
			// Methods are always uppercase, enforced by Validate() function.
			return true
		}
	}
	return false
}

// FilterAllowedHeaders returns the headers that are allowed by the rule, and a boolean indicating if all headers are allowed.
func (c *Rule) FilterAllowedHeaders(headers []string) ([]string, bool) {
	// See "AllowedHeader element" in https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html
	// It's inefficient to store the CORS config verbatim and run ToLower here, but S3 essentially
	// behaves this way, and will return the XML config verbatim when you GET it.
	filtered := []string{}
	for _, header := range headers {
		header = strings.ToLower(header)
		found := false
		for _, allowedHeader := range c.AllowedHeader {
			// Case insensitive comparison for headers
			if wildcard.Match(strings.ToLower(allowedHeader), header) {
				// Only one wildcard character (*) is allowed by S3 spec, but Match does
				// not enforce that, it's done by rule.Validate() function.
				filtered = append(filtered, header)
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return filtered, true
}

// ParseBucketCorsConfig parses a CORS configuration in XML from an io.Reader.
func ParseBucketCorsConfig(reader io.Reader) (*Config, error) {
	var c Config
	err := xml.NewDecoder(reader).Decode(&c)
	if err != nil {
		return nil, fmt.Errorf("decoding xml: %w", err)
	}
	if c.XMLNS == "" {
		c.XMLNS = defaultXMLNS
	}
	for i, rule := range c.CORSRules {
		for j, method := range rule.AllowedMethod {
			c.CORSRules[i].AllowedMethod[j] = strings.ToUpper(method)
		}
	}
	return &c, nil
}

// ToXML marshals the CORS configuration to XML.
func (c Config) ToXML() ([]byte, error) {
	if c.XMLNS == "" {
		c.XMLNS = defaultXMLNS
	}
	data, err := xml.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("marshaling xml: %w", err)
	}
	return append([]byte(xml.Header), data...), nil
}
