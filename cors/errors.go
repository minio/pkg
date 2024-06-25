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

import "fmt"

// ErrTooManyRules is returned when the number of CORS rules exceeds the allowed limit.
type ErrTooManyRules struct{}

func (e ErrTooManyRules) Error() string {
	return "The number of CORS rules should not exceed allowed limit of 100 rules."
}

// ErrMalformedXML is returned when the XML provided is not well-formed
type ErrMalformedXML struct{}

func (e ErrMalformedXML) Error() string {
	return "The XML you provided was not well-formed or did not validate against our published schema"
}

// ErrAllowedOriginWildcards is returned when more than one wildcard is found in an AllowedOrigin.
type ErrAllowedOriginWildcards struct {
	Origin string
}

func (e ErrAllowedOriginWildcards) Error() string {
	// S3 quotes the origin, e.g. "http://*.*.example.com", in the error message, but these quotes are currently
	// escaped by Go xml encoder. We could fix this with a `,innerxml` tag on the struct, but that has
	// other implications. Easier to not add quotes in our error for now, revisit if this is an issue.
	return fmt.Sprintf(`AllowedOrigin %s can not have more than one wildcard.`, e.Origin)
}

// ErrInvalidMethod is returned when an unsupported HTTP method is found in a CORS config.
type ErrInvalidMethod struct {
	Method string
}

func (e ErrInvalidMethod) Error() string {
	return fmt.Sprintf("Found unsupported HTTP method in CORS config. Unsupported method is %s", e.Method)
}

// ErrAllowedHeaderWildcards is returned when more than one wildcard is found in an AllowedHeader.
type ErrAllowedHeaderWildcards struct {
	Header string
}

func (e ErrAllowedHeaderWildcards) Error() string {
	// S3 quotes the header, e.g. "*-amz-*", in the error message, similar situation to ErrAllowedOriginWildcards above.
	return fmt.Sprintf(`AllowedHeader %s can not have more than one wildcard.`, e.Header)
}
