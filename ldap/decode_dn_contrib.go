// The MIT License (MIT)

// Copyright (c) 2011-2015 Michael Mitton (mmitton@gmail.com)
// Portions copyright (c) 2015-2016 go-ldap Authors

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package ldap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// DecodeDN - remove leading and trailing spaces from the attribute type and value
// and unescape any escaped characters in these fields
//
// pulled from the go-ldap library
// https://github.com/go-ldap/ldap/blob/dbdc485259442f987d83e604cd4f5859cfc1be58/dn.go
func DecodeDN(str string) (string, error) {
	s := []rune(stripLeadingAndTrailingSpaces(str))

	builder := strings.Builder{}
	for i := 0; i < len(s); i++ {
		char := s[i]

		// If the character is not an escape character, just add it to the
		// builder and continue
		if char != '\\' {
			builder.WriteRune(char)
			continue
		}

		// If the escape character is the last character, it's a corrupted
		// escaped character
		if i+1 >= len(s) {
			return "", ldap.NewError(34, fmt.Errorf("got corrupted escaped character: '%s'", string(s)))
		}

		// If the escaped character is a special character, just add it to
		// the builder and continue
		switch s[i+1] {
		case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
			builder.WriteRune(s[i+1])
			i++
			continue
		}

		// If the escaped character is not a special character, it should
		// be a hex-encoded character of the form \XX if it's not at least
		// two characters long, it's a corrupted escaped character
		if i+2 >= len(s) {
			return "", ldap.NewError(34, errors.New("unable to decode escaped character: encoding/hex: invalid byte: "+string(s[i+1])))
		}

		// Get the runes for the two characters after the escape character
		// and convert them to a byte slice
		xx := []byte(string(s[i+1 : i+3]))

		// If the two runes are not hex characters and result in more than
		// two bytes when converted to a byte slice, it's a corrupted
		// escaped character
		if len(xx) != 2 {
			return "", ldap.NewError(34, fmt.Errorf("unable to decode escaped character: invalid byte: %s", string(xx)))
		}

		// Decode the hex-encoded character and add it to the builder
		dst := []byte{0}
		if n, err := hex.Decode(dst, xx); err != nil {
			return "", ldap.NewError(34, errors.New("unable to decode escaped character: "+err.Error()))
		} else if n != 1 {
			return "", ldap.NewError(34, fmt.Errorf("unable to decode escaped character: encoding/hex: expected 1 byte when un-escaping, got %d", n))
		}

		builder.WriteByte(dst[0])
		i += 2
	}

	return builder.String(), nil
}

func stripLeadingAndTrailingSpaces(inVal string) string {
	noSpaces := strings.Trim(inVal, " ")

	// Re-add the trailing space if it was an escaped space
	if len(noSpaces) > 0 && noSpaces[len(noSpaces)-1] == '\\' && inVal[len(inVal)-1] == ' ' {
		noSpaces += " "
	}

	return noSpaces
}
