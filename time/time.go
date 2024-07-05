// Copyright (c) 2015-2024 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
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

package cmd

import (
	"fmt"
	"strconv"
	"time"
)

// ParseTimeDuration parses a time duration string
// supports: d, h, m, s, ms, us, ns
// eg: 7d1h2m3s, -2d1h2m3s
func ParseTimeDuration(durStr string) (time.Duration, error) {
	out := time.Duration(0)
	num := ""
	unit := ""
	isNegative := false
	parsedUint := map[string]bool{}
	isFirst := true
	add := func(num, unit string) error {
		if parsedUint[unit] {
			return fmt.Errorf("duplicate unit %s", unit)
		}
		parsedUint[unit] = true
		number, err := strconv.Atoi(num)
		if err != nil {
			return err
		}
		if !isFirst && number < 0 {
			return fmt.Errorf("negative number %d", number)
		}
		if isFirst {
			if number < 0 {
				isNegative = true
			}
			isFirst = false
		}
		if isNegative && number > 0 {
			number *= -1
		}
		switch unit {
		case "d":
			out += time.Hour * time.Duration(24*number)
		case "h":
			out += time.Hour * time.Duration(number)
		case "m":
			out += time.Minute * time.Duration(number)
		case "s":
			out += time.Second * time.Duration(number)
		case "ms":
			out += time.Millisecond * time.Duration(number)
		case "us":
			out += time.Microsecond * time.Duration(number)
		case "ns":
			out += time.Nanosecond * time.Duration(number)
		default:
			return fmt.Errorf("invalid unit %s", unit)
		}
		return nil
	}
	for _, c := range durStr {
		if c >= '0' && c <= '9' || c == '-' {
			if unit != "" {
				err := add(num, unit)
				if err != nil {
					return 0, err
				}
				unit = ""
				num = ""
			}
			num += string(c)
		} else {
			unit += string(c)
		}
	}
	if num != "" && unit != "" {
		err := add(num, unit)
		if err != nil {
			return 0, err
		}
	}
	return out, nil
}
