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

package time

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTimeDuration parses a time duration string
// supports: d, h, m, s, ms, us, ns
// eg: 7d1h2m3s, -2d1h2m3s
func ParseTimeDuration(durStr string) (out time.Duration, err error) {
	if strings.Contains(durStr, "d") {
		durStrSlice := strings.Split(durStr, "d")
		if len(durStrSlice) != 2 {
			return time.Duration(0), fmt.Errorf("invalid duration string %s", durStr)
		}
		var days float64
		days, err = strconv.ParseFloat(durStrSlice[0], 10)
		if err != nil {
			return time.Duration(0), fmt.Errorf("invalid duration string %s", durStr)
		}
		out += time.Duration(days * float64(24*time.Hour))
		if durStrSlice[1] != "" {
			leftDur, err := time.ParseDuration(durStrSlice[1])
			if err != nil {
				return time.Duration(0), fmt.Errorf("invalid duration string %s", durStr)
			}
			if leftDur < 0 {
				return time.Duration(0), fmt.Errorf("invalid duration string %s", durStr)
			}
			if days > 0 {
				out = out + leftDur
			} else {
				out = out - leftDur
			}
		}
		return out, nil
	}
	return time.ParseDuration(durStr)
}
