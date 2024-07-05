package cmd

import (
	"fmt"
	"strconv"
	"time"
)

// ParseTimeDurationSimply parses a time duration string
// supports: d, h, m, s, ms, us, ns
// eg: 7d1h2m3s, -2d1h2m3s
func ParseTimeDurationSimply(durStr string) (time.Duration, error) {
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
