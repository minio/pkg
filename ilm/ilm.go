// Copyright (c) 2015-2025 MinIO, Inc.
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

package ilm

import (
	"github.com/minio/minio-go/v7/pkg/lifecycle"
)

const defaultILMDateFormat string = "2006-01-02"

// LifecycleOptions - options for ILM rule
type LifecycleOptions struct {
	ID string

	Status *bool

	Prefix                *string
	Tags                  *string
	ObjectSizeLessThan    *int64
	ObjectSizeGreaterThan *int64
	ExpiryDate            *string
	ExpiryDays            *string
	TransitionDate        *string
	TransitionDays        *string
	StorageClass          *string

	ExpiredObjectDeleteMarker               *bool
	NoncurrentVersionExpirationDays         *int
	NewerNoncurrentExpirationVersions       *int
	NoncurrentVersionTransitionDays         *int
	NewerNoncurrentTransitionVersions       *int
	NoncurrentVersionTransitionStorageClass *string
	PurgeAllVersionsDays                    *string
	PurgeAllVersionsDeleteMarker            *bool
}

// Filter returns lifecycle.Filter appropriate for opts
func (opts LifecycleOptions) Filter() lifecycle.Filter {
	var f lifecycle.Filter
	var tags []lifecycle.Tag
	var predCount int
	if opts.Tags != nil {
		tags = extractILMTags(*opts.Tags)
		predCount += len(tags)
	}
	var prefix string
	if opts.Prefix != nil {
		prefix = *opts.Prefix
		predCount++
	}

	var szLt, szGt int64
	if opts.ObjectSizeLessThan != nil {
		szLt = *opts.ObjectSizeLessThan
		predCount++
	}

	if opts.ObjectSizeGreaterThan != nil {
		szGt = *opts.ObjectSizeGreaterThan
		predCount++
	}

	if predCount >= 2 {
		f.And = lifecycle.And{
			Tags:                  tags,
			Prefix:                prefix,
			ObjectSizeLessThan:    szLt,
			ObjectSizeGreaterThan: szGt,
		}
	} else {
		// In a valid lifecycle rule filter at most one of the
		// following will only be set.
		f.Prefix = prefix
		f.ObjectSizeGreaterThan = szGt
		f.ObjectSizeLessThan = szLt
		if len(tags) >= 1 {
			f.Tag = tags[0]
		}
	}

	return f
}

// ToILMRule creates lifecycle.Configuration based on LifecycleOptions
func (opts LifecycleOptions) ToILMRule() (lifecycle.Rule, error) {
	var (
		id, status string

		nonCurrentVersionExpirationDays         lifecycle.ExpirationDays
		newerNonCurrentExpirationVersions       int
		nonCurrentVersionTransitionDays         lifecycle.ExpirationDays
		newerNonCurrentTransitionVersions       int
		nonCurrentVersionTransitionStorageClass string
	)

	id = opts.ID
	status = func() string {
		if opts.Status != nil && !*opts.Status {
			return "Disabled"
		}
		// Generating a new ILM rule without explicit status is enabled
		return "Enabled"
	}()

	expiry, err := parseExpiry(opts.ExpiryDate, opts.ExpiryDays, opts.ExpiredObjectDeleteMarker)
	if err != nil {
		return lifecycle.Rule{}, err
	}

	allVersExpiry, err := parseAllVersionsExpiry(opts.PurgeAllVersionsDays, opts.PurgeAllVersionsDeleteMarker)
	if err != nil {
		return lifecycle.Rule{}, err
	}

	transition, err := parseTransition(opts.StorageClass, opts.TransitionDate, opts.TransitionDays)
	if err != nil {
		return lifecycle.Rule{}, err
	}

	if opts.NoncurrentVersionExpirationDays != nil {
		nonCurrentVersionExpirationDays = lifecycle.ExpirationDays(*opts.NoncurrentVersionExpirationDays)
	}
	if opts.NewerNoncurrentExpirationVersions != nil {
		newerNonCurrentExpirationVersions = *opts.NewerNoncurrentExpirationVersions
	}
	if opts.NoncurrentVersionTransitionDays != nil {
		nonCurrentVersionTransitionDays = lifecycle.ExpirationDays(*opts.NoncurrentVersionTransitionDays)
	}
	if opts.NewerNoncurrentTransitionVersions != nil {
		newerNonCurrentTransitionVersions = *opts.NewerNoncurrentTransitionVersions
	}
	if opts.NoncurrentVersionTransitionStorageClass != nil {
		nonCurrentVersionTransitionStorageClass = *opts.NoncurrentVersionTransitionStorageClass
	}

	newRule := lifecycle.Rule{
		ID:                    id,
		RuleFilter:            opts.Filter(),
		Status:                status,
		Expiration:            expiry,
		Transition:            transition,
		AllVersionsExpiration: allVersExpiry,
		NoncurrentVersionExpiration: lifecycle.NoncurrentVersionExpiration{
			NoncurrentDays:          nonCurrentVersionExpirationDays,
			NewerNoncurrentVersions: newerNonCurrentExpirationVersions,
		},
		NoncurrentVersionTransition: lifecycle.NoncurrentVersionTransition{
			NoncurrentDays:          nonCurrentVersionTransitionDays,
			NewerNoncurrentVersions: newerNonCurrentTransitionVersions,
			StorageClass:            nonCurrentVersionTransitionStorageClass,
		},
	}

	if err := validateILMRule(newRule); err != nil {
		return lifecycle.Rule{}, err
	}

	return newRule, nil
}

// ApplyRuleFields applies non nil fields of LifecycleOptions to the existing lifecycle rule
func ApplyRuleFields(dest *lifecycle.Rule, opts LifecycleOptions) error {
	// If src has tags, it should override the destination
	if opts.Tags != nil {
		dest.RuleFilter.And.Tags = extractILMTags(*opts.Tags)
		// If there are tag filters on the rule, the prefix filter must be in the And field, if tags are not used, prefix must be in the Prefix field
		if len(dest.RuleFilter.And.Prefix) > 0 || len(dest.RuleFilter.Prefix) > 0 {
			var p string
			if len(dest.RuleFilter.And.Prefix) > 0 {
				p = dest.RuleFilter.And.Prefix
			}
			if len(dest.RuleFilter.Prefix) > 0 {
				p = dest.RuleFilter.Prefix
			}
			if len(*opts.Tags) > 0 {
				dest.RuleFilter.And.Prefix = p
				dest.RuleFilter.Prefix = ""
			} else {
				dest.RuleFilter.Prefix = p
				dest.RuleFilter.And.Prefix = ""
			}
		}
	}

	// since prefix is a part of command args, it is always present in the src rule and
	// it should be always set to the destination.
	if opts.Prefix != nil {
		// if there are tags, the prefix must go into the And field, and the Prefix field must be empty
		if len(dest.RuleFilter.And.Tags) > 0 {
			dest.RuleFilter.Prefix = ""
			dest.RuleFilter.And.Prefix = *opts.Prefix
		} else {
			dest.RuleFilter.Prefix = *opts.Prefix
			dest.RuleFilter.And.Prefix = ""
		}
	}

	// only one of expiration day, date or transition day, date is expected
	if opts.ExpiryDate != nil {
		date, err := parseExpiryDate(*opts.ExpiryDate)
		if err != nil {
			return err
		}
		dest.Expiration.Date = date
		// reset everything else
		dest.Expiration.Days = 0
		dest.Expiration.DeleteMarker = false
	} else if opts.ExpiryDays != nil {
		days, err := parseExpiryDays(*opts.ExpiryDays)
		if err != nil {
			return err
		}
		dest.Expiration.Days = days
		// reset everything else
		dest.Expiration.Date = lifecycle.ExpirationDate{}
	} else if opts.ExpiredObjectDeleteMarker != nil {
		dest.Expiration.DeleteMarker = lifecycle.ExpireDeleteMarker(*opts.ExpiredObjectDeleteMarker)
		dest.Expiration.Days = 0
		dest.Expiration.Date = lifecycle.ExpirationDate{}
	}

	if opts.PurgeAllVersionsDays != nil {
		days, err := parseExpiryDays(*opts.PurgeAllVersionsDays)
		if err != nil {
			return err
		}
		dest.AllVersionsExpiration.Days = int(days)
	}
	if opts.PurgeAllVersionsDeleteMarker != nil {
		dest.AllVersionsExpiration.DeleteMarker = lifecycle.ExpireDeleteMarker(*opts.PurgeAllVersionsDeleteMarker)
	}

	if opts.TransitionDate != nil {
		date, err := parseTransitionDate(*opts.TransitionDate)
		if err != nil {
			return err
		}
		dest.Transition.Date = date
		// reset everything else
		dest.Transition.Days = 0
	} else if opts.TransitionDays != nil {
		days, err := parseTransitionDays(*opts.TransitionDays)
		if err != nil {
			return err
		}
		dest.Transition.Days = days
		// reset everything else
		dest.Transition.Date = lifecycle.ExpirationDate{}
	}

	if opts.NoncurrentVersionExpirationDays != nil {
		dest.NoncurrentVersionExpiration.NoncurrentDays = lifecycle.ExpirationDays(*opts.NoncurrentVersionExpirationDays)
	}

	if opts.NewerNoncurrentExpirationVersions != nil {
		dest.NoncurrentVersionExpiration.NewerNoncurrentVersions = *opts.NewerNoncurrentExpirationVersions
	}

	if opts.NoncurrentVersionTransitionDays != nil {
		dest.NoncurrentVersionTransition.NoncurrentDays = lifecycle.ExpirationDays(*opts.NoncurrentVersionTransitionDays)
	}

	if opts.NewerNoncurrentTransitionVersions != nil {
		dest.NoncurrentVersionTransition.NewerNoncurrentVersions = *opts.NewerNoncurrentTransitionVersions
	}

	if opts.NoncurrentVersionTransitionStorageClass != nil {
		dest.NoncurrentVersionTransition.StorageClass = *opts.NoncurrentVersionTransitionStorageClass
	}

	if opts.StorageClass != nil {
		dest.Transition.StorageClass = *opts.StorageClass
	}

	// Updated the status
	if opts.Status != nil {
		dest.Status = func() string {
			if *opts.Status {
				return "Enabled"
			}
			return "Disabled"
		}()
	}

	return nil
}
