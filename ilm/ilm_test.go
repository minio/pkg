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
	"fmt"
	"strings"
	"testing"

	"github.com/dustin/go-humanize"
	"github.com/go-openapi/swag/conv"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
)

func TestOptionFilter(t *testing.T) {
	emptyFilter := lifecycle.Filter{}
	emptyOpts := LifecycleOptions{}

	filterWithPrefix := lifecycle.Filter{
		Prefix: "doc/",
	}
	optsWithPrefix := LifecycleOptions{
		Prefix: conv.Pointer("doc/"),
	}

	filterWithTag := lifecycle.Filter{
		Tag: lifecycle.Tag{
			Key:   "key1",
			Value: "value1",
		},
	}
	optsWithTag := LifecycleOptions{
		Tags: conv.Pointer("key1=value1"),
	}

	filterWithSzLt := lifecycle.Filter{
		ObjectSizeLessThan: 100 * humanize.MiByte,
	}
	optsWithSzLt := LifecycleOptions{
		ObjectSizeLessThan: conv.Pointer(int64(100 * humanize.MiByte)),
	}

	filterWithSzGt := lifecycle.Filter{
		ObjectSizeGreaterThan: 1 * humanize.MiByte,
	}
	optsWithSzGt := LifecycleOptions{
		ObjectSizeGreaterThan: conv.Pointer(int64(1 * humanize.MiByte)),
	}

	filterWithAnd := lifecycle.Filter{
		And: lifecycle.And{
			Prefix: "doc/",
			Tags: []lifecycle.Tag{
				{
					Key:   "key1",
					Value: "value1",
				},
			},
			ObjectSizeLessThan:    100 * humanize.MiByte,
			ObjectSizeGreaterThan: 1 * humanize.MiByte,
		},
	}
	optsWithAnd := LifecycleOptions{
		Prefix:                conv.Pointer("doc/"),
		Tags:                  conv.Pointer("key1=value1"),
		ObjectSizeLessThan:    conv.Pointer(int64(100 * humanize.MiByte)),
		ObjectSizeGreaterThan: conv.Pointer(int64(1 * humanize.MiByte)),
	}

	tests := []struct {
		opts LifecycleOptions
		want lifecycle.Filter
	}{
		{
			opts: emptyOpts,
			want: emptyFilter,
		},
		{
			opts: optsWithPrefix,
			want: filterWithPrefix,
		},
		{
			opts: optsWithTag,
			want: filterWithTag,
		},
		{
			opts: optsWithSzGt,
			want: filterWithSzGt,
		},
		{
			opts: optsWithSzLt,
			want: filterWithSzLt,
		},
		{
			opts: optsWithAnd,
			want: filterWithAnd,
		},
	}

	filterEq := func(a, b lifecycle.Filter) bool {
		if a.ObjectSizeGreaterThan != b.ObjectSizeGreaterThan {
			return false
		}
		if a.ObjectSizeLessThan != b.ObjectSizeLessThan {
			return false
		}
		if a.Prefix != b.Prefix {
			return false
		}
		if a.Tag != b.Tag {
			return false
		}

		if a.And.ObjectSizeGreaterThan != b.And.ObjectSizeGreaterThan {
			return false
		}
		if a.And.ObjectSizeLessThan != b.And.ObjectSizeLessThan {
			return false
		}
		if a.And.Prefix != b.And.Prefix {
			return false
		}
		if len(a.And.Tags) != len(b.And.Tags) {
			return false
		}
		for i := range a.And.Tags {
			if a.And.Tags[i] != b.And.Tags[i] {
				return false
			}
		}

		return true
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Test %d", i+1), func(t *testing.T) {
			if got := test.opts.Filter(); !filterEq(got, test.want) {
				t.Fatalf("Expected %#v but got %#v", test.want, got)
			}
		})
	}
}

func TestToILMRule(t *testing.T) {
	tests := []struct {
		name    string
		opts    LifecycleOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid rule with expiry days",
			opts: LifecycleOptions{
				ID:         "test-rule-1",
				Status:     conv.Pointer(true),
				ExpiryDays: conv.Pointer("30"),
			},
			wantErr: false,
		},
		{
			name: "Valid rule with expiry date",
			opts: LifecycleOptions{
				ID:         "test-rule-2",
				Status:     conv.Pointer(true),
				ExpiryDate: conv.Pointer("2025-12-01"),
			},
			wantErr: false,
		},
		{
			name: "Valid rule with transition",
			opts: LifecycleOptions{
				ID:             "test-rule-3",
				Status:         conv.Pointer(true),
				TransitionDays: conv.Pointer("30"),
				StorageClass:   conv.Pointer("STANDARD_IA"),
			},
			wantErr: false,
		},
		{
			name: "Valid rule with delete marker expiration",
			opts: LifecycleOptions{
				ID:                        "test-rule-4",
				Status:                    conv.Pointer(true),
				ExpiredObjectDeleteMarker: conv.Pointer(true),
			},
			wantErr: false,
		},
		{
			name: "Rule with noncurrent version expiration",
			opts: LifecycleOptions{
				ID:                              "test-rule-5",
				Status:                          conv.Pointer(true),
				NoncurrentVersionExpirationDays: conv.Pointer(30),
			},
			wantErr: false,
		},
		{
			name: "Rule with noncurrent version transition",
			opts: LifecycleOptions{
				ID:                                      "test-rule-6",
				Status:                                  conv.Pointer(true),
				NoncurrentVersionTransitionDays:         conv.Pointer(30),
				NoncurrentVersionTransitionStorageClass: conv.Pointer("GLACIER"),
			},
			wantErr: false,
		},
		{
			name: "Rule with filter properties",
			opts: LifecycleOptions{
				ID:                    "test-rule-7",
				Status:                conv.Pointer(true),
				Prefix:                conv.Pointer("documents/"),
				Tags:                  conv.Pointer("env=prod&tier=gold"),
				ObjectSizeLessThan:    conv.Pointer(int64(100 * humanize.MiByte)),
				ObjectSizeGreaterThan: conv.Pointer(int64(1 * humanize.MiByte)),
				ExpiryDays:            conv.Pointer("90"),
			},
			wantErr: false,
		},
		{
			name: "Rule with purge all versions",
			opts: LifecycleOptions{
				ID:                           "test-rule-8",
				Status:                       conv.Pointer(true),
				PurgeAllVersionsDays:         conv.Pointer("7"),
				PurgeAllVersionsDeleteMarker: conv.Pointer(true),
			},
			wantErr: false,
		},
		{
			name: "Invalid rule - no actions",
			opts: LifecycleOptions{
				ID:     "test-rule-9",
				Status: conv.Pointer(true),
			},
			wantErr: true,
			errMsg:  errRuleAction.Error(),
		},
		{
			name: "Invalid rule - invalid expiry date",
			opts: LifecycleOptions{
				ID:         "test-rule-10",
				Status:     conv.Pointer(true),
				ExpiryDate: conv.Pointer("invalid-date"),
			},
			wantErr: true,
		},
		{
			name: "Invalid rule - zero expiry days",
			opts: LifecycleOptions{
				ID:         "test-rule-11",
				Status:     conv.Pointer(true),
				ExpiryDays: conv.Pointer("0"),
			},
			wantErr: true,
			errMsg:  errZeroExpiryDays.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := tt.opts.ToILMRule()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ToILMRule() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ToILMRule() error = %v, want error containing %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ToILMRule() unexpected error = %v", err)
				return
			}

			if rule.ID != tt.opts.ID {
				t.Errorf("ToILMRule() rule.ID = %v, want %v", rule.ID, tt.opts.ID)
			}

			expectedStatus := "Enabled"
			if tt.opts.Status != nil && !*tt.opts.Status {
				expectedStatus = "Disabled"
			}
			if rule.Status != expectedStatus {
				t.Errorf("ToILMRule() rule.Status = %v, want %v", rule.Status, expectedStatus)
			}
		})
	}
}

func TestApplyRuleFields(t *testing.T) {
	baseRule := lifecycle.Rule{
		ID:     "base-rule",
		Status: "Enabled",
		RuleFilter: lifecycle.Filter{
			Prefix: "old-prefix/",
		},
		Expiration: lifecycle.Expiration{
			Days: 30,
		},
		Transition: lifecycle.Transition{
			Days:         10,
			StorageClass: "STANDARD_IA",
		},
		NoncurrentVersionExpiration: lifecycle.NoncurrentVersionExpiration{
			NoncurrentDays: 15,
		},
		NoncurrentVersionTransition: lifecycle.NoncurrentVersionTransition{
			NoncurrentDays:          10,
			StorageClass:            "GLACIER",
			NewerNoncurrentVersions: 5,
		},
	}

	tests := []struct {
		name    string
		opts    LifecycleOptions
		wantErr bool
	}{
		{
			name: "Update prefix",
			opts: LifecycleOptions{
				Prefix: conv.Pointer("new-prefix/"),
			},
			wantErr: false,
		},
		{
			name: "Update tags",
			opts: LifecycleOptions{
				Tags: conv.Pointer("env=test&type=backup"),
			},
			wantErr: false,
		},
		{
			name: "Update tags and prefix",
			opts: LifecycleOptions{
				Prefix: conv.Pointer("tagged-prefix/"),
				Tags:   conv.Pointer("key1=value1"),
			},
			wantErr: false,
		},
		{
			name: "Update expiry date",
			opts: LifecycleOptions{
				ExpiryDate: conv.Pointer("2025-12-31"),
			},
			wantErr: false,
		},
		{
			name: "Update expiry days",
			opts: LifecycleOptions{
				ExpiryDays: conv.Pointer("60"),
			},
			wantErr: false,
		},
		{
			name: "Update expired delete marker",
			opts: LifecycleOptions{
				ExpiredObjectDeleteMarker: conv.Pointer(true),
			},
			wantErr: false,
		},
		{
			name: "Update transition date",
			opts: LifecycleOptions{
				TransitionDate: conv.Pointer("2025-06-01"),
			},
			wantErr: false,
		},
		{
			name: "Update transition days",
			opts: LifecycleOptions{
				TransitionDays: conv.Pointer("45"),
			},
			wantErr: false,
		},
		{
			name: "Update storage class",
			opts: LifecycleOptions{
				StorageClass: conv.Pointer("GLACIER"),
			},
			wantErr: false,
		},
		{
			name: "Update noncurrent version expiration",
			opts: LifecycleOptions{
				NoncurrentVersionExpirationDays: conv.Pointer(45),
			},
			wantErr: false,
		},
		{
			name: "Update newer noncurrent expiration versions",
			opts: LifecycleOptions{
				NewerNoncurrentExpirationVersions: conv.Pointer(10),
			},
			wantErr: false,
		},
		{
			name: "Update noncurrent version transition days",
			opts: LifecycleOptions{
				NoncurrentVersionTransitionDays: conv.Pointer(20),
			},
			wantErr: false,
		},
		{
			name: "Update newer noncurrent transition versions",
			opts: LifecycleOptions{
				NewerNoncurrentTransitionVersions: conv.Pointer(3),
			},
			wantErr: false,
		},
		{
			name: "Update noncurrent version transition storage class",
			opts: LifecycleOptions{
				NoncurrentVersionTransitionStorageClass: conv.Pointer("DEEP_ARCHIVE"),
			},
			wantErr: false,
		},
		{
			name: "Update purge all versions days",
			opts: LifecycleOptions{
				PurgeAllVersionsDays: conv.Pointer("7"),
			},
			wantErr: false,
		},
		{
			name: "Update purge all versions delete marker",
			opts: LifecycleOptions{
				PurgeAllVersionsDeleteMarker: conv.Pointer(true),
			},
			wantErr: false,
		},
		{
			name: "Update status to disabled",
			opts: LifecycleOptions{
				Status: conv.Pointer(false),
			},
			wantErr: false,
		},
		{
			name: "Update status to enabled",
			opts: LifecycleOptions{
				Status: conv.Pointer(true),
			},
			wantErr: false,
		},
		{
			name: "Invalid expiry date",
			opts: LifecycleOptions{
				ExpiryDate: conv.Pointer("invalid-date"),
			},
			wantErr: true,
		},
		{
			name: "Invalid expiry days",
			opts: LifecycleOptions{
				ExpiryDays: conv.Pointer("invalid"),
			},
			wantErr: true,
		},
		{
			name: "Invalid transition date",
			opts: LifecycleOptions{
				TransitionDate: conv.Pointer("invalid-date"),
			},
			wantErr: true,
		},
		{
			name: "Invalid transition days",
			opts: LifecycleOptions{
				TransitionDays: conv.Pointer("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := baseRule
			err := ApplyRuleFields(&rule, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ApplyRuleFields() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ApplyRuleFields() unexpected error = %v", err)
			}

			if tt.opts.Prefix != nil {
				expectedPrefix := *tt.opts.Prefix
				actualPrefix := ""
				if len(rule.RuleFilter.And.Tags) > 0 {
					actualPrefix = rule.RuleFilter.And.Prefix
				} else {
					actualPrefix = rule.RuleFilter.Prefix
				}
				if actualPrefix != expectedPrefix {
					t.Errorf("ApplyRuleFields() prefix = %v, want %v", actualPrefix, expectedPrefix)
				}
			}

			if tt.opts.Status != nil {
				expectedStatus := "Enabled"
				if !*tt.opts.Status {
					expectedStatus = "Disabled"
				}
				if rule.Status != expectedStatus {
					t.Errorf("ApplyRuleFields() status = %v, want %v", rule.Status, expectedStatus)
				}
			}

			if tt.opts.StorageClass != nil {
				if rule.Transition.StorageClass != *tt.opts.StorageClass {
					t.Errorf("ApplyRuleFields() transition storage class = %v, want %v", rule.Transition.StorageClass, *tt.opts.StorageClass)
				}
			}

			if tt.opts.NoncurrentVersionExpirationDays != nil {
				expectedDays := lifecycle.ExpirationDays(*tt.opts.NoncurrentVersionExpirationDays)
				if rule.NoncurrentVersionExpiration.NoncurrentDays != expectedDays {
					t.Errorf("ApplyRuleFields() noncurrent expiration days = %v, want %v", rule.NoncurrentVersionExpiration.NoncurrentDays, expectedDays)
				}
			}

			if tt.opts.NewerNoncurrentExpirationVersions != nil {
				if rule.NoncurrentVersionExpiration.NewerNoncurrentVersions != *tt.opts.NewerNoncurrentExpirationVersions {
					t.Errorf("ApplyRuleFields() newer noncurrent expiration versions = %v, want %v", rule.NoncurrentVersionExpiration.NewerNoncurrentVersions, *tt.opts.NewerNoncurrentExpirationVersions)
				}
			}

			if tt.opts.NoncurrentVersionTransitionDays != nil {
				expectedDays := lifecycle.ExpirationDays(*tt.opts.NoncurrentVersionTransitionDays)
				if rule.NoncurrentVersionTransition.NoncurrentDays != expectedDays {
					t.Errorf("ApplyRuleFields() noncurrent transition days = %v, want %v", rule.NoncurrentVersionTransition.NoncurrentDays, expectedDays)
				}
			}

			if tt.opts.NewerNoncurrentTransitionVersions != nil {
				if rule.NoncurrentVersionTransition.NewerNoncurrentVersions != *tt.opts.NewerNoncurrentTransitionVersions {
					t.Errorf("ApplyRuleFields() newer noncurrent transition versions = %v, want %v", rule.NoncurrentVersionTransition.NewerNoncurrentVersions, *tt.opts.NewerNoncurrentTransitionVersions)
				}
			}

			if tt.opts.NoncurrentVersionTransitionStorageClass != nil {
				if rule.NoncurrentVersionTransition.StorageClass != *tt.opts.NoncurrentVersionTransitionStorageClass {
					t.Errorf("ApplyRuleFields() noncurrent transition storage class = %v, want %v", rule.NoncurrentVersionTransition.StorageClass, *tt.opts.NoncurrentVersionTransitionStorageClass)
				}
			}
		})
	}
}

func TestExtractILMTags(t *testing.T) {
	tests := []struct {
		name     string
		tagInput string
		expected []lifecycle.Tag
	}{
		{
			name:     "Empty string",
			tagInput: "",
			expected: []lifecycle.Tag{},
		},
		{
			name:     "Single tag with value",
			tagInput: "key1=value1",
			expected: []lifecycle.Tag{
				{Key: "key1", Value: "value1"},
			},
		},
		{
			name:     "Single tag without value",
			tagInput: "key1",
			expected: []lifecycle.Tag{
				{Key: "key1", Value: ""},
			},
		},
		{
			name:     "Multiple tags",
			tagInput: "env=prod&tier=gold&owner=team1",
			expected: []lifecycle.Tag{
				{Key: "env", Value: "prod"},
				{Key: "tier", Value: "gold"},
				{Key: "owner", Value: "team1"},
			},
		},
		{
			name:     "Mixed tags with and without values",
			tagInput: "env=prod&debug&tier=gold",
			expected: []lifecycle.Tag{
				{Key: "env", Value: "prod"},
				{Key: "debug", Value: ""},
				{Key: "tier", Value: "gold"},
			},
		},
		{
			name:     "Empty tag in sequence",
			tagInput: "env=prod&&tier=gold",
			expected: []lifecycle.Tag{
				{Key: "env", Value: "prod"},
				{Key: "tier", Value: "gold"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractILMTags(tt.tagInput)

			if len(result) != len(tt.expected) {
				t.Errorf("extractILMTags() returned %d tags, expected %d", len(result), len(tt.expected))
				return
			}

			for i, tag := range result {
				if tag.Key != tt.expected[i].Key || tag.Value != tt.expected[i].Value {
					t.Errorf("extractILMTags() tag %d = {%s: %s}, expected {%s: %s}",
						i, tag.Key, tag.Value, tt.expected[i].Key, tt.expected[i].Value)
				}
			}
		})
	}
}

func TestValidationFunctions(t *testing.T) {
	t.Run("validateTranDays", func(t *testing.T) {
		// Test negative days
		rule := lifecycle.Rule{
			Transition: lifecycle.Transition{
				Days: -1,
			},
		}
		if err := validateTranDays(rule); err == nil {
			t.Error("validateTranDays() should error for negative days")
		}

		// Test STANDARD_IA with less than 30 days
		rule.Transition.Days = 15
		rule.Transition.StorageClass = "STANDARD_IA"
		if err := validateTranDays(rule); err == nil {
			t.Error("validateTranDays() should error for STANDARD_IA with less than 30 days")
		}

		// Test STANDARD_IA with 30 days (valid)
		rule.Transition.Days = 30
		if err := validateTranDays(rule); err != nil {
			t.Errorf("validateTranDays() should not error for STANDARD_IA with 30 days: %v", err)
		}

		// Test other storage class with less than 30 days (valid)
		rule.Transition.Days = 15
		rule.Transition.StorageClass = "GLACIER"
		if err := validateTranDays(rule); err != nil {
			t.Errorf("validateTranDays() should not error for GLACIER with 15 days: %v", err)
		}
	})

	t.Run("validateAllVersionsExpiration", func(t *testing.T) {
		// Test negative days
		rule := lifecycle.Rule{
			AllVersionsExpiration: lifecycle.AllVersionsExpiration{
				Days: -1,
			},
		}
		if err := validateAllVersionsExpiration(rule); err == nil {
			t.Error("validateAllVersionsExpiration() should error for negative days")
		}

		// Test positive days (valid)
		rule.AllVersionsExpiration.Days = 7
		if err := validateAllVersionsExpiration(rule); err != nil {
			t.Errorf("validateAllVersionsExpiration() should not error for positive days: %v", err)
		}
	})

	t.Run("validateNoncurrentExpiration", func(t *testing.T) {
		// Test negative days
		rule := lifecycle.Rule{
			NoncurrentVersionExpiration: lifecycle.NoncurrentVersionExpiration{
				NoncurrentDays: -1,
			},
		}
		if err := validateNoncurrentExpiration(rule); err == nil {
			t.Error("validateNoncurrentExpiration() should error for negative days")
		}

		// Test positive days (valid)
		rule.NoncurrentVersionExpiration.NoncurrentDays = 30
		if err := validateNoncurrentExpiration(rule); err != nil {
			t.Errorf("validateNoncurrentExpiration() should not error for positive days: %v", err)
		}
	})

	t.Run("validateNoncurrentTransition", func(t *testing.T) {
		// Test negative days
		rule := lifecycle.Rule{
			NoncurrentVersionTransition: lifecycle.NoncurrentVersionTransition{
				NoncurrentDays: -1,
			},
		}
		if err := validateNoncurrentTransition(rule); err == nil {
			t.Error("validateNoncurrentTransition() should error for negative days")
		}

		// Test positive days without storage class
		rule.NoncurrentVersionTransition.NoncurrentDays = 30
		if err := validateNoncurrentTransition(rule); err == nil {
			t.Error("validateNoncurrentTransition() should error when storage class is missing with positive days")
		}

		// Test positive days with storage class (valid)
		rule.NoncurrentVersionTransition.StorageClass = "GLACIER"
		if err := validateNoncurrentTransition(rule); err != nil {
			t.Errorf("validateNoncurrentTransition() should not error for positive days with storage class: %v", err)
		}
	})
}

func TestParseFunctions(t *testing.T) {
	t.Run("parseTransition", func(t *testing.T) {
		// Test with all parameters nil
		transition, err := parseTransition(nil, nil, nil)
		if err != nil {
			t.Errorf("parseTransition() should not error with nil parameters: %v", err)
		}
		if transition.StorageClass != "" || transition.Days != 0 {
			t.Error("parseTransition() should return empty transition with nil parameters")
		}

		// Test with invalid date
		invalidDate := "invalid-date"
		_, err = parseTransition(nil, &invalidDate, nil)
		if err == nil {
			t.Error("parseTransition() should error with invalid date")
		}

		// Test with invalid days
		invalidDays := "invalid"
		_, err = parseTransition(nil, nil, &invalidDays)
		if err == nil {
			t.Error("parseTransition() should error with invalid days")
		}

		// Test with valid parameters
		storageClass := "GLACIER"
		date := "2025-06-01"
		days := "30"
		transition, err = parseTransition(&storageClass, &date, &days)
		if err != nil {
			t.Errorf("parseTransition() should not error with valid parameters: %v", err)
		}
		if transition.StorageClass != storageClass {
			t.Errorf("parseTransition() storage class = %v, want %v", transition.StorageClass, storageClass)
		}
	})

	t.Run("parseExpiryDate", func(t *testing.T) {
		// Test zero date
		_, err := parseExpiryDate("0001-01-01")
		if err == nil {
			t.Error("parseExpiryDate() should error for zero date")
		}

		// Test invalid date format
		_, err = parseExpiryDate("invalid-date")
		if err == nil {
			t.Error("parseExpiryDate() should error for invalid date format")
		}

		// Test valid date
		date, err := parseExpiryDate("2025-06-01")
		if err != nil {
			t.Errorf("parseExpiryDate() should not error for valid date: %v", err)
		}
		if date.IsZero() {
			t.Error("parseExpiryDate() should return non-zero date")
		}
	})

	t.Run("parseAllVersionsExpiry", func(t *testing.T) {
		// Test with invalid days
		invalidDays := "invalid"
		_, err := parseAllVersionsExpiry(&invalidDays, nil)
		if err == nil {
			t.Error("parseAllVersionsExpiry() should error with invalid days")
		}

		// Test with valid days and delete marker
		validDays := "7"
		deleteMarker := true
		expiry, err := parseAllVersionsExpiry(&validDays, &deleteMarker)
		if err != nil {
			t.Errorf("parseAllVersionsExpiry() should not error with valid parameters: %v", err)
		}
		if expiry.Days != 7 {
			t.Errorf("parseAllVersionsExpiry() days = %v, want 7", expiry.Days)
		}
		if bool(expiry.DeleteMarker) != deleteMarker {
			t.Errorf("parseAllVersionsExpiry() delete marker = %v, want %v", expiry.DeleteMarker, deleteMarker)
		}
	})
}
