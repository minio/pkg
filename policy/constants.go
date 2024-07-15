// Copyright (c) 2015-2021 MinIO, Inc.
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

package policy

import (
	"github.com/minio/pkg/v3/policy/condition"
)

// Policy claim constants
const (
	PolicyName        = "policy"
	SessionPolicyName = "sessionPolicy"
)

// DefaultPolicies - list of canned policies available in MinIO.
var DefaultPolicies = []struct {
	Name       string
	Definition Policy
}{
	// ReadWrite - provides full access to all buckets and all objects.
	{
		Name: "readwrite",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(AllActions),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// ReadOnly - read only.
	{
		Name: "readonly",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(GetBucketLocationAction, GetObjectAction),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// WriteOnly - provides write access.
	{
		Name: "writeonly",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(PutObjectAction),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// AdminDiagnostics - provides admin diagnostics access.
	{
		Name: "diagnostics",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(ProfilingAdminAction,
						TraceAdminAction, ConsoleLogAdminAction,
						ServerInfoAdminAction, TopLocksAdminAction,
						HealthInfoAdminAction, BandwidthMonitorAction,
						PrometheusAdminAction,
					),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// Admin - provides admin all-access canned policy
	{
		Name: "consoleAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(AllAdminActions),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(AllKMSActions),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(AllActions),
					Resources:  NewResourceSet(NewResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},
}
