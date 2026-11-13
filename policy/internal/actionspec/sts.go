// Copyright (c) 2015-2026 MinIO, Inc.
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

package actionspec

// STS is the sts action namespace.
var STS = &Namespace{
	Prefix:       "sts",
	GoNameFormat: "%sAction",
	BaseKeys:     AllSupportedSTSKeys,
	Resource:     ResourceNone,
	Actions: []Action{
		{
			Name: "AssumeRole",
			Desc: "Use to deny or allow sts:AssumeRole action under specific conditions.",
		},
		{
			Name: "AssumeRoleLDAPIdentity",
			Desc: "Use to deny or allow sts:AssumeRoleLDAPIdentity action under specific conditions.",
		},
		{
			Name: "AssumeRoleWithCustomToken",
			Desc: "Use to deny or allow sts:AssumeRoleWithCustomToken action under specific conditions.",
		},
		{
			Name: "AssumeRoleWithWebIdentity",
			Desc: "Use to deny or allow sts:AssumeRoleWithWebIdentity action under specific conditions.",
		},
		{
			Name: "AssumeRoleWithClientGrants",
			Desc: "Use to deny or allow sts:AssumeRoleWithClientGrants action under specific conditions.",
		},
		{
			Name: "AssumeRoleWithClientCertificate",
			Desc: "Use to deny or allow sts:AssumeRoleWithClientCertificate action under specific conditions.",
		},
		{
			Name:   "*",
			GoName: "AllSTSActions",
			Desc:   "Select all STS actions",
		},
	},
}
