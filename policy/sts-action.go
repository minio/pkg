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

package policy

import (
	"github.com/minio/pkg/v3/policy/condition"
)

// STSAction - STS policy action.
type STSAction string

const (
	// AssumeRoleAction - use to deny or allow sts:AssumeRole action under specific conditions.
	AssumeRoleAction = "sts:AssumeRole"

	// AssumeRoleLDAPIdentityAction - use to deny or allow sts:AssumeRoleLDAPIdentity action under specific conditions.
	AssumeRoleLDAPIdentityAction = "sts:AssumeRoleLDAPIdentity"

	// AssumeRoleWithCustomTokenAction - use to deny or allow sts:AssumeRoleWithCustomToken action under specific conditions.
	AssumeRoleWithCustomTokenAction = "sts:AssumeRoleWithCustomToken"

	// AssumeRoleWithWebIdentityAction - use to deny or allow sts:AssumeRoleWithWebIdentity action under specific conditions.
	AssumeRoleWithWebIdentityAction = "sts:AssumeRoleWithWebIdentity"

	// AssumeRoleWithClientGrantsAction - use to deny or allow sts:AssumeRoleWithClientGrants action under specific conditions.
	AssumeRoleWithClientGrantsAction = "sts:AssumeRoleWithClientGrants"

	// AssumeRoleWithClientCertificateAction - use to deny or allow sts:AssumeRoleWithClientCertificate action under specific conditions.
	AssumeRoleWithClientCertificateAction = "sts:AssumeRoleWithClientCertificate"

	// AllSTSActions - select all STS actions
	AllSTSActions = "sts:*"
)

// List of all supported sts actions.
var supportedSTSActions = map[STSAction]struct{}{
	AllSTSActions:                         {},
	AssumeRoleAction:                      {},
	AssumeRoleLDAPIdentityAction:          {},
	AssumeRoleWithWebIdentityAction:       {},
	AssumeRoleWithCustomTokenAction:       {},
	AssumeRoleWithClientGrantsAction:      {},
	AssumeRoleWithClientCertificateAction: {},
}

// IsValid - checks if action is valid or not.
func (action STSAction) IsValid() bool {
	_, ok := supportedSTSActions[action]
	return ok
}

func createSTSActionConditionKeyMap() map[Action]condition.KeySet {
	allSupportedSTSKeys := []condition.Key{}
	for _, keyName := range condition.AllSupportedSTSKeys {
		allSupportedSTSKeys = append(allSupportedSTSKeys, keyName.ToKey())
	}

	return ActionConditionKeyMap{
		AllSTSActions:                         condition.NewKeySet(allSupportedSTSKeys...),
		AssumeRoleAction:                      condition.NewKeySet(allSupportedSTSKeys...),
		AssumeRoleLDAPIdentityAction:          condition.NewKeySet(allSupportedSTSKeys...),
		AssumeRoleWithWebIdentityAction:       condition.NewKeySet(allSupportedSTSKeys...),
		AssumeRoleWithCustomTokenAction:       condition.NewKeySet(allSupportedSTSKeys...),
		AssumeRoleWithClientGrantsAction:      condition.NewKeySet(allSupportedSTSKeys...),
		AssumeRoleWithClientCertificateAction: condition.NewKeySet(allSupportedSTSKeys...),
	}
}

// stsActionConditionKeyMap - holds mapping of supported condition key for an action.
var stsActionConditionKeyMap = createSTSActionConditionKeyMap()
