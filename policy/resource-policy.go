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

package policy

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/minio/pkg/v3/policy/condition"
)

// ResourcePolicyTarget names the resource a resource policy is attached to: a
// warehouse, or one table in it when Table is set.
type ResourcePolicyTarget struct {
	Warehouse string
	// Table is the table's UUID.
	Table string
}

func (t ResourcePolicyTarget) isTable() bool { return t.Table != "" }

func (t ResourcePolicyTarget) warehousePattern() string { return "bucket/" + t.Warehouse }

func (t ResourcePolicyTarget) tablePattern() string {
	return t.warehousePattern() + "/table/" + t.Table
}

// ResourcePolicy is an S3 Tables policy attached to a warehouse or a table.
// Every statement applies to any signed caller; conditions narrow it.
type ResourcePolicy struct {
	ID         ID                  `json:"ID,omitempty"`
	Version    string              `json:"Version"`
	Statements []ResourceStatement `json:"Statement"`
}

// ResourceStatement is a policy statement with a Principal.
type ResourceStatement struct {
	SID          ID                  `json:"Sid,omitempty"`
	Effect       Effect              `json:"Effect"`
	Principal    Principal           `json:"Principal"`
	NotPrincipal json.RawMessage     `json:"NotPrincipal,omitempty"`
	Actions      ActionSet           `json:"Action,omitempty"`
	NotActions   ActionSet           `json:"NotAction,omitempty"`
	Resources    ResourceSet         `json:"Resource,omitempty"`
	NotResources ResourceSet         `json:"NotResource,omitempty"`
	Conditions   condition.Functions `json:"Condition,omitempty"`

	// eval is the statement as an identity policy statement, filled in on
	// parse.
	eval Statement
}

// statement returns s as an identity policy statement, classified so its
// evaluation does not reclassify it per request.
func (s ResourceStatement) statement() Statement {
	st := Statement{
		SID:          s.SID,
		Effect:       s.Effect,
		Actions:      s.Actions,
		NotActions:   s.NotActions,
		Resources:    s.Resources,
		NotResources: s.NotResources,
		Conditions:   s.Conditions,
	}
	st.class = st.computeClass()
	return st
}

// canAllow reports whether the statement is an Allow this release can grant
// as written. One a write would refuse, which only a policy stored under other
// write rules can hold, grants nothing.
func (s *ResourceStatement) canAllow() bool {
	return s.Effect == Allow && s.appliesToEveryone() &&
		len(s.Actions) > 0 && len(s.NotActions) == 0 &&
		len(s.Resources) > 0 && len(s.NotResources) == 0
}

// appliesToEveryone reports whether the statement's Principal is the
// wildcard, the only form this release gives a meaning to.
func (s ResourceStatement) appliesToEveryone() bool {
	return len(s.NotPrincipal) == 0 && len(s.Principal.AWS) == 1 && s.Principal.AWS.Contains("*")
}

// ParseResourcePolicy parses a stored resource policy. Only the JSON shape is
// checked, so a policy saved under other write rules still loads.
func ParseResourcePolicy(data []byte) (*ResourcePolicy, error) {
	var p ResourcePolicy
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&p); err != nil {
		return nil, Errorf("%w", err)
	}
	if dec.More() {
		return nil, Errorf("unexpected data after the policy document")
	}
	p.index()
	return &p, nil
}

// ParseResourcePolicyForWrite parses a resource policy about to be attached
// to target, refusing anything this release cannot enforce as written.
func ParseResourcePolicyForWrite(data []byte, target ResourcePolicyTarget) (*ResourcePolicy, error) {
	if target.Warehouse == "" {
		return nil, Errorf("resource policy target names no warehouse")
	}
	if err := checkResourcePolicyFields(data); err != nil {
		return nil, err
	}
	p, err := ParseResourcePolicy(data)
	if err != nil {
		return nil, err
	}
	if err := p.validate(target); err != nil {
		return nil, err
	}
	return p, nil
}

// checkResourcePolicyFields refuses keys the document must not carry, so a
// misspelled or unsupported field is not silently dropped.
func checkResourcePolicyFields(data []byte) error {
	var doc struct {
		Statement []map[string]json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Errorf("%w", err)
	}
	allowed := map[string]bool{
		"Sid": true, "Effect": true, "Principal": true, "Action": true,
		"Resource": true, "Condition": true,
	}
	for _, st := range doc.Statement {
		for key := range st {
			if !allowed[key] {
				return Errorf("'%v' is not supported in a resource policy", key)
			}
		}
	}
	return nil
}

func (p *ResourcePolicy) validate(target ResourcePolicyTarget) error {
	if p.Version != DefaultVersion && p.Version != "" {
		return Errorf("invalid version '%v'", p.Version)
	}
	if len(p.Statements) == 0 {
		return Errorf("policy has no statements")
	}
	for i := range p.Statements {
		if err := p.Statements[i].validate(target); err != nil {
			return err
		}
	}
	return nil
}

func (s ResourceStatement) validate(target ResourcePolicyTarget) error {
	if len(s.NotPrincipal) > 0 {
		return Errorf("NotPrincipal is not supported in a resource policy")
	}
	if len(s.NotActions) > 0 {
		return Errorf("NotAction is not supported in a resource policy")
	}
	if len(s.NotResources) > 0 {
		return Errorf("NotResource is not supported in a resource policy")
	}
	if !s.Principal.IsValid() {
		return Errorf("Principal must not be empty")
	}
	if !s.appliesToEveryone() {
		return Errorf("unsupported Principal %v - only \"*\" is supported; narrow a statement with conditions such as aws:username", s.Principal.AWS.ToSlice())
	}
	if len(s.Actions) == 0 {
		return Errorf("Action must not be empty")
	}
	for action := range s.Actions {
		if err := checkResourcePolicyAction(TableAction(action), target); err != nil {
			return err
		}
	}
	if len(s.Resources) == 0 {
		return Errorf("Resource must not be empty")
	}
	for resource := range s.Resources {
		if err := checkResourcePolicyResource(resource, target); err != nil {
			return err
		}
	}
	return s.statement().isValidStrict()
}

func checkResourcePolicyAction(action TableAction, target ResourcePolicyTarget) error {
	if action == AllS3TablesActions {
		return nil
	}
	if !action.IsValid() {
		return Errorf("unsupported action '%v' - a resource policy grants s3tables actions only", action)
	}
	switch action.scope() {
	case tableScopeTable:
		return nil
	case tableScopeWarehouse:
		if target.isTable() {
			return Errorf("action '%v' applies to a warehouse and cannot be granted by a table policy", action)
		}
		return nil
	default:
		return Errorf("action '%v' names no warehouse and cannot be granted by a resource policy", action)
	}
}

func checkResourcePolicyResource(resource Resource, target ResourcePolicyTarget) error {
	if resource.Type != ResourceARNS3Tables || resource.IsBareARN() {
		return Errorf("resource '%v' is not an S3 Tables ARN", resource)
	}
	if target.isTable() {
		if resource.Pattern != target.tablePattern() {
			return Errorf("resource '%v' must be this table's ARN '%v%v'", resource, ResourceARNS3TablesPrefix, target.tablePattern())
		}
		return nil
	}
	wh := target.warehousePattern()
	if resource.Pattern != wh && !strings.HasPrefix(resource.Pattern, wh+"/") {
		return Errorf("resource '%v' is outside warehouse '%v'", resource, target.Warehouse)
	}
	return nil
}

func (p *ResourcePolicy) index() {
	for i := range p.Statements {
		p.Statements[i].eval = p.Statements[i].statement()
	}
}

// decide is Decide, or HasCapability when capability is set.
func (p *ResourcePolicy) decide(args *Args, capability bool) Decision {
	if TableAction(args.Action).scope() == tableScopeGlobal {
		return NoDecision
	}
	resource := buildRequestResource(args)
	allowed := false
	for i := range p.Statements {
		rs := &p.Statements[i]
		switch rs.Effect {
		case Deny:
			if capability && len(rs.Conditions) > 0 {
				continue
			}
			if !rs.eval.isAllowedFor(args, resource) {
				return DenyDecision
			}
		case Allow:
			if !allowed && rs.canAllow() && rs.eval.isAllowedFor(args, resource) {
				allowed = true
			}
		}
	}
	if allowed {
		return AllowDecision
	}
	return NoDecision
}

// Decide returns the policy's own decision for args: DenyDecision when a Deny
// statement applies, AllowDecision when an Allow does, and NoDecision
// otherwise. args.IsOwner and args.DenyOnly are ignored; the caller combines
// this decision with the caller's other policies. A global action, which names
// no existing warehouse, always gets NoDecision.
//
// A statement whose Principal is not the wildcard, which only a policy stored
// under other write rules can hold, fails closed: its Deny applies to every
// caller and its Allow grants nothing. So does an Allow without Action or
// Resource, or with NotAction or NotResource.
func (p *ResourcePolicy) Decide(args *Args) Decision {
	return p.decide(args, false)
}

// HasCapability answers whether the policy could ever allow args: DenyDecision
// when an unconditional Deny applies, AllowDecision when an Allow applies, and
// NoDecision otherwise. Conditional Denies are skipped, since they constrain
// how a request is formed rather than whether the action is permitted.
func (p *ResourcePolicy) HasCapability(args *Args) Decision {
	return p.decide(args, true)
}

// AllowedActions returns every action an Allow statement names. A request for
// an action that matches none of them is never allowed by this policy.
func (p *ResourcePolicy) AllowedActions() ActionSet {
	actions := NewActionSet()
	for i := range p.Statements {
		rs := &p.Statements[i]
		if !rs.canAllow() {
			continue
		}
		for action := range rs.Actions {
			actions.Add(action)
		}
	}
	return actions
}
