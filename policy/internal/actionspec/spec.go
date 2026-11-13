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

// Package actionspec is the single definition of every policy action and
// condition key. The genactions command renders it into the constants, sets and
// maps of the policy and condition packages; nothing reads it at run time.
package actionspec

// Resource is the kind of resource a policy statement names for an action.
type Resource int

const (
	// ResourceUnspecified takes the namespace's resource, or records nothing
	// when the namespace sets none.
	ResourceUnspecified Resource = iota
	// ResourceNone means the action acts on no resource a statement can name.
	ResourceNone
	// ResourceBucket means the action acts on a bucket.
	ResourceBucket
	// ResourceObject means the action acts on an object.
	ResourceObject
	// ResourceBucketOrObject means the action may act on either.
	ResourceBucketOrObject
)

// Key is a condition key.
type Key struct {
	// Name is the key as a policy writes it, such as "s3:prefix".
	Name string
	// GoName is the name of the condition package constant.
	GoName string
	// Desc describes the key.
	Desc string
	// Variable marks a key that takes a /<variable> suffix naming the tag it
	// tests, as in s3:ExistingObjectTag/<tag>.
	Variable bool
	// Untrimmed marks a key that reads the request value named by its whole
	// name, because trimming the prefix would collide with another key.
	Untrimmed bool
	// Unlisted keeps the key out of AllSupportedKeys.
	Unlisted bool
}

// Namespace is the set of actions that share an action prefix.
type Namespace struct {
	// Prefix is the part of every action name before the colon.
	Prefix string
	// Desc describes the namespace.
	Desc string
	// GoNameFormat derives an action's Go constant name from its Name, as a
	// fmt format with one %s verb.
	GoNameFormat string
	// BaseKeys are the condition keys every action of the namespace takes.
	BaseKeys []*Key
	// Resource is the resource of an action that leaves its own unspecified.
	Resource Resource
	// Actions lists the namespace's actions in declaration order.
	Actions []Action
}

// Action is one policy action.
type Action struct {
	// Name is the action without its namespace prefix; "*" names every action
	// of the namespace.
	Name string
	// GoName overrides the constant name GoNameFormat derives.
	GoName string
	// Desc describes the action.
	Desc string
	// Aliases are other names of the same action in the same namespace. A
	// statement naming any of them grants or denies all of them.
	Aliases []string
	// Keys are the condition keys the action takes beyond BaseKeys.
	Keys []*Key
	// Implies lists full action names that a statement naming this action
	// also matches, in any namespace.
	Implies []string
	// Resource is the resource the action acts on.
	Resource Resource
	// Unsupported declares the constant but keeps the action out of the
	// supported set, so no policy can name it.
	Unsupported bool
}

// KeyPrefix is the service prefix of a group of condition keys.
type KeyPrefix struct {
	// Name is the prefix before the colon, such as "aws".
	Name string
	// Trim strips the prefix from a key's request value name, so s3:prefix
	// reads the request value "prefix".
	Trim bool
}
