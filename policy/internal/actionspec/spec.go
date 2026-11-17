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

// Category classifies what an action does, so a tool can grant a level of
// access, such as writing a bucket's objects, without its configuration.
type Category string

const (
	// CategoryList enumerates resources without reading them.
	CategoryList Category = "List"
	// CategoryRead reads data, or looks up a resource by name.
	CategoryRead Category = "Read"
	// CategoryWrite creates, changes or deletes data, including object and
	// table tags.
	CategoryWrite Category = "Write"
	// CategoryManage creates, renames or deletes what lives inside a
	// container, such as namespaces, tables, views and indexes.
	CategoryManage Category = "Manage"
	// CategoryCreateDelete creates or deletes a container itself, such as a
	// bucket, warehouse or key.
	CategoryCreateDelete Category = "CreateDelete"
	// CategoryViewSettings reads a container's configuration or policy.
	CategoryViewSettings Category = "ViewSettings"
	// CategoryConfigure changes a container's configuration.
	CategoryConfigure Category = "Configure"
	// CategoryProtection locks data against deletion, or overrides a lock.
	CategoryProtection Category = "Protection"
	// CategoryPermissions grants or revokes access.
	CategoryPermissions Category = "Permissions"
	// CategoryIdentity manages users, groups and service accounts.
	CategoryIdentity Category = "Identity"
	// CategoryCredentials obtains temporary credentials.
	CategoryCredentials Category = "Credentials"
	// CategoryMonitor reads cluster health, usage and status.
	CategoryMonitor Category = "Monitor"
	// CategoryDiagnostics runs tools that can expose request details or data.
	CategoryDiagnostics Category = "Diagnostics"
	// CategoryOperate runs or changes the cluster.
	CategoryOperate Category = "Operate"
	// CategoryReplication is performed by the replication service, not people.
	CategoryReplication Category = "Replication"
)

// CategoryInfo names and describes a category for display.
type CategoryInfo struct {
	Category Category
	Title    string
	Desc     string
}

// Categories lists every category in display order.
var Categories = []CategoryInfo{
	{CategoryList, "List", "Find resources by listing them, without reading them."},
	{CategoryRead, "Read", "Read data, or look up a resource by name."},
	{CategoryWrite, "Write", "Create, change or delete data, including object and table tags."},
	{CategoryManage, "Manage", "Create, rename or delete what lives inside a container, such as namespaces, tables, views and indexes."},
	{CategoryCreateDelete, "Create & Delete", "Create or delete a container itself, such as a bucket or warehouse."},
	{CategoryViewSettings, "View Settings", "Read a container's configuration or policy."},
	{CategoryConfigure, "Configure", "Change a container's configuration, such as versioning, lifecycle or bucket tags."},
	{CategoryProtection, "Protection", "Lock data against deletion, or override a lock."},
	{CategoryPermissions, "Permissions", "Grant or revoke access."},
	{CategoryIdentity, "Identity", "Manage users, groups and service accounts."},
	{CategoryCredentials, "Credentials", "Obtain temporary credentials."},
	{CategoryMonitor, "Monitor", "Read cluster health, usage and status."},
	{CategoryDiagnostics, "Diagnostics", "Run tools that can expose request details or data."},
	{CategoryOperate, "Operate", "Run or change the cluster."},
	{CategoryReplication, "Replication", "Actions the replication service performs, not people."},
}

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
	// Title is the namespace's display name.
	Title string
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
	// Category classifies the action. Every action but "*" sets it.
	Category Category
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
