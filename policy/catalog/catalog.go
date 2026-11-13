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

// Package catalog describes every action a policy can name, for tools that
// build policies, such as a visual policy editor. The data is generated from
// the same definition as the policy package's actions, so the two never
// disagree.
package catalog

import (
	"encoding/json"
	"sync"
)

// Category classifies what an action does, so a tool can grant a level of
// access, such as writing a bucket's objects, without its configuration.
type Category string

// Categories.
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
	ID    Category `json:"id"`
	Title string   `json:"title"`
	Desc  string   `json:"description,omitempty"`
}

// Catalog lists the action namespaces a policy can use.
type Catalog struct {
	// Version changes whenever the content does, so a client can cache it.
	Version string `json:"version"`
	// Categories lists every category in display order.
	Categories []CategoryInfo `json:"categories"`
	Namespaces []Namespace    `json:"namespaces"`
}

// Namespace is the set of actions that share an action prefix. A policy names
// every action of a namespace as "<prefix>:*".
type Namespace struct {
	Prefix string `json:"prefix"`
	Title  string `json:"title"`
	Desc   string `json:"description,omitempty"`
	// ConditionKeys are the condition keys every action of the namespace takes.
	ConditionKeys []string `json:"conditionKeys,omitempty"`
	Actions       []Action `json:"actions"`
}

// Action is one action a policy can name.
type Action struct {
	// Name is the full action name, such as "s3:GetObject".
	Name     string   `json:"name"`
	Desc     string   `json:"description,omitempty"`
	Category Category `json:"category"`
	// ConditionKeys are the condition keys the action takes beyond its
	// namespace's. A key ending in "/" takes the name of a tag after it.
	ConditionKeys []string `json:"conditionKeys,omitempty"`
	// Aliases are other full names of the same action; naming any of them in
	// a policy grants or denies all of them.
	Aliases []string `json:"aliases,omitempty"`
	// Implies lists full action names a statement naming this action also
	// grants or denies.
	Implies []string `json:"implies,omitempty"`
}

// Get returns the catalog. It is shared: callers must not modify it.
func Get() *Catalog {
	return &catalog
}

var catalogJSON = sync.OnceValues(func() ([]byte, error) {
	return json.Marshal(&catalog)
})

// JSON returns the catalog encoded as JSON. The bytes are shared: callers must
// not modify them.
func JSON() ([]byte, error) {
	return catalogJSON()
}
