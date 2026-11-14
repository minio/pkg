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

// memoryEnumerationKeys are the keys of the actions that carry a query. A read
// or a write names one record in its resource and has nothing to constrain, so
// accepting them elsewhere would let a policy look effective while
// constraining nothing.
//
// Search takes them for the same reason a list does, and needs them more: it
// reads the CONTENT of every object under its prefix, so without the key the
// grant has two states -- no search, or search over the whole cortex. Its
// resource cannot carry the prefix either: one ARN would mean a single record
// under memory:GetObjectBio and every object sharing that prefix under
// memory:Search.
var memoryEnumerationKeys = []*Key{MemoryPrefix, MemoryMaxKeys}

// Memory is the memory action namespace.
var Memory = &Namespace{
	Prefix:       "memory",
	Title:        "AIStor Memory",
	Desc:         "Cortexes, agents, secrets and memory search.",
	GoNameFormat: "Memory%sAction",
	BaseKeys:     CommonKeys,
	Actions: []Action{
		{
			Name:     "CreateCortex",
			Category: CategoryCreateDelete,
			Desc:     "Create a Memory cortex (Memory Bucket).",
		},
		{
			Name:     "DeleteCortex",
			Category: CategoryCreateDelete,
			Desc:     "Delete a Memory cortex.",
		},
		{
			Name:     "GetCortex",
			Category: CategoryRead,
			Desc:     "Read a Memory cortex's metadata.",
		},
		{
			Name:     "ListCortexes",
			Category: CategoryList,
			Desc:     "List Memory cortexes.",
			Keys:     memoryEnumerationKeys,
		},
		{
			Name:     "PutSecret",
			Category: CategoryWrite,
			Desc:     "Write a secret in a cortex.",
		},
		{
			Name:     "GetSecret",
			Category: CategoryRead,
			Desc:     "Read a secret's decrypted value from a cortex.",
		},
		{
			Name:     "DeleteSecret",
			Category: CategoryWrite,
			Desc:     "Delete a secret from a cortex.",
		},
		{
			Name:     "ListSecrets",
			Category: CategoryList,
			Desc:     "List the secrets in a cortex.",
			Keys:     memoryEnumerationKeys,
		},
		{
			Name:     "PutAgent",
			Category: CategoryWrite,
			Desc:     "Write a memory beneath an agent record. It does not\ncreate or modify the record itself.",
		},
		{
			Name:     "CreateAgent",
			Category: CategoryWrite,
			Desc:     "Create an agent record. Separate from\nMemoryPutAgentAction because creating a record also mints the agent's IAM\nidentity and its derived policy, and a resource pattern cannot keep the\ntwo apart: the memory form agents/<id>/<memory> and the record form\nagents/<id> both match agents/*, so one action over that pattern would\nturn a grant to write memories into a grant to mint credentials.",
		},
		{
			Name:     "UpdateAgent",
			Category: CategoryWrite,
			Desc:     "Modify an existing agent record. Separate from\nMemoryCreateAgentAction because an update re-derives the agent's IAM policy\nwithout minting an identity, so it is grantable to a principal that may\nedit agents but not create them.",
		},
		{
			Name:     "GetAgent",
			Category: CategoryRead,
			Desc:     "Read an agent record from a cortex.",
		},
		{
			Name:     "DeleteAgent",
			Category: CategoryWrite,
			Desc:     "Delete an agent record from a cortex.",
		},
		{
			Name:     "ListAgents",
			Category: CategoryList,
			Desc:     "List the agent records in a cortex.",
			Keys:     memoryEnumerationKeys,
		},
		{
			Name:     "Search",
			Category: CategoryRead,
			Desc:     "Search (corpus-grep) the objects in a cortex.",
			Keys:     memoryEnumerationKeys,
		},
		{
			Name:     "GetObjectBio",
			Category: CategoryRead,
			Desc:     "Read an object's biography in a cortex: who\nauthored each version, when, and from where.",
		},
		{
			Name:   "*",
			GoName: "AllMemoryActions",
			Desc:   "All AIStor Memory API actions.",
			Keys:   memoryEnumerationKeys,
		},
	},
}
