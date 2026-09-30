// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import (
	"strings"
	"testing"
)

func TestFilesActionIsValid(t *testing.T) {
	testCases := []struct {
		action         FilesAction
		expectedResult bool
	}{
		{FilesCreateExportAction, true},
		{FilesDeleteExportAction, true},
		{FilesUpdateExportAction, true},
		{FilesSetExportAccessAction, true},
		{FilesGetExportStatusAction, true},
		{FilesGetExportStatsAction, true},
		{AllFilesActions, true},
		{FilesAction("s3files:FooBar"), false},
		{FilesAction("s3files:Get*"), false},
		{FilesAction("s3:GetObject"), false},
		{FilesAction("admin:ServerInfo"), false},
	}

	for i, testCase := range testCases {
		if result := testCase.action.IsValid(); result != testCase.expectedResult {
			t.Fatalf("case %v: action %v: expected: %v, got: %v", i+1, testCase.action, testCase.expectedResult, result)
		}
	}
}

func TestFilesActionConditionKeys(t *testing.T) {
	for action := range SupportedFilesActions {
		if _, ok := FilesActionConditionKeyMap[Action(action)]; !ok {
			t.Fatalf("action %v: no condition key set registered", action)
		}
	}
}

func TestFilesStatementValidate(t *testing.T) {
	testCases := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name: "one action",
			doc:  `{"Effect":"Allow","Action":["s3files:GetExportStatus"]}`,
		},
		{
			name: "every action",
			doc: `{"Effect":"Allow","Action":["s3files:CreateExport","s3files:DeleteExport",
				"s3files:UpdateExport","s3files:SetExportAccess","s3files:GetExportStatus",
				"s3files:GetExportStats"]}`,
		},
		{
			name: "wildcard",
			doc:  `{"Effect":"Allow","Action":["s3files:*"]}`,
		},
		{
			name: "deny",
			doc:  `{"Effect":"Deny","Action":["s3files:DeleteExport"]}`,
		},
		{
			name: "common condition key",
			doc: `{"Effect":"Allow","Action":["s3files:GetExportStatus"],
				"Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}`,
		},
		{
			// A name outside the namespace is not a Files action, so it falls
			// through to S3 validation, which refuses it.
			name:    "unknown action",
			doc:     `{"Effect":"Allow","Action":["s3files:FooBar"]}`,
			wantErr: "Resource must not be empty",
		},
		{
			name:    "unknown action with a resource",
			doc:     `{"Effect":"Allow","Action":["s3files:FooBar"],"Resource":["arn:aws:s3:::*"]}`,
			wantErr: "unsupported action",
		},
		{
			name:    "mixed with s3",
			doc:     `{"Effect":"Allow","Action":["s3files:GetExportStatus","s3:GetObject"],"Resource":["arn:aws:s3:::*"]}`,
			wantErr: "mixing action types",
		},
		{
			name:    "mixed with admin",
			doc:     `{"Effect":"Allow","Action":["s3files:GetExportStatus","admin:ServerInfo"]}`,
			wantErr: "mixing action types",
		},
		{
			name:    "resource",
			doc:     `{"Effect":"Allow","Action":["s3files:DeleteExport"],"Resource":["arn:aws:s3:::carol"]}`,
			wantErr: "do not take a Resource",
		},
		{
			name:    "wildcard resource",
			doc:     `{"Effect":"Allow","Action":["s3files:*"],"Resource":["*"]}`,
			wantErr: "do not take a Resource",
		},
		{
			name:    "not resource",
			doc:     `{"Effect":"Deny","Action":["s3files:DeleteExport"],"NotResource":["arn:aws:s3:::carol"]}`,
			wantErr: "do not take a Resource",
		},
		{
			name: "unsupported condition key",
			doc: `{"Effect":"Allow","Action":["s3files:GetExportStatus"],
				"Condition":{"StringEquals":{"s3:prefix":["x"]}}}`,
			wantErr: "unsupported condition keys",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"Version":"2012-10-17","Statement":[` + tc.doc + `]}`
			for _, parse := range []struct {
				name string
				fn   func(string) error
			}{
				{"ParseConfig", func(d string) error { _, err := ParseConfig(strings.NewReader(d)); return err }},
				{"ParseConfigStrict", func(d string) error { _, err := ParseConfigStrict(strings.NewReader(d)); return err }},
			} {
				err := parse.fn(doc)
				switch {
				case tc.wantErr == "" && err != nil:
					t.Errorf("%s: unexpected error: %v", parse.name, err)
				case tc.wantErr != "" && err == nil:
					t.Errorf("%s: expected an error containing %q, got none", parse.name, tc.wantErr)
				case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
					t.Errorf("%s: expected an error containing %q, got %v", parse.name, tc.wantErr, err)
				}
			}
		})
	}
}

// filesArgs is how a server asks about a Files management request: the export
// is named by the request, so the args carry no bucket or object.
func filesArgs(action FilesAction) Args {
	return Args{AccountName: "files-operator", Action: Action(action)}
}

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestFilesPolicyIsAllowed(t *testing.T) {
	allFiles := []FilesAction{
		FilesCreateExportAction,
		FilesDeleteExportAction,
		FilesUpdateExportAction,
		FilesSetExportAccessAction,
		FilesGetExportStatusAction,
		FilesGetExportStatsAction,
	}

	t.Run("read only grants list and inspect, nothing else", func(t *testing.T) {
		p := mustParse(t, `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3files:GetExportStatus"]}]}`)
		for _, action := range allFiles {
			want := action == FilesGetExportStatusAction
			if got := p.IsAllowed(filesArgs(action)); got != want {
				t.Errorf("%v: allowed=%v, want %v", action, got, want)
			}
		}
	})

	t.Run("wildcard grants every files action and only those", func(t *testing.T) {
		p := mustParse(t, `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3files:*"]}]}`)
		for _, action := range allFiles {
			if !p.IsAllowed(filesArgs(action)) {
				t.Errorf("%v: denied by s3files:*", action)
			}
		}
		for _, other := range []Action{Action(ServerInfoAdminAction), GetObjectAction, Action(MemoryListCortexesAction)} {
			if p.IsAllowed(Args{Action: other, BucketName: "b", ObjectName: "o"}) {
				t.Errorf("%v: allowed by s3files:*", other)
			}
		}
	})

	t.Run("s3 and admin wildcards grant no files action", func(t *testing.T) {
		p := mustParse(t, `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
			{"Effect":"Allow","Action":["admin:*"]}]}`)
		for _, action := range allFiles {
			if p.IsAllowed(filesArgs(action)) {
				t.Errorf("%v: allowed by s3:* + admin:*", action)
			}
		}
	})

	t.Run("deny wins", func(t *testing.T) {
		p := mustParse(t, `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3files:*"]},
			{"Effect":"Deny","Action":["s3files:DeleteExport"]}]}`)
		if p.IsAllowed(filesArgs(FilesDeleteExportAction)) {
			t.Error("s3files:DeleteExport allowed despite an explicit Deny")
		}
		if !p.IsAllowed(filesArgs(FilesCreateExportAction)) {
			t.Error("s3files:CreateExport denied; the Deny names only DeleteExport")
		}
	})

	t.Run("condition applies", func(t *testing.T) {
		p := mustParse(t, `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3files:GetExportStatus"],
			 "Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}]}`)
		inside := filesArgs(FilesGetExportStatusAction)
		inside.ConditionValues = map[string][]string{"SourceIp": {"10.1.2.3"}}
		if !p.IsAllowed(inside) {
			t.Error("denied from inside the allowed network")
		}
		outside := filesArgs(FilesGetExportStatusAction)
		outside.ConditionValues = map[string][]string{"SourceIp": {"192.168.1.1"}}
		if p.IsAllowed(outside) {
			t.Error("allowed from outside the allowed network")
		}
	})
}

func TestFilesActionNotGrantedByDefaultPolicies(t *testing.T) {
	// No canned policy grants the Files namespace yet, consoleAdmin included:
	// it is granted on its own, as the issue that introduced it asks.
	for _, dp := range DefaultPolicies {
		for action := range SupportedFilesActions {
			if action == AllFilesActions {
				continue
			}
			if dp.Definition.IsAllowed(filesArgs(action)) {
				t.Errorf("default policy %q allows %v", dp.Name, action)
			}
		}
	}
}
