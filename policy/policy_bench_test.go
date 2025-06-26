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

package policy

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

func setupPolicy(statements []Statement) Policy {
	return Policy{
		Version:    "2012-10-17",
		Statements: statements,
	}
}

func setupStatement(actions, resources []string, effect string, conditions condition.Functions) Statement {
	return Statement{
		Actions:    NewActionStrings(actions...),
		Resources:  NewResourceStrings(resources...),
		Effect:     Effect(effect),
		Conditions: conditions,
	}
}

func BenchmarkIsAllowed(b *testing.B) {
	// Common PolicyArgs for all benchmarks
	args := Args{
		Action:          "s3:GetObject",
		BucketName:      "test-bucket",
		ObjectName:      "test/object.txt",
		ConditionValues: map[string][]string{"aws:Referer": {"http://example.com"}},
	}

	// Benchmark scenarios
	scenarios := []struct {
		name   string
		policy Policy
		args   Args
	}{
		{
			name: "SingleStatementAllow",
			policy: setupPolicy([]Statement{
				setupStatement(
					[]string{"s3:GetObject"},
					[]string{"arn:aws:s3:::test-bucket/*"},
					"Allow",
					nil,
				),
			}),
			args: args,
		},
		{
			name: "MultipleStatements",
			policy: setupPolicy(func() []Statement {
				stmts := make([]Statement, 100)
				for i := 0; i < 100; i++ {
					stmts[i] = setupStatement(
						[]string{fmt.Sprintf("s3:Action%d", i)},
						[]string{fmt.Sprintf("arn:aws:s3:::bucket%d/*", i)},
						"Allow",
						nil,
					)
				}
				// Add one matching statement at the end
				stmts = append(stmts, setupStatement(
					[]string{"s3:GetObject"},
					[]string{"arn:aws:s3:::test-bucket/*"},
					"Allow",
					nil,
				))
				return stmts
			}()),
			args: args,
		},
		{
			name: "DenyRule",
			policy: setupPolicy([]Statement{
				setupStatement(
					[]string{"s3:GetObject"},
					[]string{"arn:aws:s3:::test-bucket/*"},
					"Deny",
					nil,
				),
				setupStatement(
					[]string{"s3:GetObject"},
					[]string{"arn:aws:s3:::test-bucket/*"},
					"Allow",
					nil,
				),
			}),
			args: args,
		},
		{
			name: "WildcardMatching",
			policy: setupPolicy([]Statement{
				setupStatement(
					[]string{"s3:*"},
					[]string{"arn:aws:s3:::test-bucket/*"},
					"Allow",
					nil,
				),
			}),
			args: args,
		},
	}

	for _, scenario := range scenarios {
		scenario.policy.updateActionIndex()
		b.Run(scenario.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				scenario.policy.IsAllowed(scenario.args)
			}
		})
	}
}

// setupStatements creates a slice of Statements for benchmarking.
func setupStatements(count int, dupRatio float64) []Statement {
	statements := make([]Statement, count)
	dupCount := int(float64(count) * dupRatio)
	uniqueCount := count - dupCount

	// Create unique statements
	for i := range uniqueCount {
		actions := []string{fmt.Sprintf("s3:Action%d", i)}
		resources := []string{fmt.Sprintf("arn:aws:s3:::bucket%d/*", i)}
		statements[i] = setupStatement(
			actions,
			resources,
			"Allow",
			nil,
		)
	}

	// Add duplicates by copying the first statement
	for i := uniqueCount; i < count; i++ {
		statements[i] = statements[0]
	}

	return statements
}

func BenchmarkMergePolicies(b *testing.B) {
	scenarios := []struct {
		name     string
		count    int
		dupRatio float64
	}{
		{name: "10Policies_1Stmt_NoDups", count: 10, dupRatio: 0.0},
		{name: "10Policies_1Stmt_HalfDups", count: 10, dupRatio: 0.5},
		{name: "100Policies_1Stmt_NoDups", count: 100, dupRatio: 0.0},
		{name: "100Policies_1Stmt_HalfDups", count: 100, dupRatio: 0.5},
		{name: "1000Policies_1Stmt_NoDups", count: 1000, dupRatio: 0.0},
		{name: "1000Policies_1Stmt_HalfDups", count: 1000, dupRatio: 0.5},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			// Prepare input policies
			policies := make([]Policy, scenario.count)
			uniqueCount := int(float64(scenario.count) * (1 - scenario.dupRatio))
			for i := 0; i < uniqueCount; i++ {
				policies[i] = setupPolicy([]Statement{
					setupStatement(
						[]string{fmt.Sprintf("s3:Action%d", i)},
						[]string{fmt.Sprintf("arn:aws:s3:::bucket%d/*", i)},
						"Allow",
						nil,
					),
				})
				policies[i].Version = "2012-10-17"
			}
			for i := uniqueCount; i < scenario.count; i++ {
				policies[i] = setupPolicy([]Statement{
					setupStatement(
						[]string{"s3:Action0"},
						[]string{"arn:aws:s3:::bucket0/*"},
						"Allow",
						nil,
					),
				})
				policies[i].Version = "2012-10-17"
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = MergePolicies(policies...)
			}
		})
	}
}

func BenchmarkDropDuplicateStatements(b *testing.B) {
	scenarios := []struct {
		name     string
		count    int
		dupRatio float64
	}{
		{name: "10Statements_NoDups", count: 10, dupRatio: 0.0},
		{name: "10Statements_HalfDups", count: 10, dupRatio: 0.5},
		{name: "100Statements_NoDups", count: 100, dupRatio: 0.0},
		{name: "100Statements_HalfDups", count: 100, dupRatio: 0.5},
		{name: "1000Statements_NoDups", count: 1000, dupRatio: 0.0},
		{name: "1000Statements_HalfDups", count: 1000, dupRatio: 0.5},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name+"_Original", func(b *testing.B) {
			statements := setupStatements(scenario.count, scenario.dupRatio)
			policy := &Policy{Version: "2012-10-17", Statements: statements}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p := *policy
				p.Statements = make([]Statement, len(policy.Statements))
				copy(p.Statements, policy.Statements)
				p.dropDuplicateStatementsOriginal()
			}
		})
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name+"_Optimized", func(b *testing.B) {
			statements := setupStatements(scenario.count, scenario.dupRatio)
			policy := &Policy{Version: "2012-10-17", Statements: statements}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p := *policy
				p.Statements = make([]Statement, len(policy.Statements))
				copy(p.Statements, policy.Statements)
				p.dropDuplicateStatements()
			}
		})
	}
}

func BenchmarkDedupe(b *testing.B) {
	var allActions []Action
	var allAdminActions []Action
	for action := range supportedActions {
		allActions = append(allActions, action)
	}
	for action := range supportedAdminActions {
		allAdminActions = append(allAdminActions, Action(action))
	}

	p1 := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Deny,
				NewActionSet(allAdminActions...),
				NewResourceSet(NewResource("bucket0"), NewResource("bucket1"), NewResource("bucket2"), NewResource("bucket3"), NewResource("bucket4"), NewResource("bucket5")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
				NewActionSet(allActions...),
				NewResourceSet(NewResource("bucket0"), NewResource("bucket1"), NewResource("bucket2"), NewResource("bucket3"), NewResource("bucket4"), NewResource("bucket5")),
				condition.NewFunctions(),
			),
		},
	}

	// p2 is a subset of p1
	p2 := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Deny,
				NewActionSet(allAdminActions...),
				NewResourceSet(NewResource("bucket0"), NewResource("bucket1"), NewResource("bucket2"), NewResource("bucket3"), NewResource("bucket4"), NewResource("bucket5")),
				condition.NewFunctions(),
			),
		},
	}

	p3 := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(allActions...),
				NewResourceSet(NewResource("mybucketA"), NewResource("mybucketB"), NewResource("mybucketC"), NewResource("mybucketD"), NewResource("mybucketE"), NewResource("mybucketF"), NewResource("mybucketG"), NewResource("mybucketH"), NewResource("mybucketI"), NewResource("mybucketJ"), NewResource("mybucketK"), NewResource("mybucketL"), NewResource("mybucketM"), NewResource("mybucketN"), NewResource("mybucketO"), NewResource("mybucketP"), NewResource("mybucketQ"), NewResource("mybucketR"), NewResource("mybucketS"), NewResource("mybucketS"), NewResource("mybucketU"), NewResource("mybucketV"), NewResource("mybucketX")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		inputs   []Policy
		expected Policy
	}{
		{
			inputs: []Policy{p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3},
			expected: Policy{
				Version: DefaultVersion,
				Statements: []Statement{
					NewStatement(
						"",
						Deny,
						NewActionSet(allAdminActions...),
						NewResourceSet(NewResource("bucket0"), NewResource("bucket1"), NewResource("bucket2"), NewResource("bucket3"), NewResource("bucket4"), NewResource("bucket5")),
						condition.NewFunctions(),
					),
					NewStatement(
						"",
						Allow,
						NewActionSet(allActions...),
						NewResourceSet(NewResource("bucket0"), NewResource("bucket1"), NewResource("bucket2"), NewResource("bucket3"), NewResource("bucket4"), NewResource("bucket5")),
						condition.NewFunctions(),
					),
					NewStatement(
						"",
						Allow,
						NewActionSet(allActions...),
						NewResourceSet(NewResource("mybucketA"), NewResource("mybucketB"), NewResource("mybucketC"), NewResource("mybucketD"), NewResource("mybucketE"), NewResource("mybucketF"), NewResource("mybucketG"), NewResource("mybucketH"), NewResource("mybucketI"), NewResource("mybucketJ"), NewResource("mybucketK"), NewResource("mybucketL"), NewResource("mybucketM"), NewResource("mybucketN"), NewResource("mybucketO"), NewResource("mybucketP"), NewResource("mybucketQ"), NewResource("mybucketR"), NewResource("mybucketS"), NewResource("mybucketS"), NewResource("mybucketU"), NewResource("mybucketV"), NewResource("mybucketX")),
						condition.NewFunctions(),
					),
				},
			},
		},
	}
	for i, testCase := range testCases {
		b.Run(strconv.Itoa(i), func(b *testing.B) {
			var merged Policy
			for _, p := range testCase.inputs {
				if merged.Version == "" {
					merged.Version = p.Version
				}
				for _, st := range p.Statements {
					merged.Statements = append(merged.Statements, st.Clone())
				}
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				shallow := merged
				shallow.dropDuplicateStatements()
			}
		})
	}
}
