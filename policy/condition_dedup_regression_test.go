package policy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

// A Deny restricted by a condition that holds a space in its value used to be
// dropped as a duplicate of a Deny carrying the same characters as two values:
// StringFunc.String rendered both as "[a b]", so Statement.Equals and
// Statement.hash -- which compare through that string -- called them equal and
// dropDuplicateStatements discarded the second. The restriction it states went
// with it. Unlike the NotResources omission fixed earlier, this one is not
// confined to the hashed path: both the exact-comparison and the hashed path
// route through String.
func TestDropDuplicateStatementsKeepsDistinctConditions(t *testing.T) {
	deny := func(t *testing.T, cond string) Statement {
		t.Helper()
		var p Policy
		src := `{"Version":"` + DefaultVersion + `","Statement":[{"Effect":"Deny",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/*"],"Condition":` + cond + `}]}`
		if err := json.Unmarshal([]byte(src), &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(p.Statements) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(p.Statements))
		}
		return p.Statements[0]
	}

	// Two statements that share Effect, Action and Resource, and differ only in
	// the condition: one value holding a space against two separate values.
	space := deny(t, `{"StringEquals":{"s3:prefix":"a b"}}`)
	split := deny(t, `{"StringEquals":{"s3:prefix":["a","b"]}}`)

	// The two conditions must stay distinguishable, otherwise the test below
	// proves nothing about de-duplication.
	if space.Conditions.Equals(split.Conditions) {
		t.Fatal("precondition failed: the two conditions compare equal")
	}
	for _, prefix := range []string{"a b", "a"} {
		values := map[string][]string{"prefix": {prefix}}
		if !space.Conditions.Evaluate(values) && !split.Conditions.Evaluate(values) {
			continue
		}
		if space.Conditions.Evaluate(values) == split.Conditions.Evaluate(values) {
			t.Fatalf("precondition failed: the two conditions agree on prefix %q", prefix)
		}
	}

	build := func(n int, first, second Statement) Policy {
		sts := []Statement{first, second}
		for i := len(sts); i < n; i++ {
			sts = append(sts, NewStatement("", Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource(fmt.Sprintf("filler%d/*", i))),
				condition.NewFunctions()))
		}
		return Policy{Version: DefaultVersion, Statements: sts}
	}

	for _, n := range []int{4, 11, 20} {
		p := build(n, space, split)
		before := len(p.Statements)
		p.dropDuplicateStatements()
		path := "original(<=10)"
		if n > 10 {
			path = "hashed(>10)"
		}
		got := len(p.Statements)
		t.Logf("n=%2d %-15s statements %d -> %d", n, path, before, got)
		if got != before {
			t.Errorf("n=%d: LOST %d statement(s) that are not duplicates", n, before-got)
		}
	}
}

// The same collapse reaches the decision, not just the statement list: the
// dropped Deny stopped restricting a request that the parser had been told to
// restrict.
func TestDistinctConditionsKeepRestrictingTheDecision(t *testing.T) {
	const src = `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]},
	    {"Effect": "Deny", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"],
	     "Condition": {"StringEquals": {"s3:prefix": "a b"}}},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler1/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler2/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler3/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler4/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler5/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler6/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler7/*"]},
	    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::filler8/*"]}
	  ]
	}`

	var p Policy
	if err := json.Unmarshal([]byte(src), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The Deny names the prefix "a b", so that request is refused ...
	denied := p.IsAllowed(Args{
		AccountName:     "user",
		Action:          GetObjectAction,
		BucketName:      "bucket",
		ObjectName:      "obj",
		ConditionValues: map[string][]string{"prefix": {"a b"}},
	})
	if denied {
		t.Error("the Deny on prefix \"a b\" was dropped: the request it refuses was allowed")
	}

	// ... while the object it does not cover stays readable.
	if !p.IsAllowed(Args{
		AccountName:     "user",
		Action:          GetObjectAction,
		BucketName:      "bucket",
		ObjectName:      "obj",
		ConditionValues: map[string][]string{"prefix": {"other"}},
	}) {
		t.Error("an unrelated request was refused")
	}
}
