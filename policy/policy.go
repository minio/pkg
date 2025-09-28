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
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/minio/pkg/v3/wildcard"
)

// DefaultVersion - default policy version as per AWS S3 specification.
const DefaultVersion = "2012-10-17"

// Args - arguments to policy to check whether it is allowed
type Args struct {
	AccountName     string              `json:"account"`
	Groups          []string            `json:"groups"`
	Action          Action              `json:"action"`
	OriginalAction  Action              `json:"originalAction"`
	BucketName      string              `json:"bucket"`
	ConditionValues map[string][]string `json:"conditions"`
	IsOwner         bool                `json:"owner"`
	ObjectName      string              `json:"object"`
	Claims          map[string]any      `json:"claims"`
	DenyOnly        bool                `json:"denyOnly"` // only applies deny
}

// GetValuesFromClaims returns the list of values for the input claimName.
// Supports values in following formats
// - string
// - comma separated values
// - string array
func GetValuesFromClaims(claims map[string]any, claimName string) (set.StringSet, bool) {
	s := set.NewStringSet()
	pname, ok := claims[claimName]
	if !ok {
		return s, false
	}
	pnames, ok := pname.([]any)
	if !ok {
		pnameStr, ok := pname.(string)
		if ok {
			for _, pname := range strings.Split(pnameStr, ",") {
				pname = strings.TrimSpace(pname)
				if pname == "" {
					// ignore any empty strings, considerate
					// towards some user errors.
					continue
				}
				s.Add(pname)
			}
			return s, true
		}
		return s, false
	}
	for _, pname := range pnames {
		pnameStr, ok := pname.(string)
		if ok {
			for _, pnameStr := range strings.Split(pnameStr, ",") {
				pnameStr = strings.TrimSpace(pnameStr)
				if pnameStr == "" {
					// ignore any empty strings, considerate
					// towards some user errors.
					continue
				}
				s.Add(pnameStr)
			}
		}
	}
	return s, true
}

// GetPoliciesFromClaims returns the list of policies to be applied for this
// incoming request, extracting the information from input JWT claims.
func GetPoliciesFromClaims(claims map[string]any, policyClaimName string) (set.StringSet, bool) {
	return GetValuesFromClaims(claims, policyClaimName)
}

// GetPolicies returns the list of policies to be applied for this
// incoming request, extracting the information from JWT claims.
func (a Args) GetPolicies(policyClaimName string) (set.StringSet, bool) {
	return GetPoliciesFromClaims(a.Claims, policyClaimName)
}

// GetRoleArn returns the role ARN from JWT claims if present. Otherwise returns
// empty string.
func (a Args) GetRoleArn() string {
	s, ok := a.Claims["roleArn"]
	roleArn, ok2 := s.(string)
	if ok && ok2 {
		return roleArn
	}
	return ""
}

// Policy - iam bucket iamp.
type Policy struct {
	ID                   ID `json:"ID,omitempty"`
	Version              string
	Statements           []Statement `json:"Statement"`
	actionStatementIndex map[Action][]int
	hasDeny              bool
}

// HasDenyStatement returns if the policy has a deny statement.
func (iamp *Policy) HasDenyStatement() bool {
	return iamp.hasDeny
}

// MatchResource matches resource with match resource patterns
func (iamp Policy) MatchResource(resource string) bool {
	for _, statement := range iamp.Statements {
		if statement.Resources.MatchResource(resource) {
			return true
		}
	}
	return false
}

// IsAllowedActions returns all supported actions for this policy.
func (iamp Policy) IsAllowedActions(bucketName, objectName string, conditionValues map[string][]string) ActionSet {
	actionSet := make(ActionSet)
	for action := range supportedActions {
		if iamp.IsAllowed(Args{
			BucketName:      bucketName,
			ObjectName:      objectName,
			Action:          action,
			ConditionValues: conditionValues,
		}) {
			actionSet.Add(action)
		}
	}
	for action := range supportedAdminActions {
		admAction := Action(action)
		if iamp.IsAllowed(Args{
			BucketName:      bucketName,
			ObjectName:      objectName,
			Action:          admAction,
			ConditionValues: conditionValues,
			// checks mainly for actions that can have explicit
			// deny, while without it are implicitly enabled.
			DenyOnly: action == CreateServiceAccountAdminAction || action == CreateUserAdminAction,
		}) {
			actionSet.Add(admAction)
		}
	}
	for action := range supportedKMSActions {
		kmsAction := Action(action)
		if iamp.IsAllowed(Args{
			BucketName:      bucketName,
			ObjectName:      objectName,
			Action:          kmsAction,
			ConditionValues: conditionValues,
		}) {
			actionSet.Add(kmsAction)
		}
	}

	return actionSet
}

// IsAllowedSerial - checks if the given Args is allowed by any one of the given
// policies in serial.
//
// This is currently the fastest implementation for our basic benchmark.
func IsAllowedSerial(policies []Policy, args Args) bool {
	gotAllow := false
	for _, policy := range policies {
		res := policy.Decide(&args)
		if res == DenyDecision {
			return false
		}
		if res == AllowDecision {
			gotAllow = true
		}
	}
	return gotAllow
}

// IsAllowedPar - checks if the given Args is allowed by any one of the given
// policies in parallel (when len(policies) > 100).
func IsAllowedPar(policies []Policy, args Args) bool {
	if len(policies) == 0 {
		return false
	}

	// If there is only one policy, use it directly.
	if len(policies) == 1 {
		return policies[0].IsAllowed(args)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// This must be at least 1.
	const numPoliciesPerWorker = 25

	// Here numJobs = ceil(len(policies) / numPoliciesPerWorker) - computed
	// using integer arithmetic
	numJobs := (len(policies) + numPoliciesPerWorker - 1) / numPoliciesPerWorker

	// get number of workers.
	numWorkers := min(runtime.GOMAXPROCS(0), numJobs)

	jobs := make(chan int, numJobs)
	for i := range numJobs {
		jobs <- i * numPoliciesPerWorker
	}
	close(jobs)

	resultCh := make(chan Decision, len(policies))

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for range numWorkers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				maxJ := min(i+numPoliciesPerWorker, len(policies))
				res := NoDecision
				for j := i; j < maxJ; j++ {
					decision := policies[j].Decide(&args)
					if decision == DenyDecision {
						res = DenyDecision
						break
					} else if decision == AllowDecision {
						res = AllowDecision
					}
				}

				select {
				case resultCh <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	gotAllow := false
	for range numJobs {
		res := <-resultCh
		if res == DenyDecision {
			cancel()
			wg.Wait()
			return false
		}
		if res == AllowDecision {
			gotAllow = true
		}
	}

	wg.Wait()
	return gotAllow
}

// Decision is an enum type representing the decision made by the policy
// for the given arguments.
type Decision uint8

// Possible decisions made by the policy.
const (
	NoDecision Decision = iota
	AllowDecision
	DenyDecision
)

// Decide - decides whether the given args is allowed or not. If no policy
// statement explicitly allows or denies the operation in the Args, it returns
// `noDecision`. It is upto the caller to handle such cases.
func (iamp *Policy) Decide(args *Args) Decision {
	// Check all deny statements. If any one statement denies, return false.
	for _, statement := range iamp.Statements {
		if statement.Effect == Deny && !statement.IsAllowedPtr(args) {
			return DenyDecision
		}
	}

	// Applied any 'Deny' only policies, if we have
	// reached here it means that there were no 'Deny'
	// policies - this function mainly used for
	// specific scenarios where we only want to validate
	// 'Deny' only policies.
	if args.DenyOnly {
		return AllowDecision
	}

	// For owner, its allowed by default.
	if args.IsOwner {
		return AllowDecision
	}

	// Check all allow statements. If any one statement allows, return true.
	if len(iamp.actionStatementIndex) > 0 {
		if indexes, ok := iamp.actionStatementIndex[args.Action]; ok {
			for _, index := range indexes {
				statement := iamp.Statements[index]
				if statement.Effect == Allow && statement.IsAllowedPtr(args) {
					return AllowDecision
				}
			}
		}
	}

	for _, statement := range iamp.Statements {
		if statement.Effect == Allow && statement.IsAllowedPtr(args) {
			return AllowDecision
		}
	}

	return NoDecision
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (iamp Policy) IsAllowed(args Args) bool {
	decision := iamp.Decide(&args)
	if decision == NoDecision {
		// No decision made, return false.
		return false
	}

	return decision == AllowDecision
}

// IsEmpty - returns whether policy is empty or not.
func (iamp Policy) IsEmpty() bool {
	return len(iamp.Statements) == 0
}

// isValid - checks if Policy is valid or not.
func (iamp Policy) isValid() error {
	if iamp.Version != DefaultVersion && iamp.Version != "" {
		return Errorf("invalid version '%v'", iamp.Version)
	}

	for _, statement := range iamp.Statements {
		if err := statement.isValid(); err != nil {
			return err
		}
	}
	return nil
}

// MergePolicies merges all the given policies into a single policy dropping any
// duplicate statements.
func MergePolicies(inputs ...Policy) (merged Policy) {
	if len(inputs) == 0 {
		return merged
	}

	if len(inputs) == 1 {
		return inputs[0]
	}

	totalStmts := 0
	for _, p := range inputs {
		if merged.Version == "" {
			merged.Version = p.Version
		}
		totalStmts += len(p.Statements)
	}
	merged.Statements = make([]Statement, 0, totalStmts)
	found := make(map[[16]byte]struct{}, totalStmts)

	// Apply a base seed
	var baseSeed [8]byte
	rand.Read(baseSeed[:])
	var seed uint64
	binary.LittleEndian.PutUint64(baseSeed[:], seed)

	for _, p := range inputs {
		for _, st := range p.Statements {
			h := st.hash(seed)
			if _, ok := found[h]; ok {
				continue
			}
			found[h] = struct{}{}
			merged.Statements = append(merged.Statements, st)
		}
	}

	merged.updateActionIndex()
	return merged
}

func (iamp *Policy) dropDuplicateStatementsMany() {
	// Calculate a hash for each.
	// Drop statements with duplicate hashes.
	found := make(map[[16]byte]struct{}, len(iamp.Statements))

	// Apply a base seed
	var baseSeed [8]byte
	rand.Read(baseSeed[:])
	var seed uint64
	binary.LittleEndian.PutUint64(baseSeed[:], seed)
	writeAt := 0
	for _, s := range iamp.Statements {
		h := s.hash(seed)
		if _, ok := found[h]; ok {
			// duplicate, do not write.
			continue
		}
		found[h] = struct{}{}
		iamp.Statements[writeAt] = s
		writeAt++
	}
	iamp.Statements = iamp.Statements[:writeAt]
}

// dropDuplicateStatements removes duplicate statements using hashing.
func (iamp *Policy) dropDuplicateStatementsOriginal() {
	dups := make(map[int]struct{})
	for i := range iamp.Statements {
		if _, ok := dups[i]; ok {
			continue
		}
		for j := i + 1; j < len(iamp.Statements); j++ {
			if !iamp.Statements[i].Equals(iamp.Statements[j]) {
				continue
			}
			dups[j] = struct{}{}
		}
	}

	var c int
	for i := range iamp.Statements {
		if _, ok := dups[i]; ok {
			continue
		}
		iamp.Statements[c] = iamp.Statements[i]
		c++
	}
	iamp.Statements = iamp.Statements[:c]
}

// dropDuplicateStatements removes duplicate statements using hashing.
func (iamp *Policy) dropDuplicateStatements() {
	if len(iamp.Statements) <= 10 {
		iamp.dropDuplicateStatementsOriginal()
		return
	}

	iamp.dropDuplicateStatementsMany()
}

// UnmarshalJSON - decodes JSON data to Iamp.
func (iamp *Policy) UnmarshalJSON(data []byte) error {
	// subtype to avoid recursive call to UnmarshalJSON()
	type subPolicy Policy
	var sp subPolicy
	if err := json.Unmarshal(data, &sp); err != nil {
		return err
	}

	p := Policy(sp)
	p.dropDuplicateStatements()
	p.updateActionIndex()
	*iamp = p
	return nil
}

// Validate - validates all statements are for given bucket or not.
func (iamp Policy) Validate() error {
	return iamp.isValid()
}

// updateActionIndex with latest statements()
// maintains a reverse map of Action -> []Statements
// for faster lookup and short-circuit.
func (iamp *Policy) updateActionIndex() {
	for i := range iamp.Statements {
		stmt := &iamp.Statements[i]
		if stmt.Effect == Deny {
			iamp.hasDeny = true
			continue
		}
		for action := range stmt.Actions {
			if wildcard.Has(string(action)) {
				// Do not store any 'wildcard' actions
				// as we cannot optimize such actions.
				continue
			}
			if iamp.actionStatementIndex == nil {
				// do not create action statement index
				// if we do not have any statement or actions
				// to save them for, simply avoids allocations
				iamp.actionStatementIndex = make(map[Action][]int, len(iamp.Statements))
			}
			iamp.actionStatementIndex[action] = append(iamp.actionStatementIndex[action], i)
		}
	}
}

// ParseConfig - parses data in given reader to Iamp.
func ParseConfig(reader io.Reader) (*Policy, error) {
	var iamp Policy

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&iamp); err != nil {
		return nil, Errorf("%w", err)
	}

	return &iamp, iamp.Validate()
}

// Equals returns true if the two policies are identical
func (iamp *Policy) Equals(p Policy) bool {
	if iamp.ID != p.ID || iamp.Version != p.Version {
		return false
	}
	if len(iamp.Statements) != len(p.Statements) {
		return false
	}
	for i, st := range iamp.Statements {
		if !p.Statements[i].Equals(st) {
			return false
		}
	}
	return true
}
