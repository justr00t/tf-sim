package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type preparedEntrypoint struct {
	pkg        string
	entrypoint string
	query      rego.PreparedEvalQuery
}

type rawPolicyFile struct {
	path    string
	content string
}

// Evaluator implements in-memory Rego policy evaluation against PlanSnapshot models.
type Evaluator struct {
	mu    sync.RWMutex
	cache map[string][]preparedEntrypoint
}

// NewEvaluator creates a new PolicyEvaluator instance.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		cache: make(map[string][]preparedEntrypoint),
	}
}

var _ model.PolicyEvaluator = (*Evaluator)(nil)

// EvaluatePlan evaluates the provided policy files against a PlanSnapshot.
func (e *Evaluator) EvaluatePlan(ctx context.Context, policyPaths []string, snapshot *model.PlanSnapshot) (*model.EvalResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, fmt.Errorf("plan snapshot cannot be nil")
	}
	if len(policyPaths) == 0 {
		return nil, fmt.Errorf("at least one policy path must be provided")
	}

	// 1. Dual-envelope input map construction (supporting both rc.change.after.<attr> and rc.after.<attr>)
	rcList := make([]map[string]any, 0, len(snapshot.ResourceChanges))
	for _, rc := range snapshot.ResourceChanges {
		rcMap := map[string]any{
			"address":        rc.Address,
			"module_address": rc.ModuleAddress,
			"type":           rc.Type,
			"name":           rc.Name,
			"provider_name":  rc.ProviderName,
			"actions":        rc.Actions,
			"before":         rc.Before,
			"after":          rc.After,
			"change": map[string]any{
				"actions": rc.Actions,
				"before":  rc.Before,
				"after":   rc.After,
			},
		}
		rcList = append(rcList, rcMap)
	}
	input := map[string]any{
		"resource_changes":  rcList,
		"terraform_version": snapshot.TerraformVer,
		"repo_name":         snapshot.RepoName,
		"snapshot_id":       snapshot.SnapshotID,
	}

	// 2. Load or retrieve cached pre-compiled Rego queries per detected package and entrypoint
	preparedQueries, err := e.getOrPrepareQueries(ctx, policyPaths)
	if err != nil {
		return nil, err
	}

	violations := make([]model.PolicyViolation, 0)

	// 3. Query execution per prepared entrypoint using EvalInput
	for _, pe := range preparedQueries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rs, err := pe.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return nil, fmt.Errorf("evaluate query for %s.%s: %w", pe.pkg, pe.entrypoint, err)
		}

		for _, res := range rs {
			for _, expr := range res.Expressions {
				if expr.Value == nil {
					continue
				}
				if slice, ok := expr.Value.([]any); ok {
					for _, item := range slice {
						v, ok := unmarshalViolation(item)
						if ok {
							violations = append(violations, v)
						}
					}
				} else if itemMap, ok := expr.Value.(map[string]any); ok {
					v, ok := unmarshalViolation(itemMap)
					if ok {
						violations = append(violations, v)
					}
				}
			}
		}
	}

	// 4. Deterministic sort: ResourceAddress ASC, RuleID ASC
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].ResourceAddress != violations[j].ResourceAddress {
			return violations[i].ResourceAddress < violations[j].ResourceAddress
		}
		return violations[i].RuleID < violations[j].RuleID
	})

	return &model.EvalResult{
		SnapshotID:     snapshot.SnapshotID,
		RepoName:       snapshot.RepoName,
		TotalResources: len(snapshot.ResourceChanges),
		Passed:         len(violations) == 0,
		Violations:     violations,
	}, nil
}

func (e *Evaluator) getOrPrepareQueries(ctx context.Context, policyPaths []string) ([]preparedEntrypoint, error) {
	rawFiles := make([]rawPolicyFile, 0, len(policyPaths))
	hasher := sha256.New()

	for _, p := range policyPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read policy file %s: %w", p, err)
		}
		rawFiles = append(rawFiles, rawPolicyFile{
			path:    p,
			content: string(content),
		})
		fmt.Fprintf(hasher, "%d:%s:%d:", len(p), p, len(content))
		hasher.Write(content)
	}

	cacheKey := hex.EncodeToString(hasher.Sum(nil))

	e.mu.RLock()
	if e.cache != nil {
		if cached, ok := e.cache[cacheKey]; ok {
			e.mu.RUnlock()
			return cached, nil
		}
	}
	e.mu.RUnlock()

	packages := make(map[string]map[string]bool) // pkgName -> set of entrypoint rule heads ("deny", "violation")
	for _, rf := range rawFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mod, err := ast.ParseModuleWithOpts(rf.path, rf.content, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parse policy file %s: %w", rf.path, err)
		}

		pkgName := ""
		if mod.Package != nil && mod.Package.Path != nil {
			pkgName = strings.TrimPrefix(mod.Package.Path.String(), "data.")
		}
		if pkgName != "" {
			if _, ok := packages[pkgName]; !ok {
				packages[pkgName] = make(map[string]bool)
			}
			for _, r := range mod.Rules {
				ruleHead := r.Head.Name.String()
				if ruleHead == "deny" || ruleHead == "violation" {
					packages[pkgName][ruleHead] = true
				}
			}
		}
	}

	pkgNames := make([]string, 0, len(packages))
	for pkg := range packages {
		pkgNames = append(pkgNames, pkg)
	}
	sort.Strings(pkgNames)

	prepared := make([]preparedEntrypoint, 0)
	for _, pkg := range pkgNames {
		epMap := packages[pkg]
		epNames := make([]string, 0, len(epMap))
		for ep := range epMap {
			epNames = append(epNames, ep)
		}
		sort.Strings(epNames)

		for _, entrypoint := range epNames {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			regoOpts := make([]func(*rego.Rego), 0, 1+len(rawFiles))
			regoOpts = append(regoOpts, rego.Query("data."+pkg+"."+entrypoint))
			for _, rf := range rawFiles {
				regoOpts = append(regoOpts, rego.Module(rf.path, rf.content))
			}

			r := rego.New(regoOpts...)
			pq, err := r.PrepareForEval(ctx)
			if err != nil {
				return nil, fmt.Errorf("prepare query for %s.%s: %w", pkg, entrypoint, err)
			}

			prepared = append(prepared, preparedEntrypoint{
				pkg:        pkg,
				entrypoint: entrypoint,
				query:      pq,
			})
		}
	}

	e.mu.Lock()
	if e.cache == nil {
		e.cache = make(map[string][]preparedEntrypoint)
	}
	e.cache[cacheKey] = prepared
	e.mu.Unlock()

	return prepared, nil
}

func unmarshalViolation(item any) (model.PolicyViolation, bool) {
	bytes, err := json.Marshal(item)
	if err != nil {
		return model.PolicyViolation{}, false
	}
	var v model.PolicyViolation
	if err := json.Unmarshal(bytes, &v); err != nil {
		return model.PolicyViolation{}, false
	}
	if v.RuleID == "" && v.ResourceAddress == "" {
		return model.PolicyViolation{}, false
	}
	return v, true
}
