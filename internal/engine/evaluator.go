package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Evaluator implements in-memory Rego policy evaluation against PlanSnapshot models.
type Evaluator struct{}

// NewEvaluator creates a new PolicyEvaluator instance.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
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

	// 2. Load policy modules and detect packages and entrypoints
	modules := make(map[string]string)
	packages := make(map[string]map[string]bool) // pkgName -> set of entrypoint rule heads ("deny", "violation")

	for _, p := range policyPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read policy file %s: %w", p, err)
		}
		mod, err := ast.ParseModuleWithOpts(p, string(content), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parse policy file %s: %w", p, err)
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

		modules[p] = string(content)
	}

	violations := make([]model.PolicyViolation, 0)

	// 3. Query execution per detected package and entrypoint
	for pkg, entrypoints := range packages {
		for entrypoint := range entrypoints {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			regoOpts := []func(*rego.Rego){
				rego.Query("data." + pkg + "." + entrypoint),
				rego.Input(input),
			}
			for path, content := range modules {
				regoOpts = append(regoOpts, rego.Module(path, content))
			}

			r := rego.New(regoOpts...)
			pq, err := r.PrepareForEval(ctx)
			if err != nil {
				return nil, fmt.Errorf("prepare query for %s.%s: %w", pkg, entrypoint, err)
			}

			rs, err := pq.Eval(ctx)
			if err != nil {
				return nil, fmt.Errorf("evaluate query for %s.%s: %w", pkg, entrypoint, err)
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
