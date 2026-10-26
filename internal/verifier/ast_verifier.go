package verifier

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

// Verifier implements static Rego AST schema verification.
type Verifier struct{}

// NewVerifier creates a new ASTVerifier instance.
func NewVerifier() *Verifier {
	return &Verifier{}
}

var _ model.ASTVerifier = (*Verifier)(nil)

type intermediateBinding struct {
	resourceType string
	path         []string
}

type segmentInfo struct {
	name string
	row  int
}

// VerifyPolicy performs static analysis on a Rego policy against the provider schema.
func (v *Verifier) VerifyPolicy(ctx context.Context, policyPath string, schemas model.ProviderSchemaMap) (*model.VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fi, err := os.Stat(policyPath)
	if err != nil {
		return nil, fmt.Errorf("stat policy file %s: %w", policyPath, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("stat policy file %s: is a directory", policyPath)
	}

	content, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", policyPath, err)
	}

	mod, err := ast.ParseModuleWithOpts(policyPath, string(content), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		var diags []model.SchemaDiagnostic
		if astErrors, ok := err.(ast.Errors); ok {
			for _, e := range astErrors {
				row := 1
				if e.Location != nil {
					row = e.Location.Row
				}
				diags = append(diags, model.SchemaDiagnostic{
					PolicyFile: policyPath,
					Line:       row,
					Message:    e.Message,
					Severity:   "ERROR",
				})
			}
		} else {
			diags = append(diags, model.SchemaDiagnostic{
				PolicyFile: policyPath,
				Line:       1,
				Message:    err.Error(),
				Severity:   "ERROR",
			})
		}
		return &model.VerificationResult{
			PolicyPath:  policyPath,
			PackageName: "",
			Valid:       false,
			Diagnostics: diags,
		}, nil
	}

	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{policyPath: mod})
	if compiler.Failed() {
		var diags []model.SchemaDiagnostic
		for _, e := range compiler.Errors {
			row := 1
			if e.Location != nil {
				row = e.Location.Row
			}
			diags = append(diags, model.SchemaDiagnostic{
				PolicyFile: policyPath,
				Line:       row,
				Message:    e.Message,
				Severity:   "ERROR",
			})
		}
		pkgName := ""
		if mod.Package != nil && mod.Package.Path != nil {
			pkgName = strings.TrimPrefix(mod.Package.Path.String(), "data.")
		}
		return &model.VerificationResult{
			PolicyPath:  policyPath,
			PackageName: pkgName,
			Valid:       false,
			Diagnostics: diags,
		}, nil
	}

	pkgName := ""
	if mod.Package != nil && mod.Package.Path != nil {
		pkgName = strings.TrimPrefix(mod.Package.Path.String(), "data.")
	}

	var diagnostics []model.SchemaDiagnostic

	hasEntrypoint := false
	for _, r := range mod.Rules {
		headName := r.Head.Name.String()
		if headName == "deny" || headName == "violation" {
			hasEntrypoint = true
			break
		}
	}
	if !hasEntrypoint {
		row := 1
		if mod.Package != nil && mod.Package.Location != nil {
			row = mod.Package.Location.Row
		}
		diagnostics = append(diagnostics, model.SchemaDiagnostic{
			PolicyFile: policyPath,
			Line:       row,
			Message:    "policy must define at least one 'deny' or 'violation' rule",
			Severity:   "ERROR",
		})
	}

	if len(schemas) == 0 {
		return &model.VerificationResult{
			PolicyPath:  policyPath,
			PackageName: pkgName,
			Valid:       len(diagnostics) == 0,
			Diagnostics: diagnostics,
		}, nil
	}

	// Index rules by head name for helper call resolution.
	rulesByName := make(map[string][]*ast.Rule)
	for _, r := range mod.Rules {
		name := r.Head.Name.String()
		rulesByName[name] = append(rulesByName[name], r)
	}

	// Map each rule to sets of parameter bindings (paramName -> resourceType).
	ruleBindings := make(map[*ast.Rule][]map[string]string)

	// Step 1: Scan entrypoint and top-level rules for resource types and helper calls.
	for _, r := range mod.Rules {
		headName := r.Head.Name.String()
		isEntrypoint := (headName == "deny" || headName == "violation")
		isParamless := len(r.Head.Args) == 0

		if !isEntrypoint && !isParamless {
			continue
		}

		localTypes, typeDiags := scanRuleResourceTypes(r, schemas, policyPath)
		diagnostics = append(diagnostics, typeDiags...)

		ruleBindings[r] = append(ruleBindings[r], localTypes)

		// Check for helper rule calls in this rule.
		propagateHelperCalls(r, localTypes, rulesByName, ruleBindings)
	}

	// Step 2: Validate each rule against provider schemas.
	for _, r := range mod.Rules {
		bindingSets := ruleBindings[r]
		if len(bindingSets) == 0 {
			// If not called by entrypoint, still scan its own local resource types.
			localTypes, typeDiags := scanRuleResourceTypes(r, schemas, policyPath)
			diagnostics = append(diagnostics, typeDiags...)
			bindingSets = []map[string]string{localTypes}
		}

		for _, vt := range bindingSets {
			ruleDiags := validateRuleBody(r, vt, schemas, policyPath)
			diagnostics = append(diagnostics, ruleDiags...)
		}
	}

	// Deduplicate diagnostics
	diagnostics = deduplicateDiagnostics(diagnostics)

	// Deterministic sort: Line ASC, ResourceType ASC, InvalidPath ASC
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].Line != diagnostics[j].Line {
			return diagnostics[i].Line < diagnostics[j].Line
		}
		if diagnostics[i].ResourceType != diagnostics[j].ResourceType {
			return diagnostics[i].ResourceType < diagnostics[j].ResourceType
		}
		return diagnostics[i].InvalidPath < diagnostics[j].InvalidPath
	})

	return &model.VerificationResult{
		PolicyPath:  policyPath,
		PackageName: pkgName,
		Valid:       len(diagnostics) == 0,
		Diagnostics: diagnostics,
	}, nil
}

// scanRuleResourceTypes discovers resource types bound in rule expressions (e.g. rc.type == "aws_s3_bucket").
func scanRuleResourceTypes(r *ast.Rule, schemas model.ProviderSchemaMap, policyPath string) (map[string]string, []model.SchemaDiagnostic) {
	varTypes := make(map[string]string)
	var diags []model.SchemaDiagnostic

	for _, expr := range r.Body {
		terms, ok := expr.Terms.([]*ast.Term)
		if !ok || len(terms) < 2 {
			continue
		}

		op := expr.Operator().String()

		// Case 1: Equality (rc.type == "resource_type" or "resource_type" == rc.type)
		if (op == "equal" || op == "eq" || op == "=") && len(terms) == 3 {
			varName, resType, locRow := extractTypeEquality(terms[1], terms[2])
			if varName == "" {
				varName, resType, locRow = extractTypeEquality(terms[2], terms[1])
			}
			if varName != "" && resType != "" {
				if _, ok := schemas[resType]; !ok {
					diags = append(diags, model.SchemaDiagnostic{
						PolicyFile:   policyPath,
						Line:         locRow,
						ResourceType: resType,
						Message:      fmt.Sprintf("Unknown resource type %q in provider schema", resType),
						Severity:     "ERROR",
					})
				} else {
					varTypes[varName] = resType
					if varName == "input" || strings.HasPrefix(varName, "input.") {
						varTypes["input"] = resType
					}
				}
			}
		}

		// Case 2: rc.type in ["resource_type"] (internal.member_2)
		if op == "internal.member_2" && len(terms) == 3 {
			if ref, ok := terms[1].Value.(ast.Ref); ok && isTypeRef(ref) {
				varName := getRootVar(ref)
				row := 1
				if terms[1].Location != nil {
					row = terms[1].Location.Row
				}
				if arr, ok := terms[2].Value.(*ast.Array); ok {
					for i := 0; i < arr.Len(); i++ {
						elem := arr.Elem(i)
						if str, ok := elem.Value.(ast.String); ok {
							resType := string(str)
							if _, ok := schemas[resType]; !ok {
								diags = append(diags, model.SchemaDiagnostic{
									PolicyFile:   policyPath,
									Line:         row,
									ResourceType: resType,
									Message:      fmt.Sprintf("Unknown resource type %q in provider schema", resType),
									Severity:     "ERROR",
								})
							} else {
								varTypes[varName] = resType
							}
						}
					}
				}
			}
		}
	}

	return varTypes, diags
}

// extractTypeEquality checks if a term is an rc.type ref and the other is a resource type string literal.
func extractTypeEquality(termA, termB *ast.Term) (string, string, int) {
	ref, isRef := termA.Value.(ast.Ref)
	str, isStr := termB.Value.(ast.String)
	if !isRef || !isStr {
		return "", "", 0
	}
	if !isTypeRef(ref) {
		return "", "", 0
	}
	varName := getRootVar(ref)
	row := 1
	if termA.Location != nil {
		row = termA.Location.Row
	}
	return varName, string(str), row
}

func isTypeRef(ref ast.Ref) bool {
	if len(ref) < 2 {
		return false
	}
	last := ref[len(ref)-1]
	if str, ok := last.Value.(ast.String); ok && string(str) == "type" {
		return true
	}
	return false
}

func getRootVar(ref ast.Ref) string {
	if len(ref) == 0 {
		return ""
	}
	if v, ok := ref[0].Value.(ast.Var); ok {
		return string(v)
	}
	return ""
}

// propagateHelperCalls discovers calls to other rules in the policy and propagates parameter types.
func propagateHelperCalls(r *ast.Rule, localTypes map[string]string, rulesByName map[string][]*ast.Rule, ruleBindings map[*ast.Rule][]map[string]string) {
	for _, expr := range r.Body {
		terms, ok := expr.Terms.([]*ast.Term)
		if !ok || len(terms) < 2 {
			continue
		}

		fnName := ""
		if ref, ok := terms[0].Value.(ast.Ref); ok && len(ref) == 1 {
			fnName = ref[0].String()
		} else if v, ok := terms[0].Value.(ast.Var); ok {
			fnName = string(v)
		}

		targetRules, exists := rulesByName[fnName]
		if !exists {
			continue
		}

		// Map arguments to parameter positions.
		for _, tr := range targetRules {
			trBindings := make(map[string]string)
			for argIdx := 1; argIdx < len(terms); argIdx++ {
				paramIdx := argIdx - 1
				if paramIdx >= len(tr.Head.Args) {
					break
				}
				paramName := tr.Head.Args[paramIdx].String()
				argVar := ""
				if v, ok := terms[argIdx].Value.(ast.Var); ok {
					argVar = string(v)
				}
				if resType, ok := localTypes[argVar]; ok {
					trBindings[paramName] = resType
				}
			}
			if len(trBindings) > 0 {
				ruleBindings[tr] = append(ruleBindings[tr], trBindings)
				// Propagate recursively
				propagateHelperCalls(tr, trBindings, rulesByName, ruleBindings)
			}
		}
	}
}

// validateRuleBody performs AST ref extraction and schema cross-referencing.
func validateRuleBody(r *ast.Rule, varTypes map[string]string, schemas model.ProviderSchemaMap, policyPath string) []model.SchemaDiagnostic {
	var diags []model.SchemaDiagnostic
	varBindings := make(map[string]intermediateBinding)

	// In single-resource rules, if only one resource type is known, bind "input" as well.
	if len(varTypes) == 1 {
		for _, rt := range varTypes {
			varTypes["input"] = rt
			break
		}
	}

	for _, expr := range r.Body {
		// 1. Discover intermediate variable bindings in this expression.
		bindVar, sourceRef := extractBinding(expr)
		if bindVar != "" && len(sourceRef) > 0 {
			resType, prefix := resolveRefPrefix(sourceRef, varTypes, varBindings)
			if resType != "" {
				varBindings[bindVar] = intermediateBinding{
					resourceType: resType,
					path:         prefix,
				}
			}
		}

		// 2. Validate all refs in the expression.
		ast.WalkRefs(expr, func(ref ast.Ref) bool {
			resType, segments := resolveRefPath(ref, varTypes, varBindings)
			if resType == "" || len(segments) == 0 {
				return false
			}

			if d := validatePathAgainstSchema(policyPath, resType, segments, schemas); d != nil {
				diags = append(diags, *d)
			}
			return false
		})
	}

	return diags
}

// extractBinding discovers variable assignments from some ... in ... or := / =.
func extractBinding(expr *ast.Expr) (string, ast.Ref) {
	if someDecl, isSome := expr.Terms.(*ast.SomeDecl); isSome {
		for _, sym := range someDecl.Symbols {
			if call, isCall := sym.Value.(ast.Call); isCall {
				if len(call) >= 3 {
					fn := call[0].String()
					if fn == "internal.member_2" {
						if v, isVar := call[1].Value.(ast.Var); isVar {
							if ref, isRef := call[2].Value.(ast.Ref); isRef {
								return string(v), ref
							}
						}
					} else if fn == "internal.member_3" && len(call) >= 4 {
						if v, isVar := call[2].Value.(ast.Var); isVar {
							if ref, isRef := call[3].Value.(ast.Ref); isRef {
								return string(v), ref
							}
						}
					}
				}
			}
		}
	} else if terms, isTerms := expr.Terms.([]*ast.Term); isTerms && len(terms) == 3 {
		op := expr.Operator().String()
		if op == "assign" || op == "equal" || op == "eq" || op == "=" {
			if v, isVar := terms[1].Value.(ast.Var); isVar {
				if ref, isRef := terms[2].Value.(ast.Ref); isRef {
					return string(v), ref
				}
			} else if v, isVar := terms[2].Value.(ast.Var); isVar {
				if ref, isRef := terms[1].Value.(ast.Ref); isRef {
					return string(v), ref
				}
			}
		}
	}
	return "", nil
}

// resolveRefPrefix extracts the schema prefix path for an intermediate binding source.
func resolveRefPrefix(ref ast.Ref, varTypes map[string]string, varBindings map[string]intermediateBinding) (string, []string) {
	if len(ref) == 0 {
		return "", nil
	}
	root := getRootVar(ref)

	// If root is an existing intermediate binding
	if binding, ok := varBindings[root]; ok {
		prefix := append([]string{}, binding.path...)
		for _, term := range ref[1:] {
			if str, ok := term.Value.(ast.String); ok {
				prefix = append(prefix, string(str))
			}
		}
		return binding.resourceType, prefix
	}

	// If root is a resource variable (e.g. rc) or input
	resType, ok := varTypes[root]
	if !ok && root == "input" {
		resType = varTypes["input"]
	}
	if resType == "" {
		return "", nil
	}

	afterIdx := findStateIndex(ref)
	if afterIdx == -1 {
		return "", nil
	}

	prefix := make([]string, 0)
	for _, term := range ref[afterIdx+1:] {
		if str, ok := term.Value.(ast.String); ok {
			prefix = append(prefix, string(str))
		}
	}
	return resType, prefix
}

// resolveRefPath extracts the full sequence of schema segment names and line numbers for a ref.
func resolveRefPath(ref ast.Ref, varTypes map[string]string, varBindings map[string]intermediateBinding) (string, []segmentInfo) {
	if len(ref) == 0 {
		return "", nil
	}
	root := getRootVar(ref)

	// Case 1: Ref rooted at intermediate variable (e.g. def.sse_algorithm or ssec.rule)
	if binding, ok := varBindings[root]; ok {
		segments := make([]segmentInfo, 0, len(binding.path)+len(ref)-1)
		rootRow := 1
		if ref[0].Location != nil {
			rootRow = ref[0].Location.Row
		}
		for _, p := range binding.path {
			segments = append(segments, segmentInfo{name: p, row: rootRow})
		}
		for _, term := range ref[1:] {
			if str, ok := term.Value.(ast.String); ok {
				row := rootRow
				if term.Location != nil {
					row = term.Location.Row
				}
				segments = append(segments, segmentInfo{name: string(str), row: row})
			}
		}
		return binding.resourceType, segments
	}

	// Case 2: Ref rooted at resource variable (e.g. rc.change.after.foo or rc.after.foo)
	resType, ok := varTypes[root]
	if !ok && root == "input" {
		resType = varTypes["input"]
	}
	if resType == "" {
		return "", nil
	}

	afterIdx := findStateIndex(ref)
	if afterIdx == -1 {
		return "", nil
	}

	segments := make([]segmentInfo, 0)
	for _, term := range ref[afterIdx+1:] {
		if str, ok := term.Value.(ast.String); ok {
			row := 1
			if term.Location != nil {
				row = term.Location.Row
			}
			segments = append(segments, segmentInfo{name: string(str), row: row})
		}
	}

	return resType, segments
}

func findStateIndex(ref ast.Ref) int {
	for idx, term := range ref {
		if str, ok := term.Value.(ast.String); ok {
			val := string(str)
			if val == "after" || val == "before" {
				return idx
			}
		}
	}
	return -1
}

// validatePathAgainstSchema traverses the schema definition for a resource and validates path segments.
func validatePathAgainstSchema(policyPath string, resourceType string, segments []segmentInfo, schemas model.ProviderSchemaMap) *model.SchemaDiagnostic {
	curr, ok := schemas[resourceType]
	if !ok {
		return nil
	}

	for i, seg := range segments {
		isFinal := (i == len(segments)-1)

		// 1. Does seg exist in NestedBlocks?
		if nb, ok := curr.NestedBlocks[seg.name]; ok {
			curr = nb
			continue
		}

		// 2. Does seg exist in Attributes?
		if _, ok := curr.Attributes[seg.name]; ok {
			if isFinal {
				return nil
			}
			// If not final, can we descend into a block with the same name?
			if nb, ok := curr.NestedBlocks[seg.name]; ok {
				curr = nb
				continue
			}
			return &model.SchemaDiagnostic{
				PolicyFile:   policyPath,
				Line:         seg.row,
				ResourceType: resourceType,
				InvalidPath:  seg.name,
				Message:      fmt.Sprintf("Attribute %q is not a nested block on resource %q — potential silent fail-open bug", seg.name, resourceType),
				Severity:     "ERROR",
			}
		}

		// 3. Neither block nor attribute exists.
		return &model.SchemaDiagnostic{
			PolicyFile:   policyPath,
			Line:         seg.row,
			ResourceType: resourceType,
			InvalidPath:  seg.name,
			Message:      fmt.Sprintf("Attribute or block %q does not exist on resource %q — potential silent fail-open bug", seg.name, resourceType),
			Severity:     "ERROR",
		}
	}

	return nil
}

func deduplicateDiagnostics(diags []model.SchemaDiagnostic) []model.SchemaDiagnostic {
	seen := make(map[string]bool)
	result := make([]model.SchemaDiagnostic, 0, len(diags))
	for _, d := range diags {
		key := fmt.Sprintf("%d:%s:%s:%s", d.Line, d.ResourceType, d.InvalidPath, d.Message)
		if !seen[key] {
			seen[key] = true
			result = append(result, d)
		}
	}
	return result
}
