package verifier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/justr00t/tf-sim/internal/engine"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
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

type parsedModule struct {
	path string
	mod  *ast.Module
}

// VerifyPolicy performs static analysis on a single Rego policy against the provider schema.
func (v *Verifier) VerifyPolicy(ctx context.Context, policyPath string, schemas model.ProviderSchemaMap) (*model.VerificationResult, error) {
	return v.VerifyPolicies(ctx, []string{policyPath}, schemas)
}

// VerifyPolicies performs static analysis on one or more Rego policy files against the provider schema.
func (v *Verifier) VerifyPolicies(ctx context.Context, policyPaths []string, schemas model.ProviderSchemaMap) (*model.VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(policyPaths) == 0 {
		return nil, fmt.Errorf("at least one policy path must be provided")
	}

	joinedPolicyPath := strings.Join(policyPaths, ", ")
	orderedModules := make([]parsedModule, 0, len(policyPaths))
	modulesMap := make(map[string]*ast.Module, len(policyPaths))
	var parseDiags []model.SchemaDiagnostic

	for _, p := range policyPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat policy file %s: %w", p, err)
		}
		if fi.IsDir() {
			return nil, fmt.Errorf("stat policy file %s: is a directory", p)
		}

		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read policy file %s: %w", p, err)
		}

		mod, err := ast.ParseModuleWithOpts(p, string(content), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			if astErrors, ok := err.(ast.Errors); ok {
				for _, e := range astErrors {
					row := 1
					if e.Location != nil && e.Location.Row > 0 {
						row = e.Location.Row
					}
					parseDiags = append(parseDiags, model.SchemaDiagnostic{
						PolicyFile: p,
						Line:       row,
						Message:    e.Message,
						Severity:   "ERROR",
					})
				}
			} else {
				parseDiags = append(parseDiags, model.SchemaDiagnostic{
					PolicyFile: p,
					Line:       1,
					Message:    err.Error(),
					Severity:   "ERROR",
				})
			}
			continue
		}

		orderedModules = append(orderedModules, parsedModule{path: p, mod: mod})
		modulesMap[p] = mod
	}

	if len(parseDiags) > 0 {
		return &model.VerificationResult{
			PolicyPath:  joinedPolicyPath,
			PackageName: "",
			Valid:       false,
			Diagnostics: parseDiags,
		}, nil
	}

	var uniquePkgs []string
	seenPkg := make(map[string]bool)
	for _, pm := range orderedModules {
		if pm.mod.Package != nil && pm.mod.Package.Path != nil {
			pkg := strings.TrimPrefix(pm.mod.Package.Path.String(), "data.")
			if pkg != "" && !seenPkg[pkg] {
				seenPkg[pkg] = true
				uniquePkgs = append(uniquePkgs, pkg)
			}
		}
	}
	pkgName := strings.Join(uniquePkgs, ", ")

	compiler := ast.NewCompiler()
	compiler.Compile(modulesMap)
	if compiler.Failed() {
		var diags []model.SchemaDiagnostic
		for _, e := range compiler.Errors {
			row := 1
			file := policyPaths[0]
			if e.Location != nil {
				if e.Location.Row > 0 {
					row = e.Location.Row
				}
				if e.Location.File != "" {
					file = e.Location.File
				}
			}
			diags = append(diags, model.SchemaDiagnostic{
				PolicyFile: file,
				Line:       row,
				Message:    e.Message,
				Severity:   "ERROR",
			})
		}
		return &model.VerificationResult{
			PolicyPath:  joinedPolicyPath,
			PackageName: pkgName,
			Valid:       false,
			Diagnostics: diags,
		}, nil
	}

	var diagnostics []model.SchemaDiagnostic

	hasEntrypoint := false
	for _, pm := range orderedModules {
		for _, r := range pm.mod.Rules {
			headName := r.Head.Name.String()
			if headName == "deny" || headName == "violation" {
				hasEntrypoint = true
				break
			}
		}
		if hasEntrypoint {
			break
		}
	}
	if !hasEntrypoint {
		row := 1
		firstMod := orderedModules[0].mod
		if firstMod.Package != nil && firstMod.Package.Location != nil {
			row = firstMod.Package.Location.Row
		}
		diagnostics = append(diagnostics, model.SchemaDiagnostic{
			PolicyFile: orderedModules[0].path,
			Line:       row,
			Message:    "policy must define at least one 'deny' or 'violation' rule",
			Severity:   "ERROR",
		})
	}

	if len(schemas) == 0 {
		return &model.VerificationResult{
			PolicyPath:  joinedPolicyPath,
			PackageName: pkgName,
			Valid:       len(diagnostics) == 0,
			Diagnostics: diagnostics,
		}, nil
	}

	// Index rules across all policy modules in deterministic order.
	var allRules []*ast.Rule
	ruleFile := make(map[*ast.Rule]string)
	rulesByName := make(map[string][]*ast.Rule)
	for _, pm := range orderedModules {
		for _, r := range pm.mod.Rules {
			allRules = append(allRules, r)
			ruleFile[r] = pm.path
			name := r.Head.Name.String()
			rulesByName[name] = append(rulesByName[name], r)
		}
	}

	// Map each rule to sets of parameter bindings (paramName -> resourceType).
	ruleBindings := make(map[*ast.Rule][]map[string]string)

	// Step 1: Scan entrypoint and top-level rules for resource types and helper calls.
	for _, r := range allRules {
		headName := r.Head.Name.String()
		isEntrypoint := (headName == "deny" || headName == "violation")
		isParamless := len(r.Head.Args) == 0

		if !isEntrypoint && !isParamless {
			continue
		}

		localBindingSets, typeDiags := scanRuleResourceTypes(r, schemas, ruleFile[r])
		diagnostics = append(diagnostics, typeDiags...)

		ruleBindings[r] = append(ruleBindings[r], localBindingSets...)

		// Check for helper rule calls in this rule for each binding set.
		for _, lt := range localBindingSets {
			propagateHelperCalls(r, lt, rulesByName, ruleBindings)
		}
	}

	// Step 2: Validate each rule against provider schemas using its originating file path.
	for _, r := range allRules {
		bindingSets := ruleBindings[r]
		if len(bindingSets) == 0 {
			// If not called by entrypoint, still scan its own local resource types.
			localBindingSets, typeDiags := scanRuleResourceTypes(r, schemas, ruleFile[r])
			diagnostics = append(diagnostics, typeDiags...)
			bindingSets = localBindingSets
		}

		for _, vt := range bindingSets {
			ruleDiags := validateRuleBody(r, vt, schemas, ruleFile[r])
			diagnostics = append(diagnostics, ruleDiags...)
		}
	}

	// Deduplicate diagnostics
	diagnostics = deduplicateDiagnostics(diagnostics)

	// Deterministic sort: PolicyFile ASC, Line ASC, ResourceType ASC, InvalidPath ASC
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].PolicyFile != diagnostics[j].PolicyFile {
			return diagnostics[i].PolicyFile < diagnostics[j].PolicyFile
		}
		if diagnostics[i].Line != diagnostics[j].Line {
			return diagnostics[i].Line < diagnostics[j].Line
		}
		if diagnostics[i].ResourceType != diagnostics[j].ResourceType {
			return diagnostics[i].ResourceType < diagnostics[j].ResourceType
		}
		return diagnostics[i].InvalidPath < diagnostics[j].InvalidPath
	})

	return &model.VerificationResult{
		PolicyPath:  joinedPolicyPath,
		PackageName: pkgName,
		Valid:       len(diagnostics) == 0,
		Diagnostics: diagnostics,
	}, nil
}

// scanRuleResourceTypes discovers resource types bound in rule expressions
// (e.g. rc.type == "aws_s3_bucket" or rc.type in ["aws_s3_bucket", "azurerm_storage_account"]).
func scanRuleResourceTypes(r *ast.Rule, schemas model.ProviderSchemaMap, policyPath string) ([]map[string]string, []model.SchemaDiagnostic) {
	varTypeList := make(map[string][]string)
	var diags []model.SchemaDiagnostic

	addVarType := func(varName, resType string) {
		for _, existing := range varTypeList[varName] {
			if existing == resType {
				return
			}
		}
		varTypeList[varName] = append(varTypeList[varName], resType)
	}

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
					addVarType(varName, resType)
				}
			}
		}

		// Case 2: rc.type in ["resource_type", ...] or rc.type in {"resource_type", ...} (internal.member_2)
		if op == "internal.member_2" && len(terms) == 3 {
			if ref, ok := terms[1].Value.(ast.Ref); ok && isTypeRef(ref) {
				varName := getRootVar(ref)
				row := 1
				if terms[1].Location != nil {
					row = terms[1].Location.Row
				}
				var elems []*ast.Term
				switch col := terms[2].Value.(type) {
				case *ast.Array:
					for i := 0; i < col.Len(); i++ {
						elems = append(elems, col.Elem(i))
					}
				case ast.Set:
					elems = col.Slice()
				}
				for _, elem := range elems {
					if str, ok := elem.Value.(ast.String); ok {
						resType := string(str)
						elemRow := row
						if elem.Location != nil {
							elemRow = elem.Location.Row
						}
						if _, ok := schemas[resType]; !ok {
							diags = append(diags, model.SchemaDiagnostic{
								PolicyFile:   policyPath,
								Line:         elemRow,
								ResourceType: resType,
								Message:      fmt.Sprintf("Unknown resource type %q in provider schema", resType),
								Severity:     "ERROR",
							})
						} else {
							addVarType(varName, resType)
						}
					}
				}
			}
		}
	}

	if len(varTypeList) == 0 {
		return []map[string]string{{}}, diags
	}

	varNames := make([]string, 0, len(varTypeList))
	for k := range varTypeList {
		varNames = append(varNames, k)
	}
	sort.Strings(varNames)

	bindingSets := []map[string]string{{}}
	for _, varName := range varNames {
		types := varTypeList[varName]
		next := make([]map[string]string, 0, len(bindingSets)*len(types))
		for _, existing := range bindingSets {
			for _, rt := range types {
				clone := make(map[string]string, len(existing)+2)
				for k, v := range existing {
					clone[k] = v
				}
				clone[varName] = rt
				if varName == "input" || strings.HasPrefix(varName, "input.") {
					clone["input"] = rt
				}
				next = append(next, clone)
			}
		}
		bindingSets = next
	}

	return bindingSets, diags
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

// propagateHelperCalls discovers calls to other rules in the policy (including across files/packages)
// and propagates parameter resource types.
func propagateHelperCalls(r *ast.Rule, localTypes map[string]string, rulesByName map[string][]*ast.Rule, ruleBindings map[*ast.Rule][]map[string]string) {
	for _, expr := range r.Body {
		callSlices := extractExprCallSlices(expr)
		for _, terms := range callSlices {
			if len(terms) < 2 {
				continue
			}

			fnName := extractCalledRuleName(terms[0])
			if fnName == "" {
				continue
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
					if v, ok := tr.Head.Args[paramIdx].Value.(ast.Var); ok {
						paramName = string(v)
					}
					argVar := ""
					if v, ok := terms[argIdx].Value.(ast.Var); ok {
						argVar = string(v)
					}
					if resType, ok := localTypes[argVar]; ok {
						trBindings[paramName] = resType
					}
				}
				if len(trBindings) > 0 && !hasBindingSet(ruleBindings[tr], trBindings) {
					ruleBindings[tr] = append(ruleBindings[tr], trBindings)
					// Propagate recursively
					propagateHelperCalls(tr, trBindings, rulesByName, ruleBindings)
				}
			}
		}
	}
}

func extractExprCallSlices(expr *ast.Expr) [][]*ast.Term {
	var result [][]*ast.Term
	if terms, ok := expr.Terms.([]*ast.Term); ok && len(terms) >= 2 {
		result = append(result, terms)
		for _, t := range terms[1:] {
			if t != nil {
				if call, ok := t.Value.(ast.Call); ok && len(call) >= 2 {
					result = append(result, []*ast.Term(call))
				}
			}
		}
	}
	return result
}

func extractCalledRuleName(fnTerm *ast.Term) string {
	if fnTerm == nil || fnTerm.Value == nil {
		return ""
	}
	switch val := fnTerm.Value.(type) {
	case ast.Var:
		return string(val)
	case ast.Ref:
		if len(val) == 0 {
			return ""
		}
		last := val[len(val)-1]
		if v, ok := last.Value.(ast.Var); ok {
			return string(v)
		}
		if s, ok := last.Value.(ast.String); ok {
			return string(s)
		}
		return last.String()
	}
	return ""
}

func hasBindingSet(existingSets []map[string]string, candidate map[string]string) bool {
	for _, existing := range existingSets {
		if len(existing) != len(candidate) {
			continue
		}
		match := true
		for k, v := range candidate {
			if existing[k] != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// validateRuleBody performs AST ref extraction, remediation.attribute_path extraction, and schema cross-referencing.
func validateRuleBody(r *ast.Rule, varTypes map[string]string, schemas model.ProviderSchemaMap, policyPath string) []model.SchemaDiagnostic {
	var diags []model.SchemaDiagnostic
	varBindings := make(map[string]intermediateBinding)

	localVarTypes := make(map[string]string, len(varTypes)+1)
	for k, v := range varTypes {
		localVarTypes[k] = v
	}

	// In single-resource rules, if only one resource type is known, bind "input" as well.
	if len(localVarTypes) == 1 {
		for _, rt := range localVarTypes {
			localVarTypes["input"] = rt
			break
		}
	}

	for _, expr := range r.Body {
		// 1. Discover intermediate variable bindings in this expression.
		bindVar, sourceRef := extractBinding(expr)
		if bindVar != "" && len(sourceRef) > 0 {
			resType, prefix := resolveRefPrefix(sourceRef, localVarTypes, varBindings)
			if resType != "" {
				varBindings[bindVar] = intermediateBinding{
					resourceType: resType,
					path:         prefix,
				}
			}
		}

		// 2. Validate all refs in the expression.
		ast.WalkRefs(expr, func(ref ast.Ref) bool {
			resType, segments := resolveRefPath(ref, localVarTypes, varBindings)
			if resType == "" || len(segments) == 0 {
				return false
			}

			if d := validatePathAgainstSchema(policyPath, resType, segments, schemas); d != nil {
				diags = append(diags, *d)
			}
			return false
		})
	}

	// 3. Validate remediation.attribute_path arrays in rule head and body.
	remDiags := validateRuleRemediationPaths(r, localVarTypes, schemas, policyPath)
	diags = append(diags, remDiags...)

	return diags
}

// validateRuleRemediationPaths extracts and validates remediation.attribute_path arrays across r.Head and r.Body.
func validateRuleRemediationPaths(r *ast.Rule, localVarTypes map[string]string, schemas model.ProviderSchemaMap, policyPath string) []model.SchemaDiagnostic {
	seenTypes := make(map[string]bool)
	var ruleResourceTypes []string
	for _, rt := range localVarTypes {
		if rt != "" && !seenTypes[rt] {
			seenTypes[rt] = true
			ruleResourceTypes = append(ruleResourceTypes, rt)
		}
	}
	sort.Strings(ruleResourceTypes)

	localTerms := extractLocalTermAssignments(r.Body)

	var objects []ast.Object
	collectObjects := func(obj ast.Object) {
		objects = append(objects, obj)
	}

	if r.Head != nil {
		walkTerm(r.Head.Key, collectObjects)
		walkTerm(r.Head.Value, collectObjects)
		for _, arg := range r.Head.Args {
			walkTerm(arg, collectObjects)
		}
	}
	for _, expr := range r.Body {
		switch t := expr.Terms.(type) {
		case *ast.Term:
			walkTerm(t, collectObjects)
		case []*ast.Term:
			for _, term := range t {
				walkTerm(term, collectObjects)
			}
		case *ast.SomeDecl:
			for _, sym := range t.Symbols {
				walkTerm(sym, collectObjects)
			}
		}
	}

	var diags []model.SchemaDiagnostic
	validatedRemObjects := make(map[ast.Object]bool)

	// Pass 1: Validate objects containing a "remediation" key (violation objects).
	for _, obj := range objects {
		remKeyTerm, remValTerm := objectKeyTerm(obj, "remediation")
		if remValTerm == nil {
			continue
		}

		resolvedRem := resolveTerm(remValTerm, localTerms)
		if resolvedRem == nil {
			continue
		}
		remObj, ok := resolvedRem.Value.(ast.Object)
		if !ok {
			continue
		}
		validatedRemObjects[remObj] = true

		targetTypes := resolveViolationResourceTypes(obj, localTerms, localVarTypes, ruleResourceTypes, schemas)
		if len(targetTypes) == 0 {
			continue
		}

		attrKeyTerm, attrValTerm := objectKeyTerm(remObj, "attribute_path")
		if attrValTerm == nil {
			continue
		}

		fallbackRow := termLine(attrValTerm, termLine(attrKeyTerm, termLine(remValTerm, termLine(remKeyTerm, 1))))
		resolvedAttrPath := resolveTerm(attrValTerm, localTerms)
		if resolvedAttrPath == nil {
			continue
		}
		arr, ok := resolvedAttrPath.Value.(*ast.Array)
		if !ok {
			continue
		}

		segments := extractArraySegments(arr, localTerms, termLine(resolvedAttrPath, fallbackRow))
		if len(segments) == 0 {
			continue
		}

		for _, rt := range targetTypes {
			if d := validateRemediationPathAgainstSchema(policyPath, rt, segments, schemas); d != nil {
				diags = append(diags, *d)
			}
		}
	}

	// Pass 2: Validate any standalone remediation objects (containing "attribute_path") not already validated in Pass 1.
	if len(ruleResourceTypes) > 0 {
		for _, obj := range objects {
			if validatedRemObjects[obj] {
				continue
			}
			attrKeyTerm, attrValTerm := objectKeyTerm(obj, "attribute_path")
			if attrValTerm == nil {
				continue
			}

			fallbackRow := termLine(attrValTerm, termLine(attrKeyTerm, 1))
			resolvedAttrPath := resolveTerm(attrValTerm, localTerms)
			if resolvedAttrPath == nil {
				continue
			}
			arr, ok := resolvedAttrPath.Value.(*ast.Array)
			if !ok {
				continue
			}

			segments := extractArraySegments(arr, localTerms, termLine(resolvedAttrPath, fallbackRow))
			if len(segments) == 0 {
				continue
			}

			for _, rt := range ruleResourceTypes {
				if d := validateRemediationPathAgainstSchema(policyPath, rt, segments, schemas); d != nil {
					diags = append(diags, *d)
				}
			}
		}
	}

	return diags
}

func resolveViolationResourceTypes(violationObj ast.Object, localTerms map[string]*ast.Term, localVarTypes map[string]string, fallbackTypes []string, schemas model.ProviderSchemaMap) []string {
	_, rtValTerm := objectKeyTerm(violationObj, "resource_type")
	if rtValTerm != nil {
		resolvedRT := resolveTerm(rtValTerm, localTerms)
		if resolvedRT != nil {
			switch val := resolvedRT.Value.(type) {
			case ast.String:
				rt := string(val)
				if _, ok := schemas[rt]; ok {
					return []string{rt}
				}
			case ast.Ref:
				root := getRootVar(val)
				if rt, ok := localVarTypes[root]; ok && rt != "" {
					return []string{rt}
				}
			}
		}
	}
	return fallbackTypes
}

func extractLocalTermAssignments(body ast.Body) map[string]*ast.Term {
	localTerms := make(map[string]*ast.Term)
	for _, expr := range body {
		terms, ok := expr.Terms.([]*ast.Term)
		if !ok || len(terms) != 3 {
			continue
		}
		op := expr.Operator().String()
		if op != "assign" && op != "equal" && op != "eq" && op != "=" {
			continue
		}
		lhs, rhs := terms[1], terms[2]
		if v, isVar := lhs.Value.(ast.Var); isVar {
			if _, rhsIsVar := rhs.Value.(ast.Var); !rhsIsVar {
				localTerms[string(v)] = rhs
			} else if _, exists := localTerms[string(v)]; !exists {
				localTerms[string(v)] = rhs
			}
		}
		if v, isVar := rhs.Value.(ast.Var); isVar {
			if _, lhsIsVar := lhs.Value.(ast.Var); !lhsIsVar {
				localTerms[string(v)] = lhs
			} else if _, exists := localTerms[string(v)]; !exists {
				localTerms[string(v)] = lhs
			}
		}
	}
	return localTerms
}

func resolveTerm(term *ast.Term, localTerms map[string]*ast.Term) *ast.Term {
	curr := term
	for depth := 0; depth < 8 && curr != nil; depth++ {
		switch val := curr.Value.(type) {
		case ast.Var:
			next, ok := localTerms[string(val)]
			if !ok || next == curr {
				return curr
			}
			curr = next
		case ast.Ref:
			if len(val) == 1 {
				if v, ok := val[0].Value.(ast.Var); ok {
					next, exists := localTerms[string(v)]
					if exists && next != curr {
						curr = next
						continue
					}
				}
			}
			return curr
		default:
			return curr
		}
	}
	return curr
}

func walkTerm(term *ast.Term, visitObj func(ast.Object)) {
	if term == nil || term.Value == nil {
		return
	}
	switch val := term.Value.(type) {
	case ast.Object:
		visitObj(val)
		val.Foreach(func(k, v *ast.Term) {
			walkTerm(k, visitObj)
			walkTerm(v, visitObj)
		})
	case *ast.Array:
		for i := 0; i < val.Len(); i++ {
			walkTerm(val.Elem(i), visitObj)
		}
	case ast.Set:
		for _, elem := range val.Slice() {
			walkTerm(elem, visitObj)
		}
	case ast.Call:
		for _, elem := range val {
			walkTerm(elem, visitObj)
		}
	}
}

func objectKeyTerm(obj ast.Object, key string) (*ast.Term, *ast.Term) {
	var foundK, foundV *ast.Term
	obj.Foreach(func(k, v *ast.Term) {
		if foundV != nil {
			return
		}
		if s, ok := k.Value.(ast.String); ok && string(s) == key {
			foundK = k
			foundV = v
		}
	})
	return foundK, foundV
}

func termLine(t *ast.Term, fallback int) int {
	if t != nil && t.Location != nil && t.Location.Row > 0 {
		return t.Location.Row
	}
	return fallback
}

func extractArraySegments(arr *ast.Array, localTerms map[string]*ast.Term, fallbackRow int) []segmentInfo {
	segments := make([]segmentInfo, 0, arr.Len())
	for i := 0; i < arr.Len(); i++ {
		rawElem := arr.Elem(i)
		row := termLine(rawElem, fallbackRow)
		resolvedElem := resolveTerm(rawElem, localTerms)
		if resolvedElem == nil {
			break
		}
		row = termLine(resolvedElem, row)
		str, ok := resolvedElem.Value.(ast.String)
		if !ok {
			break
		}
		segments = append(segments, segmentInfo{
			name: string(str),
			row:  row,
		})
	}
	return segments
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
		if attr, ok := curr.Attributes[seg.name]; ok {
			if isFinal {
				return nil
			}
			// If not final, can we descend into a block with the same name?
			if nb, ok := curr.NestedBlocks[seg.name]; ok {
				curr = nb
				continue
			}
			// Allow arbitrary key access beneath free-form map, object, or dynamic attributes.
			if attr.Type == "map" || attr.Type == "object" || attr.Type == "dynamic" {
				return nil
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

// validateRemediationPathAgainstSchema validates a remediation.attribute_path slice against the resource schema,
// ensuring all segments exist and the final segment resolves to an attribute (or map/object/dynamic key) rather than a nested block.
func validateRemediationPathAgainstSchema(policyPath string, resourceType string, segments []segmentInfo, schemas model.ProviderSchemaMap) *model.SchemaDiagnostic {
	if len(segments) == 0 {
		return nil
	}
	if d := validatePathAgainstSchema(policyPath, resourceType, segments, schemas); d != nil {
		return d
	}

	// Ensure the final segment is an Attribute (or beneath a map/object/dynamic attribute),
	// not solely a NestedBlock, because hcl_patcher sets the final segment via SetAttributeValue.
	curr, ok := schemas[resourceType]
	if !ok {
		return nil
	}
	for i, seg := range segments {
		isFinal := (i == len(segments)-1)
		if isFinal {
			if _, isAttr := curr.Attributes[seg.name]; isAttr {
				return nil
			}
			if _, isBlock := curr.NestedBlocks[seg.name]; isBlock {
				return &model.SchemaDiagnostic{
					PolicyFile:   policyPath,
					Line:         seg.row,
					ResourceType: resourceType,
					InvalidPath:  seg.name,
					Message:      fmt.Sprintf("Remediation target %q is a nested block, not an attribute on resource %q", seg.name, resourceType),
					Severity:     "ERROR",
				}
			}
			return nil
		}

		if nb, ok := curr.NestedBlocks[seg.name]; ok {
			curr = nb
			continue
		}
		if attr, ok := curr.Attributes[seg.name]; ok {
			if attr.Type == "map" || attr.Type == "object" || attr.Type == "dynamic" {
				return nil
			}
		}
	}
	return nil
}

func deduplicateDiagnostics(diags []model.SchemaDiagnostic) []model.SchemaDiagnostic {
	seen := make(map[string]bool)
	result := make([]model.SchemaDiagnostic, 0, len(diags))
	for _, d := range diags {
		key := fmt.Sprintf("%s:%d:%s:%s:%s", d.PolicyFile, d.Line, d.ResourceType, d.InvalidPath, d.Message)
		if !seen[key] {
			seen[key] = true
			result = append(result, d)
		}
	}
	return result
}

type fixtureSnapshot struct {
	displayPath string
	snapshot    *model.PlanSnapshot
}

// VerifyPoliciesWithFixtures performs static AST and provider schema analysis on one or more Rego policies,
// and additionally evaluates optional pass-fixture plans (expecting 0 violations) and fail-fixture plans
// (expecting >= 1 violation).
func (v *Verifier) VerifyPoliciesWithFixtures(
	ctx context.Context,
	policyPaths []string,
	schemas model.ProviderSchemaMap,
	passFixturePaths []string,
	failFixturePaths []string,
) (*model.VerificationResult, error) {
	res, err := v.VerifyPolicies(ctx, policyPaths, schemas)
	if err != nil {
		return nil, err
	}

	cleanedPass := cleanNonEmptyStrings(passFixturePaths)
	cleanedFail := cleanNonEmptyStrings(failFixturePaths)
	if len(cleanedPass) == 0 && len(cleanedFail) == 0 {
		return res, nil
	}

	passSnaps, err := loadFixtureSnapshots(ctx, cleanedPass)
	if err != nil {
		return nil, err
	}
	failSnaps, err := loadFixtureSnapshots(ctx, cleanedFail)
	if err != nil {
		return nil, err
	}

	// If the policy failed Rego syntax parsing, AST compilation, or lacks a deny/violation entrypoint,
	// return the static diagnostics directly rather than failing with a runtime evaluator compilation error.
	if !canEvaluatePolicy(res) {
		return res, nil
	}

	ev := engine.NewEvaluator()
	policyFileLabel := policyPaths[0]
	var fixtureDiags []model.SchemaDiagnostic

	for _, fs := range passSnaps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evalRes, err := ev.EvaluatePlan(ctx, policyPaths, fs.snapshot)
		if err != nil {
			return nil, fmt.Errorf("evaluating pass fixture %q: %w", fs.displayPath, err)
		}
		if len(evalRes.Violations) > 0 {
			ruleSet := make(map[string]bool)
			var ruleIDs []string
			for _, viol := range evalRes.Violations {
				id := strings.TrimSpace(viol.RuleID)
				if id == "" {
					id = "unknown"
				}
				if !ruleSet[id] {
					ruleSet[id] = true
					ruleIDs = append(ruleIDs, id)
				}
			}
			sort.Strings(ruleIDs)
			fixtureDiags = append(fixtureDiags, model.SchemaDiagnostic{
				PolicyFile:   policyFileLabel,
				Line:         1,
				ResourceType: "fixture:pass",
				InvalidPath:  fs.displayPath,
				Message:      fmt.Sprintf("Pass fixture %q failed: expected 0 violations, got %d (%s)", fs.displayPath, len(evalRes.Violations), strings.Join(ruleIDs, ", ")),
				Severity:     "ERROR",
			})
		}
	}

	for _, fs := range failSnaps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evalRes, err := ev.EvaluatePlan(ctx, policyPaths, fs.snapshot)
		if err != nil {
			return nil, fmt.Errorf("evaluating fail fixture %q: %w", fs.displayPath, err)
		}
		if len(evalRes.Violations) == 0 {
			fixtureDiags = append(fixtureDiags, model.SchemaDiagnostic{
				PolicyFile:   policyFileLabel,
				Line:         1,
				ResourceType: "fixture:fail",
				InvalidPath:  fs.displayPath,
				Message:      fmt.Sprintf("Fail fixture %q passed unexpectedly: expected at least 1 violation, got 0 — potential silent fail-open bug", fs.displayPath),
				Severity:     "ERROR",
			})
		}
	}

	if len(fixtureDiags) > 0 {
		res.Diagnostics = append(res.Diagnostics, fixtureDiags...)
		res.Diagnostics = deduplicateDiagnostics(res.Diagnostics)
		sort.Slice(res.Diagnostics, func(i, j int) bool {
			if res.Diagnostics[i].PolicyFile != res.Diagnostics[j].PolicyFile {
				return res.Diagnostics[i].PolicyFile < res.Diagnostics[j].PolicyFile
			}
			if res.Diagnostics[i].Line != res.Diagnostics[j].Line {
				return res.Diagnostics[i].Line < res.Diagnostics[j].Line
			}
			if res.Diagnostics[i].ResourceType != res.Diagnostics[j].ResourceType {
				return res.Diagnostics[i].ResourceType < res.Diagnostics[j].ResourceType
			}
			return res.Diagnostics[i].InvalidPath < res.Diagnostics[j].InvalidPath
		})
		res.Valid = false
	}

	return res, nil
}

func cleanNonEmptyStrings(items []string) []string {
	var out []string
	for _, item := range items {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func canEvaluatePolicy(res *model.VerificationResult) bool {
	if res == nil || strings.TrimSpace(res.PackageName) == "" {
		return false
	}
	for _, d := range res.Diagnostics {
		if d.ResourceType == "" {
			return false
		}
	}
	return true
}

func loadFixtureSnapshots(ctx context.Context, paths []string) ([]fixtureSnapshot, error) {
	p := parser.NewParser()
	var results []fixtureSnapshot

	for _, rawPath := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lfi, err := os.Lstat(rawPath)
		if err != nil {
			return nil, fmt.Errorf("stat fixture path %q: %w", rawPath, err)
		}
		if lfi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("fixture path %q is a symlink", rawPath)
		}

		if !lfi.IsDir() {
			base := filepath.Base(rawPath)
			repoName := strings.TrimSuffix(base, filepath.Ext(base))
			snap, err := p.ParsePlanFile(ctx, rawPath, repoName)
			if err != nil {
				return nil, fmt.Errorf("parsing fixture plan %q: %w", rawPath, err)
			}
			results = append(results, fixtureSnapshot{
				displayPath: filepath.ToSlash(rawPath),
				snapshot:    snap,
			})
			continue
		}

		var jsonFiles []string
		err = filepath.WalkDir(rawPath, func(walkPath string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(walkPath), ".json") {
				jsonFiles = append(jsonFiles, walkPath)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking fixture directory %q: %w", rawPath, err)
		}
		if len(jsonFiles) == 0 {
			return nil, fmt.Errorf("fixture directory %q contains no .json plan files", rawPath)
		}
		sort.Strings(jsonFiles)

		for _, jf := range jsonFiles {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			base := filepath.Base(jf)
			repoName := strings.TrimSuffix(base, filepath.Ext(base))
			snap, err := p.ParsePlanFile(ctx, jf, repoName)
			if err != nil {
				return nil, fmt.Errorf("parsing fixture plan %q: %w", jf, err)
			}
			results = append(results, fixtureSnapshot{
				displayPath: filepath.ToSlash(jf),
				snapshot:    snap,
			})
		}
	}

	return results, nil
}
