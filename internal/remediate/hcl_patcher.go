package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// Ensure Patcher implements model.RemediationGenerator at compile time.
var _ model.RemediationGenerator = (*Patcher)(nil)

// Patcher implements surgical HCL AST remediation and unified diff generation.
type Patcher struct {
	writeChanges bool
}

// Option configures a Patcher instance.
type Option func(*Patcher)

// WithWriteChanges configures whether GeneratePatches also writes patched HCL back to disk.
func WithWriteChanges(write bool) Option {
	return func(p *Patcher) {
		p.writeChanges = write
	}
}

// NewPatcher constructs a new Patcher with the provided options.
func NewPatcher(opts ...Option) *Patcher {
	p := &Patcher{}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	return p
}

// parsedTFFile holds an in-memory HCL AST and original normalized content for a single .tf file.
type parsedTFFile struct {
	relPath     string
	originalHCL string
	hclFile     *hclwrite.File
}

// GeneratePatches scans .tf files in tfDir, applies RemediationSpecs from violations to matching
// HCL resource blocks in-memory, and returns deterministic RemediationPatch objects with unified diffs.
// If WithWriteChanges(true) was configured, it also writes the patched files to disk via ApplyPatches.
func (p *Patcher) GeneratePatches(ctx context.Context, tfDir string, violations []model.PolicyViolation) ([]model.RemediationPatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if strings.TrimSpace(tfDir) == "" {
		return nil, fmt.Errorf("tfDir cannot be empty")
	}

	absDir, err := filepath.Abs(tfDir)
	if err != nil {
		return nil, fmt.Errorf("resolving tfDir %q: %w", tfDir, err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return nil, fmt.Errorf("accessing tfDir %q: %w", tfDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("tfDir %q is not a directory", tfDir)
	}

	if len(violations) == 0 {
		return []model.RemediationPatch{}, nil
	}

	// Validate candidate violations upfront so invalid attribute paths or unsupported SuggestedVal types fail fast.
	type actionableViolation struct {
		violation model.PolicyViolation
		resType   string
		resName   string
		ctyVal    cty.Value
	}

	var actionable []actionableViolation
	for _, v := range violations {
		if v.Remediation == nil || len(v.Remediation.AttributePath) == 0 {
			continue
		}
		for _, seg := range v.Remediation.AttributePath {
			if strings.TrimSpace(seg) == "" {
				return nil, fmt.Errorf("invalid empty attribute path segment for resource %q", v.ResourceAddress)
			}
		}
		ctyVal, err := toCtyValue(v.Remediation.SuggestedVal)
		if err != nil {
			return nil, fmt.Errorf("converting remediation value for resource %q: %w", v.ResourceAddress, err)
		}
		resType, resName := resolveResourceTypeAndName(v)
		if resType == "" || resName == "" {
			continue
		}
		actionable = append(actionable, actionableViolation{
			violation: v,
			resType:   resType,
			resName:   resName,
			ctyVal:    ctyVal,
		})
	}

	// Discover .tf files in tfDir while skipping symlinks.
	var tfFiles []string
	walkErr := filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if path == absDir {
			return nil
		}
		// Never follow or read symlinks.
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".tf") {
			tfFiles = append(tfFiles, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walking tfDir %q: %w", tfDir, walkErr)
	}

	sort.Strings(tfFiles)

	parsedFiles := make([]*parsedTFFile, 0, len(tfFiles))
	for _, fullPath := range tfFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		lstat, err := os.Lstat(fullPath)
		if err != nil {
			return nil, fmt.Errorf("lstat %q: %w", fullPath, err)
		}
		if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
			continue
		}

		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("reading HCL file %q: %w", fullPath, err)
		}

		normalized := bytes.ReplaceAll(rawBytes, []byte("\r\n"), []byte("\n"))
		rel, err := filepath.Rel(absDir, fullPath)
		if err != nil {
			return nil, fmt.Errorf("computing relative path for %q: %w", fullPath, err)
		}
		relSlash := filepath.ToSlash(rel)

		hclFile, diags := hclwrite.ParseConfig(normalized, relSlash, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return nil, fmt.Errorf("parsing HCL file %s: %s", relSlash, diags.Error())
		}

		parsedFiles = append(parsedFiles, &parsedTFFile{
			relPath:     relSlash,
			originalHCL: string(normalized),
			hclFile:     hclFile,
		})
	}

	patches := make([]model.RemediationPatch, 0, len(actionable))
	for _, av := range actionable {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		for _, pf := range parsedFiles {
			block := findResourceBlock(pf.hclFile.Body(), av.resType, av.resName)
			if block == nil {
				continue
			}

			if err := applyRemediationToBlock(block, av.violation.Remediation.AttributePath, av.ctyVal); err != nil {
				return nil, fmt.Errorf("applying remediation to %s in %s: %w", av.violation.ResourceAddress, pf.relPath, err)
			}

			formatted := hclwrite.Format(pf.hclFile.Bytes())
			normalizedPatched := string(bytes.ReplaceAll(formatted, []byte("\r\n"), []byte("\n")))
			unifiedDiff := computeUnifiedDiff(pf.relPath, pf.originalHCL, normalizedPatched)

			address := av.violation.ResourceAddress
			if address == "" {
				address = av.resType + "." + av.resName
			}

			patches = append(patches, model.RemediationPatch{
				FilePath:        pf.relPath,
				ResourceAddress: address,
				OriginalHCL:     pf.originalHCL,
				PatchedHCL:      normalizedPatched,
				UnifiedDiff:     unifiedDiff,
			})
			break
		}
	}

	if p.writeChanges && len(patches) > 0 {
		if err := p.ApplyPatches(ctx, tfDir, patches); err != nil {
			return nil, err
		}
	}

	return patches, nil
}

// ApplyPatches safely writes the PatchedHCL contents of each RemediationPatch back to disk under tfDir,
// enforcing path-traversal containment and rejecting symlink targets.
func (p *Patcher) ApplyPatches(ctx context.Context, tfDir string, patches []model.RemediationPatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if strings.TrimSpace(tfDir) == "" {
		return fmt.Errorf("tfDir cannot be empty")
	}

	absRoot, err := filepath.Abs(tfDir)
	if err != nil {
		return fmt.Errorf("resolving tfDir %q: %w", tfDir, err)
	}
	absRoot = filepath.Clean(absRoot)

	rootInfo, err := os.Stat(absRoot)
	if err != nil {
		return fmt.Errorf("accessing tfDir %q: %w", tfDir, err)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("tfDir %q is not a directory", tfDir)
	}

	if len(patches) == 0 {
		return nil
	}

	// Validate all patch paths first and deduplicate by FilePath preserving order and latest PatchedHCL.
	type fileWriteTarget struct {
		targetPath string
		patchedHCL string
	}
	var orderedFiles []string
	latestByRel := make(map[string]fileWriteTarget, len(patches))

	for _, patch := range patches {
		if err := ctx.Err(); err != nil {
			return err
		}

		rawRel := strings.TrimSpace(patch.FilePath)
		if rawRel == "" {
			return fmt.Errorf("remediation patch has empty file_path")
		}
		if filepath.IsAbs(rawRel) || strings.HasPrefix(rawRel, "/") || strings.HasPrefix(rawRel, `\`) {
			return fmt.Errorf("path traversal rejected: patch file_path %q must be relative to tfDir", patch.FilePath)
		}

		target := filepath.Clean(filepath.Join(absRoot, filepath.FromSlash(rawRel)))
		rel, err := filepath.Rel(absRoot, target)
		if err != nil {
			return fmt.Errorf("resolving patch target %q relative to %q: %w", patch.FilePath, absRoot, err)
		}
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("path traversal detected: %q escapes root directory %q", patch.FilePath, tfDir)
		}
		if !strings.HasPrefix(target, absRoot+string(filepath.Separator)) {
			return fmt.Errorf("path traversal detected: %q is outside root directory %q", patch.FilePath, tfDir)
		}

		normKey := filepath.ToSlash(rel)
		if _, exists := latestByRel[normKey]; !exists {
			orderedFiles = append(orderedFiles, normKey)
		}
		latestByRel[normKey] = fileWriteTarget{
			targetPath: target,
			patchedHCL: patch.PatchedHCL,
		}
	}

	for _, key := range orderedFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		item := latestByRel[key]

		lstat, err := os.Lstat(item.targetPath)
		if err != nil {
			return fmt.Errorf("checking target file %q: %w", key, err)
		}
		if lstat.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write to symlink target %q", key)
		}
		if !lstat.Mode().IsRegular() {
			return fmt.Errorf("refusing to write to non-regular file %q", key)
		}

		normalizedContent := strings.ReplaceAll(item.patchedHCL, "\r\n", "\n")
		if err := os.WriteFile(item.targetPath, []byte(normalizedContent), lstat.Mode().Perm()); err != nil {
			return fmt.Errorf("writing patched HCL to %q: %w", key, err)
		}
	}

	return nil
}

// resolveResourceTypeAndName extracts the resource type and resource name from a PolicyViolation,
// falling back to the last two dot-separated segments of ResourceAddress when needed.
func resolveResourceTypeAndName(v model.PolicyViolation) (string, string) {
	resType := strings.TrimSpace(v.ResourceType)
	resName := strings.TrimSpace(v.ResourceName)
	if resType != "" && resName != "" {
		return resType, resName
	}

	addr := strings.TrimSpace(v.ResourceAddress)
	if addr == "" {
		return resType, resName
	}

	parts := strings.Split(addr, ".")
	if len(parts) >= 2 {
		if resType == "" {
			resType = strings.TrimSpace(parts[len(parts)-2])
		}
		if resName == "" {
			resName = strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return resType, resName
}

// findResourceBlock searches the top-level HCL body for `resource "<resType>" "<resName>"`.
func findResourceBlock(body *hclwrite.Body, resType, resName string) *hclwrite.Block {
	for _, block := range body.Blocks() {
		if block.Type() != "resource" {
			continue
		}
		labels := block.Labels()
		if len(labels) == 2 && labels[0] == resType && labels[1] == resName {
			return block
		}
	}
	return nil
}

// applyRemediationToBlock traverses or creates intermediate nested HCL blocks for attrPath[0..N-2]
// and sets the leaf attribute attrPath[N-1] to val.
func applyRemediationToBlock(block *hclwrite.Block, attrPath []string, val cty.Value) error {
	if block == nil {
		return fmt.Errorf("target HCL block is nil")
	}
	if len(attrPath) == 0 {
		return fmt.Errorf("attribute path cannot be empty")
	}

	currBody := block.Body()
	for i := 0; i < len(attrPath)-1; i++ {
		blockName := strings.TrimSpace(attrPath[i])
		if blockName == "" {
			return fmt.Errorf("empty block name at path index %d", i)
		}
		nextBlock := currBody.FirstMatchingBlock(blockName, nil)
		if nextBlock == nil {
			nextBlock = currBody.AppendNewBlock(blockName, nil)
		}
		currBody = nextBlock.Body()
	}

	leafAttr := strings.TrimSpace(attrPath[len(attrPath)-1])
	if leafAttr == "" {
		return fmt.Errorf("empty leaf attribute name")
	}
	currBody.SetAttributeValue(leafAttr, val)
	return nil
}

// toCtyValue converts a Go value from RemediationSpec.SuggestedVal into a typed cty.Value.
func toCtyValue(val any) (cty.Value, error) {
	if val == nil {
		return cty.NilVal, fmt.Errorf("unsupported remediation suggested_value type <nil>")
	}

	switch v := val.(type) {
	case string:
		return cty.StringVal(v), nil
	case bool:
		return cty.BoolVal(v), nil
	case int:
		return cty.NumberIntVal(int64(v)), nil
	case int64:
		return cty.NumberIntVal(v), nil
	case float64:
		return cty.NumberFloatVal(v), nil
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return cty.NumberIntVal(i), nil
		}
		if f, err := v.Float64(); err == nil {
			return cty.NumberFloatVal(f), nil
		}
		return cty.NilVal, fmt.Errorf("invalid json.Number value %q", v.String())
	case []string:
		if len(v) == 0 {
			return cty.ListValEmpty(cty.String), nil
		}
		elems := make([]cty.Value, len(v))
		for i, s := range v {
			elems[i] = cty.StringVal(s)
		}
		return cty.TupleVal(elems), nil
	case []any:
		if len(v) == 0 {
			return cty.EmptyTupleVal, nil
		}
		elems := make([]cty.Value, len(v))
		for i, raw := range v {
			elemVal, err := toCtyValue(raw)
			if err != nil {
				return cty.NilVal, fmt.Errorf("element %d: %w", i, err)
			}
			elems[i] = elemVal
		}
		return cty.TupleVal(elems), nil
	case map[string]any:
		if len(v) == 0 {
			return cty.EmptyObjectVal, nil
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		attrMap := make(map[string]cty.Value, len(v))
		for _, k := range keys {
			elemVal, err := toCtyValue(v[k])
			if err != nil {
				return cty.NilVal, fmt.Errorf("key %q: %w", k, err)
			}
			attrMap[k] = elemVal
		}
		return cty.ObjectVal(attrMap), nil
	default:
		return cty.NilVal, fmt.Errorf("unsupported remediation suggested_value type %T", val)
	}
}

type editKind int

const (
	editEqual editKind = iota
	editDelete
	editInsert
)

type diffEdit struct {
	kind    editKind
	text    string
	oldLine int // 1-based line number in before
	newLine int // 1-based line number in after
}

// computeUnifiedDiff computes a deterministic, pure-Go unified diff with 3 lines of context.
func computeUnifiedDiff(relPath, before, after string) string {
	if before == after {
		return ""
	}

	oldLines := splitLines(before)
	newLines := splitLines(after)

	edits := computeLCSEdits(oldLines, newLines)
	if len(edits) == 0 {
		return ""
	}

	const contextLines = 3
	type hunkRange struct {
		start int
		end   int
	}

	var ranges []hunkRange
	for i, e := range edits {
		if e.kind == editEqual {
			continue
		}
		s := i - contextLines
		if s < 0 {
			s = 0
		}
		end := i + contextLines
		if end >= len(edits) {
			end = len(edits) - 1
		}
		if len(ranges) > 0 && s <= ranges[len(ranges)-1].end+1 {
			if end > ranges[len(ranges)-1].end {
				ranges[len(ranges)-1].end = end
			}
		} else {
			ranges = append(ranges, hunkRange{start: s, end: end})
		}
	}

	if len(ranges) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("--- a/%s\n", relPath))
	b.WriteString(fmt.Sprintf("+++ b/%s\n", relPath))

	for _, hr := range ranges {
		oldStart, oldCount := 0, 0
		newStart, newCount := 0, 0

		for idx := hr.start; idx <= hr.end; idx++ {
			ed := edits[idx]
			switch ed.kind {
			case editEqual:
				if oldStart == 0 {
					oldStart = ed.oldLine
				}
				if newStart == 0 {
					newStart = ed.newLine
				}
				oldCount++
				newCount++
			case editDelete:
				if oldStart == 0 {
					oldStart = ed.oldLine
				}
				oldCount++
			case editInsert:
				if newStart == 0 {
					newStart = ed.newLine
				}
				newCount++
			}
		}

		if oldStart == 0 && len(oldLines) > 0 {
			oldStart = 1
		}
		if newStart == 0 && len(newLines) > 0 {
			newStart = 1
		}

		b.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount))
		for idx := hr.start; idx <= hr.end; idx++ {
			ed := edits[idx]
			switch ed.kind {
			case editEqual:
				b.WriteString(" " + ed.text + "\n")
			case editDelete:
				b.WriteString("-" + ed.text + "\n")
			case editInsert:
				b.WriteString("+" + ed.text + "\n")
			}
		}
	}

	return b.String()
}

// splitLines splits a normalized LF string into lines without a trailing empty element from the final newline.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	trimmed := strings.TrimSuffix(s, "\n")
	if trimmed == "" {
		return []string{""}
	}
	return strings.Split(trimmed, "\n")
}

// computeLCSEdits computes the Longest Common Subsequence line diff between oldLines and newLines.
func computeLCSEdits(oldLines, newLines []string) []diffEdit {
	m := len(oldLines)
	n := len(newLines)

	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				dp[i][j] = 1 + dp[i+1][j+1]
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	edits := make([]diffEdit, 0, m+n)
	i, j := 0, 0
	for i < m && j < n {
		if oldLines[i] == newLines[j] {
			edits = append(edits, diffEdit{
				kind:    editEqual,
				text:    oldLines[i],
				oldLine: i + 1,
				newLine: j + 1,
			})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			edits = append(edits, diffEdit{
				kind:    editDelete,
				text:    oldLines[i],
				oldLine: i + 1,
			})
			i++
		} else {
			edits = append(edits, diffEdit{
				kind:    editInsert,
				text:    newLines[j],
				newLine: j + 1,
			})
			j++
		}
	}
	for i < m {
		edits = append(edits, diffEdit{
			kind:    editDelete,
			text:    oldLines[i],
			oldLine: i + 1,
		})
		i++
	}
	for j < n {
		edits = append(edits, diffEdit{
			kind:    editInsert,
			text:    newLines[j],
			newLine: j + 1,
		})
		j++
	}

	return edits
}
