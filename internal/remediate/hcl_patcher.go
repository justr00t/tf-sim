package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/zclconf/go-cty/cty"
)

const maxTFFileBytes = 4 * 1024 * 1024

// Ensure Patcher implements model.RemediationGenerator and model.DetailedRemediationGenerator at compile time.
var _ model.RemediationGenerator = (*Patcher)(nil)
var _ model.DetailedRemediationGenerator = (*Patcher)(nil)

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
	rep, err := p.GenerateRemediationReport(ctx, tfDir, violations)
	if err != nil {
		return nil, err
	}
	return rep.Patches, nil
}

// GenerateRemediationReport scans .tf files in tfDir and accounts for every PolicyViolation as either
// a surgical HCL patch (Patches) or a structured manual-review diagnostic (Skipped).
func (p *Patcher) GenerateRemediationReport(ctx context.Context, tfDir string, violations []model.PolicyViolation) (*model.RemediationReport, error) {
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
	absDir = filepath.Clean(absDir)

	info, err := os.Stat(absDir)
	if err != nil {
		return nil, fmt.Errorf("accessing tfDir %q: %w", tfDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("tfDir %q is not a directory", tfDir)
	}

	rep := &model.RemediationReport{
		Patches: []model.RemediationPatch{},
		Skipped: []model.RemediationDiagnostic{},
		Summary: model.RemediationSummary{
			TotalViolations: len(violations),
			ByReason:        map[string]int{},
		},
	}

	if len(violations) == 0 {
		return rep, nil
	}

	// Validate candidate violations upfront so invalid attribute paths or unsupported SuggestedVal types fail fast.
	precomputedVals := make([]cty.Value, len(violations))
	for idx, v := range violations {
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
		precomputedVals[idx] = ctyVal
	}

	parsedFiles, filesByDir, err := discoverAndParseTFFiles(ctx, absDir, tfDir)
	if err != nil {
		return nil, err
	}

	recordSkip := func(v model.PolicyViolation, resType, resName string, reason model.RemediationSkipReason, filePath, moduleSource, detail, guidance string) {
		var attrPath []string
		if v.Remediation != nil && len(v.Remediation.AttributePath) > 0 {
			attrPath = append([]string(nil), v.Remediation.AttributePath...)
		}
		rep.Skipped = append(rep.Skipped, model.RemediationDiagnostic{
			RuleID:          v.RuleID,
			Severity:        v.Severity,
			ResourceAddress: v.ResourceAddress,
			ResourceType:    resType,
			ResourceName:    resName,
			Reason:          reason,
			FilePath:        filePath,
			ModuleSource:    moduleSource,
			AttributePath:   attrPath,
			Detail:          detail,
			Guidance:        guidance,
		})
		rep.Summary.SkippedCount++
		rep.Summary.ByReason[string(reason)]++
	}

	for idx, v := range violations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resType, resName := resolveResourceTypeAndName(v)
		displayAddr := v.ResourceAddress
		if displayAddr == "" && resType != "" && resName != "" {
			displayAddr = resType + "." + resName
		}

		if v.Remediation == nil || len(v.Remediation.AttributePath) == 0 {
			recordSkip(
				v, resType, resName,
				model.SkipReasonMissingRemediationMetadata,
				"", "",
				fmt.Sprintf("Policy rule %q does not define auto-remediation metadata (attribute_path) for %q.", v.RuleID, displayAddr),
				"Review the policy violation message and update the Terraform resource configuration manually.",
			)
			continue
		}

		if resType == "" || resName == "" {
			recordSkip(
				v, resType, resName,
				model.SkipReasonInvalidResourceAddress,
				"", "",
				fmt.Sprintf("Could not extract a valid Terraform resource type and name from address %q.", v.ResourceAddress),
				"Verify the plan resource address format (for example, <resource_type>.<name> or module.<mod>.<resource_type>.<name>) and remediate manually.",
			)
			continue
		}

		moduleChain, _, _ := parseResourceAddress(v.ResourceAddress)
		var candidateFiles []*parsedTFFile
		if len(moduleChain) == 0 {
			if len(filesByDir["."]) > 0 {
				candidateFiles = filesByDir["."]
			} else {
				candidateFiles = parsedFiles
			}
		} else {
			targetDir, modSkip := resolveModuleTarget(absDir, filesByDir, moduleChain)
			if modSkip != nil {
				recordSkip(v, resType, resName, modSkip.reason, modSkip.filePath, modSkip.moduleSource, modSkip.detail, modSkip.guidance)
				continue
			}
			candidateFiles = filesByDir[targetDir]
		}

		if isDataSourceAddress(v.ResourceAddress) {
			recordSkip(
				v, resType, resName,
				model.SkipReasonResourceBlockNotFound,
				"", "",
				fmt.Sprintf("Address %q references a read-only data source, which cannot be patched as a managed resource block.", v.ResourceAddress),
				"Data sources are read-only; remediate the underlying managed resource or adjust the data source filters manually.",
			)
			continue
		}

		foundBlock := false
		for _, pf := range candidateFiles {
			block := findResourceBlock(pf.hclFile.Body(), resType, resName)
			if block == nil {
				continue
			}
			foundBlock = true

			if detail, guidance, safe := validateBlockRemediationSafety(block, pf.relPath, v.Remediation.AttributePath, displayAddr); !safe {
				recordSkip(v, resType, resName, model.SkipReasonUnsupportedExpression, pf.relPath, "", detail, guidance)
				break
			}

			if err := applyRemediationToBlock(block, v.Remediation.AttributePath, precomputedVals[idx]); err != nil {
				return nil, fmt.Errorf("applying remediation to %s in %s: %w", displayAddr, pf.relPath, err)
			}

			formatted := hclwrite.Format(pf.hclFile.Bytes())
			normalizedPatched := string(bytes.ReplaceAll(formatted, []byte("\r\n"), []byte("\n")))
			unifiedDiff := computeUnifiedDiff(pf.relPath, pf.originalHCL, normalizedPatched)

			rep.Patches = append(rep.Patches, model.RemediationPatch{
				FilePath:        pf.relPath,
				ResourceAddress: displayAddr,
				RuleID:          v.RuleID,
				OriginalHCL:     pf.originalHCL,
				PatchedHCL:      normalizedPatched,
				UnifiedDiff:     unifiedDiff,
			})
			rep.Summary.PatchedCount++
			break
		}

		if !foundBlock {
			recordSkip(
				v, resType, resName,
				model.SkipReasonResourceBlockNotFound,
				"", "",
				fmt.Sprintf("No matching resource %q %q block was found in the target Terraform files.", resType, resName),
				"Locate where this resource is declared and apply the attribute update manually.",
			)
		}
	}

	if p.writeChanges && len(rep.Patches) > 0 {
		if err := p.ApplyPatches(ctx, tfDir, rep.Patches); err != nil {
			return nil, err
		}
	}

	return rep, nil
}

// discoverAndParseTFFiles walks absDir for regular non-symlink .tf files within maxTFFileBytes and parses them into HCL ASTs.
func discoverAndParseTFFiles(ctx context.Context, absDir, tfDir string) ([]*parsedTFFile, map[string][]*parsedTFFile, error) {
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
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".tf") {
			tfFiles = append(tfFiles, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("walking tfDir %q: %w", tfDir, walkErr)
	}

	sort.Strings(tfFiles)

	parsedFiles := make([]*parsedTFFile, 0, len(tfFiles))
	filesByDir := make(map[string][]*parsedTFFile)

	for _, fullPath := range tfFiles {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		lstat, err := os.Lstat(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("lstat %q: %w", fullPath, err)
		}
		if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
			continue
		}

		rel, err := filepath.Rel(absDir, fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("computing relative path for %q: %w", fullPath, err)
		}
		relSlash := filepath.ToSlash(rel)

		rawBytes, err := readTFFileBounded(fullPath, relSlash, lstat.Size())
		if err != nil {
			return nil, nil, err
		}

		normalized := bytes.ReplaceAll(rawBytes, []byte("\r\n"), []byte("\n"))
		hclFile, diags := hclwrite.ParseConfig(normalized, relSlash, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return nil, nil, fmt.Errorf("parsing HCL file %s: %s", relSlash, diags.Error())
		}

		pf := &parsedTFFile{
			relPath:     relSlash,
			originalHCL: string(normalized),
			hclFile:     hclFile,
		}
		parsedFiles = append(parsedFiles, pf)
		dirKey := path.Clean(path.Dir(relSlash))
		filesByDir[dirKey] = append(filesByDir[dirKey], pf)
	}

	return parsedFiles, filesByDir, nil
}

// readTFFileBounded enforces maxTFFileBytes before and during reading a .tf file.
func readTFFileBounded(fullPath, relSlash string, statSize int64) ([]byte, error) {
	if statSize > maxTFFileBytes {
		return nil, fmt.Errorf("HCL file %s exceeds maximum size of %d bytes", relSlash, maxTFFileBytes)
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("reading HCL file %q: %w", fullPath, err)
	}
	defer f.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(f, maxTFFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading HCL file %q: %w", fullPath, err)
	}
	if len(rawBytes) > maxTFFileBytes {
		return nil, fmt.Errorf("HCL file %s exceeds maximum size of %d bytes", relSlash, maxTFFileBytes)
	}
	return rawBytes, nil
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
		rawRel     string
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
		if strings.ContainsRune(rawRel, 0) ||
			filepath.IsAbs(rawRel) ||
			filepath.VolumeName(rawRel) != "" ||
			strings.HasPrefix(rawRel, "/") ||
			strings.HasPrefix(rawRel, `\`) {
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
		if hasUncleanSymlinkSegment(absRoot, filepath.ToSlash(rawRel)) || hasSymlinkSegment(absRoot, rel) {
			return fmt.Errorf("refusing to write through symlink path %q", patch.FilePath)
		}

		normKey := filepath.ToSlash(rel)
		if _, exists := latestByRel[normKey]; !exists {
			orderedFiles = append(orderedFiles, normKey)
		}
		latestByRel[normKey] = fileWriteTarget{
			rawRel:     rawRel,
			targetPath: target,
			patchedHCL: patch.PatchedHCL,
		}
	}

	for _, key := range orderedFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		item := latestByRel[key]

		if hasUncleanSymlinkSegment(absRoot, filepath.ToSlash(item.rawRel)) || hasSymlinkSegment(absRoot, key) {
			return fmt.Errorf("refusing to write through symlink path %q", key)
		}

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

// resolveResourceTypeAndName extracts the normalized resource type and resource name from a PolicyViolation,
// stripping any count/for_each index suffixes (e.g. [0], ["prod"]) and falling back to ResourceAddress.
func resolveResourceTypeAndName(v model.PolicyViolation) (string, string) {
	resType := stripIndexSuffix(v.ResourceType)
	resName := stripIndexSuffix(v.ResourceName)
	if resType != "" && resName != "" {
		return resType, resName
	}

	_, parsedType, parsedName := parseResourceAddress(v.ResourceAddress)
	if resType == "" {
		resType = parsedType
	}
	if resName == "" {
		resName = parsedName
	}
	return resType, resName
}

// parseResourceAddress parses a Terraform resource address into its normalized module chain,
// resource type, and resource name, stripping count/for_each index suffixes from each segment.
func parseResourceAddress(addr string) (moduleChain []string, resType string, resName string) {
	segments := splitAddressSegments(addr)
	if len(segments) == 0 {
		return nil, "", ""
	}

	i := 0
	for i+1 < len(segments) && stripIndexSuffix(segments[i]) == "module" {
		modName := stripIndexSuffix(segments[i+1])
		if modName != "" {
			moduleChain = append(moduleChain, modName)
		}
		i += 2
	}

	remaining := segments[i:]
	if len(remaining) >= 3 && stripIndexSuffix(remaining[0]) == "data" {
		remaining = remaining[1:]
	}
	if len(remaining) >= 2 {
		resType = stripIndexSuffix(remaining[len(remaining)-2])
		resName = stripIndexSuffix(remaining[len(remaining)-1])
	}
	return moduleChain, resType, resName
}

// splitAddressSegments splits a Terraform address on '.' only when outside brackets [...] and quotes "...".
func splitAddressSegments(addr string) []string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}

	var segments []string
	inQuotes := false
	escaped := false
	bracketDepth := 0
	start := 0

	for i := 0; i < len(addr); i++ {
		ch := addr[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuotes {
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inQuotes = false
			}
			continue
		}

		switch ch {
		case '"':
			inQuotes = true
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '.':
			if bracketDepth == 0 {
				segments = append(segments, strings.TrimSpace(addr[start:i]))
				start = i + 1
			}
		}
	}

	segments = append(segments, strings.TrimSpace(addr[start:]))
	return segments
}

// stripIndexSuffix removes any trailing count or for_each index suffix (e.g. [0], ["key"]) from an address segment.
func stripIndexSuffix(segment string) string {
	s := strings.TrimSpace(segment)
	if idx := strings.IndexByte(s, '['); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return s
}

// isDataSourceAddress reports whether a Terraform resource address refers to a read-only data source.
func isDataSourceAddress(addr string) bool {
	segments := splitAddressSegments(addr)
	if len(segments) == 0 {
		return false
	}
	i := 0
	for i+1 < len(segments) && stripIndexSuffix(segments[i]) == "module" {
		i += 2
	}
	remaining := segments[i:]
	return len(remaining) >= 3 && stripIndexSuffix(remaining[0]) == "data"
}

type moduleSkipInfo struct {
	reason       model.RemediationSkipReason
	filePath     string
	moduleSource string
	detail       string
	guidance     string
}

// resolveModuleTarget resolves a module chain step-by-step starting from "." within absRoot
// without ever falling back to scanning all repository .tf files.
func resolveModuleTarget(absRoot string, filesByDir map[string][]*parsedTFFile, moduleChain []string) (string, *moduleSkipInfo) {
	absRoot = filepath.Clean(absRoot)
	currDir := "."

	for _, rawMod := range moduleChain {
		modName := stripIndexSuffix(rawMod)
		if modName == "" {
			return "", &moduleSkipInfo{
				reason:   model.SkipReasonInvalidResourceAddress,
				detail:   "Module chain contains an empty module segment.",
				guidance: "Verify the plan resource address format and remediate manually.",
			}
		}

		nextDir, skip := resolveModuleStep(absRoot, filesByDir, currDir, modName)
		if skip != nil {
			return "", skip
		}
		currDir = nextDir
	}

	return currDir, nil
}

// resolveModuleStep resolves a single module.<modName> hop from currDir using explicit module blocks first,
// then conventional ./modules/<modName> only when no explicit module block exists in currDir.
func resolveModuleStep(absRoot string, filesByDir map[string][]*parsedTFFile, currDir, modName string) (string, *moduleSkipInfo) {
	for _, pf := range filesByDir[currDir] {
		block := findModuleBlock(pf.hclFile.Body(), modName)
		if block == nil {
			continue
		}

		srcAttr := block.Body().GetAttribute("source")
		if srcAttr == nil {
			return "", &moduleSkipInfo{
				reason:   model.SkipReasonUnresolvedLocalModule,
				filePath: pf.relPath,
				detail:   fmt.Sprintf("Module block %q in %s does not declare a source attribute.", modName, pf.relPath),
				guidance: "Declare a local module source or apply the required attribute change directly inside the module definition.",
			}
		}

		rawSource, isStatic := parseStaticStringAttr(srcAttr, pf.relPath)
		if !isStatic {
			return "", &moduleSkipInfo{
				reason:   model.SkipReasonUnsupportedExpression,
				filePath: pf.relPath,
				detail:   fmt.Sprintf("Module %q in %s uses a non-literal source expression that cannot be resolved statically.", modName, pf.relPath),
				guidance: "Replace the dynamic module source with a static local path or update the referenced module manually.",
			}
		}

		if rawSource == "" {
			return "", &moduleSkipInfo{
				reason:   model.SkipReasonUnresolvedLocalModule,
				filePath: pf.relPath,
				detail:   fmt.Sprintf("Module block %q in %s has an empty source attribute.", modName, pf.relPath),
				guidance: "Set a valid local module source path or remediate the target module directly.",
			}
		}

		candRel, skip := classifyModuleSource(absRoot, currDir, modName, pf.relPath, rawSource)
		if skip != nil {
			return "", skip
		}
		if len(filesByDir[candRel]) == 0 {
			return "", &moduleSkipInfo{
				reason:       model.SkipReasonUnresolvedLocalModule,
				filePath:     pf.relPath,
				moduleSource: rawSource,
				detail:       fmt.Sprintf("Local module %q source %q (declared in %s) resolved to %q, which contains no .tf files.", modName, rawSource, pf.relPath, candRel),
				guidance:     "Ensure the local module directory and .tf files exist within the Terraform workspace, or apply the fix directly in the module source.",
			}
		}
		return candRel, nil
	}

	// No explicit module "<modName>" block in currDir; check conventional ./modules/<modName>.
	convSource := "./" + path.Join("modules", modName)
	candRel, skip := classifyModuleSource(absRoot, currDir, modName, "", convSource)
	if skip != nil {
		return "", skip
	}
	if len(filesByDir[candRel]) == 0 {
		return "", &moduleSkipInfo{
			reason:   model.SkipReasonUnresolvedLocalModule,
			detail:   fmt.Sprintf("Could not resolve local module %q from %q; no matching module block or ./modules/%s directory with .tf files was found.", modName, currDir, modName),
			guidance: "Ensure the local module block and .tf files exist within the Terraform workspace, or apply the remediation manually.",
		}
	}
	return candRel, nil
}

// findModuleBlock searches the top-level HCL body for `module "<modName>"`.
func findModuleBlock(body *hclwrite.Body, modName string) *hclwrite.Block {
	if body == nil {
		return nil
	}
	for _, block := range body.Blocks() {
		if block.Type() != "module" {
			continue
		}
		labels := block.Labels()
		if len(labels) == 1 && stripIndexSuffix(labels[0]) == modName {
			return block
		}
	}
	return nil
}

// classifyModuleSource classifies a static module source string as external, path-traversal-blocked,
// or a safe workspace-contained relative directory.
func classifyModuleSource(absRoot, currDir, modName, declFilePath, rawSource string) (string, *moduleSkipInfo) {
	if strings.Contains(rawSource, "://") || strings.Contains(rawSource, "::") {
		return "", &moduleSkipInfo{
			reason:       model.SkipReasonExternalModuleSource,
			filePath:     declFilePath,
			moduleSource: rawSource,
			detail:       fmt.Sprintf("Resource belongs to external/remote module %q (source %q in %s), which cannot be patched in the local repository.", modName, rawSource, declFilePath),
			guidance:     "Pass the compliant configuration via module input variables in the caller block or update the upstream module source version.",
		}
	}

	if strings.ContainsRune(rawSource, 0) ||
		filepath.IsAbs(rawSource) ||
		filepath.VolumeName(rawSource) != "" ||
		strings.HasPrefix(rawSource, "/") ||
		strings.HasPrefix(rawSource, `\`) {
		return "", &moduleSkipInfo{
			reason:       model.SkipReasonPathTraversalBlocked,
			filePath:     declFilePath,
			moduleSource: rawSource,
			detail:       fmt.Sprintf("Blocked module %q source %q because absolute or root-anchored paths cannot be traversed safely.", modName, rawSource),
			guidance:     "Replace the absolute module source with a relative path strictly inside the Terraform root directory or remediate manually.",
		}
	}

	srcSlash := filepath.ToSlash(rawSource)
	isExplicitRelative := strings.HasPrefix(srcSlash, "./") || strings.HasPrefix(srcSlash, "../") || srcSlash == "." || srcSlash == ".."
	if !isExplicitRelative {
		return "", &moduleSkipInfo{
			reason:       model.SkipReasonExternalModuleSource,
			filePath:     declFilePath,
			moduleSource: rawSource,
			detail:       fmt.Sprintf("Resource belongs to external registry/remote module %q (source %q in %s), which cannot be patched in the local repository.", modName, rawSource, declFilePath),
			guidance:     "Pass the compliant configuration via module input variables in the caller block or update the upstream module source version.",
		}
	}

	currAbs := filepath.Join(absRoot, filepath.FromSlash(currDir))
	candAbs := filepath.Clean(filepath.Join(currAbs, filepath.FromSlash(srcSlash)))
	rel, err := filepath.Rel(absRoot, candAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", &moduleSkipInfo{
			reason:       model.SkipReasonPathTraversalBlocked,
			filePath:     declFilePath,
			moduleSource: rawSource,
			detail:       fmt.Sprintf("Blocked module %q source %q because it escapes the Terraform root directory.", modName, rawSource),
			guidance:     "Move the module inside the Terraform root directory or remediate the external module directory directly.",
		}
	}

	if hasUncleanSymlinkSegment(currAbs, srcSlash) || hasSymlinkSegment(absRoot, rel) {
		return "", &moduleSkipInfo{
			reason:       model.SkipReasonPathTraversalBlocked,
			filePath:     declFilePath,
			moduleSource: rawSource,
			detail:       fmt.Sprintf("Blocked module %q source %q because it traverses a symbolic link.", modName, rawSource),
			guidance:     "Avoid symlinked module directories or apply the remediation directly inside the target module.",
		}
	}

	return path.Clean(filepath.ToSlash(rel)), nil
}

// hasUncleanSymlinkSegment walks rawSlash relative to baseAbs before lexical ".." collapsing
// so paths like "./symlink/../sibling" are caught and rejected as symlink traversals.
func hasUncleanSymlinkSegment(baseAbs, rawSlash string) bool {
	if rawSlash == "" || rawSlash == "." {
		return false
	}
	curr := filepath.Clean(baseAbs)
	for _, seg := range strings.Split(rawSlash, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			curr = filepath.Dir(curr)
			continue
		}
		curr = filepath.Join(curr, seg)
		lstat, err := os.Lstat(curr)
		if err != nil {
			return false
		}
		if lstat.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// hasSymlinkSegment checks every path segment of rel inside absRoot for symlinks without resolving above absRoot.
func hasSymlinkSegment(absRoot, rel string) bool {
	relSlash := path.Clean(filepath.ToSlash(rel))
	if relSlash == "." || relSlash == "" {
		return false
	}
	curr := absRoot
	for _, seg := range strings.Split(relSlash, "/") {
		if seg == "" || seg == "." {
			continue
		}
		curr = filepath.Join(curr, seg)
		lstat, err := os.Lstat(curr)
		if err != nil {
			return false
		}
		if lstat.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// parseStaticStringAttr parses an attribute expression and extracts its trimmed literal string value
// only when the expression is a static string literal without template interpolation or variables.
func parseStaticStringAttr(attr *hclwrite.Attribute, filePath string) (string, bool) {
	if attr == nil {
		return "", false
	}
	exprBytes := bytes.TrimSpace(attr.Expr().BuildTokens(nil).Bytes())
	if len(exprBytes) == 0 {
		return "", false
	}
	expr, diags := hclsyntax.ParseExpression(exprBytes, filePath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", false
	}
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type() == cty.String && !e.Val.IsNull() {
			return strings.TrimSpace(e.Val.AsString()), true
		}
		return "", false
	case *hclsyntax.TemplateExpr:
		var b strings.Builder
		for _, part := range e.Parts {
			lit, ok := part.(*hclsyntax.LiteralValueExpr)
			if !ok || lit.Val.Type() != cty.String || lit.Val.IsNull() {
				return "", false
			}
			b.WriteString(lit.Val.AsString())
		}
		return strings.TrimSpace(b.String()), true
	default:
		return "", false
	}
}

// extractStaticStringAttr extracts the literal string value from an HCL attribute if and only if
// the expression is a static quoted string literal without template interpolation.
func extractStaticStringAttr(attr *hclwrite.Attribute) string {
	val, _ := parseStaticStringAttr(attr, "")
	return val
}

// validateBlockRemediationSafety inspects the target block read-only before any AST mutation,
// rejecting dynamic blocks, ambiguous multiple nested blocks, block/attribute mismatches, and non-literal expressions.
func validateBlockRemediationSafety(block *hclwrite.Block, filePath string, attrPath []string, displayAddr string) (detail string, guidance string, ok bool) {
	currBody := block.Body()
	for i := 0; i < len(attrPath)-1; i++ {
		blockName := strings.TrimSpace(attrPath[i])
		if hasDynamicBlock(currBody, blockName) {
			return fmt.Sprintf("Resource %q in %s defines a dynamic %q block; auto-remediation will not overwrite dynamic HCL constructs.", displayAddr, filePath, blockName),
				"Update the dynamic block content or its input variables manually.",
				false
		}
		if currBody.GetAttribute(blockName) != nil {
			return fmt.Sprintf("Resource %q in %s defines %q as an attribute expression rather than a nested HCL block.", displayAddr, filePath, blockName),
				"Update the attribute expression or referenced variable/local manually.",
				false
		}
		matches := matchingUnlabeledBlocks(currBody, blockName)
		if len(matches) > 1 {
			return fmt.Sprintf("Resource %q in %s contains multiple %q blocks, making the target block ambiguous for auto-remediation.", displayAddr, filePath, blockName),
				"Inspect the multiple nested blocks in the resource and update the appropriate block manually.",
				false
		}
		if len(matches) == 0 {
			// Missing intermediate blocks will be safely appended by applyRemediationToBlock.
			return "", "", true
		}
		currBody = matches[0].Body()
	}

	leafAttr := strings.TrimSpace(attrPath[len(attrPath)-1])
	if hasDynamicBlock(currBody, leafAttr) {
		return fmt.Sprintf("Resource %q in %s defines a dynamic %q block; auto-remediation will not overwrite dynamic HCL constructs.", displayAddr, filePath, leafAttr),
			"Update the dynamic block content or its input variables manually.",
			false
	}
	if hasBlockOfType(currBody, leafAttr) {
		return fmt.Sprintf("Resource %q in %s defines %q as a nested block rather than a leaf attribute.", displayAddr, filePath, leafAttr),
			"Update the nested block configuration manually.",
			false
	}

	if existingAttr := currBody.GetAttribute(leafAttr); existingAttr != nil {
		exprBytes := bytes.TrimSpace(existingAttr.Expr().BuildTokens(nil).Bytes())
		expr, diags := hclsyntax.ParseExpression(exprBytes, filePath, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() || !isStaticLiteralExpr(expr) {
			return fmt.Sprintf("Attribute %q on %q in %s uses a non-literal expression (such as a variable, local, interpolation, or function call) and was left untouched.", leafAttr, displayAddr, filePath),
				"Update the referenced variable, local, or expression in your Terraform configuration manually.",
				false
		}
	}

	return "", "", true
}

func hasDynamicBlock(body *hclwrite.Body, targetName string) bool {
	for _, b := range body.Blocks() {
		if b.Type() == "dynamic" && len(b.Labels()) == 1 && b.Labels()[0] == targetName {
			return true
		}
	}
	return false
}

func matchingUnlabeledBlocks(body *hclwrite.Body, blockType string) []*hclwrite.Block {
	var matches []*hclwrite.Block
	for _, b := range body.Blocks() {
		if b.Type() == blockType && len(b.Labels()) == 0 {
			matches = append(matches, b)
		}
	}
	return matches
}

func hasBlockOfType(body *hclwrite.Body, blockType string) bool {
	for _, b := range body.Blocks() {
		if b.Type() == blockType {
			return true
		}
	}
	return false
}

// isStaticLiteralExpr reports whether an HCL syntax expression represents a purely static literal value
// safe to overwrite without clobbering variables, locals, conditionals, function calls, or interpolations.
func isStaticLiteralExpr(expr hclsyntax.Expression) bool {
	if expr == nil {
		return false
	}
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return true
	case *hclsyntax.TemplateExpr:
		// "" has len(Parts)==0; static strings have only *hclsyntax.LiteralValueExpr parts.
		for _, part := range e.Parts {
			if _, ok := part.(*hclsyntax.LiteralValueExpr); !ok {
				return false
			}
		}
		return true
	case *hclsyntax.UnaryOpExpr:
		return e.Op == hclsyntax.OpNegate && isStaticLiteralExpr(e.Val)
	case *hclsyntax.ParenthesesExpr:
		return isStaticLiteralExpr(e.Expression)
	case *hclsyntax.TupleConsExpr:
		for _, elem := range e.Exprs {
			if !isStaticLiteralExpr(elem) {
				return false
			}
		}
		return true
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			if !isStaticObjectKey(item.KeyExpr) || !isStaticLiteralExpr(item.ValueExpr) {
				return false
			}
		}
		return true
	default:
		// ScopeTraversalExpr (var.*, local.*), FunctionCallExpr, ConditionalExpr, TemplateWrapExpr, ForExpr, etc.
		return false
	}
}

func isStaticObjectKey(keyExpr hclsyntax.Expression) bool {
	if keyExpr == nil {
		return false
	}
	if objKey, ok := keyExpr.(*hclsyntax.ObjectConsKeyExpr); ok {
		if objKey.ForceNonLiteral {
			return false
		}
		if st, ok := objKey.Wrapped.(*hclsyntax.ScopeTraversalExpr); ok && len(st.Traversal) == 1 {
			return true
		}
		return isStaticLiteralExpr(objKey.Wrapped)
	}
	return isStaticLiteralExpr(keyExpr)
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

const maxLCSCells = 4_000_000

// computeLCSEdits computes the Longest Common Subsequence line diff between oldLines and newLines,
// trimming common prefix/suffix lines first and capping DP matrix size to prevent OOM DoS.
func computeLCSEdits(oldLines, newLines []string) []diffEdit {
	m := len(oldLines)
	n := len(newLines)

	prefix := 0
	for prefix < m && prefix < n && oldLines[prefix] == newLines[prefix] {
		prefix++
	}

	suffix := 0
	for suffix < m-prefix && suffix < n-prefix && oldLines[m-1-suffix] == newLines[n-1-suffix] {
		suffix++
	}

	edits := make([]diffEdit, 0, m+n)
	for k := 0; k < prefix; k++ {
		edits = append(edits, diffEdit{
			kind:    editEqual,
			text:    oldLines[k],
			oldLine: k + 1,
			newLine: k + 1,
		})
	}

	oldMid := oldLines[prefix : m-suffix]
	newMid := newLines[prefix : n-suffix]
	mm := len(oldMid)
	nm := len(newMid)

	if mm == 0 || nm == 0 || nm > maxLCSCells/mm {
		for i := 0; i < mm; i++ {
			edits = append(edits, diffEdit{
				kind:    editDelete,
				text:    oldMid[i],
				oldLine: prefix + i + 1,
			})
		}
		for j := 0; j < nm; j++ {
			edits = append(edits, diffEdit{
				kind:    editInsert,
				text:    newMid[j],
				newLine: prefix + j + 1,
			})
		}
	} else {
		dp := make([][]int, mm+1)
		for i := range dp {
			dp[i] = make([]int, nm+1)
		}

		for i := mm - 1; i >= 0; i-- {
			for j := nm - 1; j >= 0; j-- {
				if oldMid[i] == newMid[j] {
					dp[i][j] = 1 + dp[i+1][j+1]
				} else if dp[i+1][j] >= dp[i][j+1] {
					dp[i][j] = dp[i+1][j]
				} else {
					dp[i][j] = dp[i][j+1]
				}
			}
		}

		i, j := 0, 0
		for i < mm && j < nm {
			if oldMid[i] == newMid[j] {
				edits = append(edits, diffEdit{
					kind:    editEqual,
					text:    oldMid[i],
					oldLine: prefix + i + 1,
					newLine: prefix + j + 1,
				})
				i++
				j++
			} else if dp[i+1][j] >= dp[i][j+1] {
				edits = append(edits, diffEdit{
					kind:    editDelete,
					text:    oldMid[i],
					oldLine: prefix + i + 1,
				})
				i++
			} else {
				edits = append(edits, diffEdit{
					kind:    editInsert,
					text:    newMid[j],
					newLine: prefix + j + 1,
				})
				j++
			}
		}
		for i < mm {
			edits = append(edits, diffEdit{
				kind:    editDelete,
				text:    oldMid[i],
				oldLine: prefix + i + 1,
			})
			i++
		}
		for j < nm {
			edits = append(edits, diffEdit{
				kind:    editInsert,
				text:    newMid[j],
				newLine: prefix + j + 1,
			})
			j++
		}
	}

	for k := 0; k < suffix; k++ {
		oldIdx := m - suffix + k
		newIdx := n - suffix + k
		edits = append(edits, diffEdit{
			kind:    editEqual,
			text:    oldLines[oldIdx],
			oldLine: oldIdx + 1,
			newLine: newIdx + 1,
		})
	}

	return edits
}
