package policy

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/policies"
	"github.com/open-policy-agent/opa/v1/ast"
)

const maxPolicyFileBytes = 2 << 20 // 2 MiB maximum policy file size

// PackInfo describes metadata for a bundled starter policy pack.
type PackInfo struct {
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
	FileCount   int    `json:"file_count"`
	RuleCount   int    `json:"rule_count"`
}

type packSpec struct {
	name        string
	provider    string
	description string
}

var bundledCloudPacks = []packSpec{
	{
		name:        "aws",
		provider:    "aws",
		description: "AWS v5 security guardrails (S3, RDS, EBS, EC2, KMS)",
	},
	{
		name:        "azure",
		provider:    "azurerm",
		description: "AzureRM v4 security guardrails (Storage, SQL, PostgreSQL, Key Vault)",
	},
	{
		name:        "gcp",
		provider:    "google",
		description: "Google Cloud v6 security guardrails (Storage, Cloud SQL, Compute, KMS, Firewall)",
	},
}

// ListPacks returns deterministic metadata for all bundled starter policy packs,
// including the composite "all" pack.
func ListPacks() []PackInfo {
	infos := make([]PackInfo, 0, len(bundledCloudPacks)+1)
	totalFiles := 0
	totalRules := 0

	for _, spec := range bundledCloudPacks {
		files, rules := inspectEmbeddedPack(spec.name)
		totalFiles += files
		totalRules += rules
		infos = append(infos, PackInfo{
			Name:        spec.name,
			Provider:    spec.provider,
			Description: spec.description,
			FileCount:   files,
			RuleCount:   rules,
		})
	}

	infos = append(infos, PackInfo{
		Name:        "all",
		Provider:    "multi-cloud",
		Description: "All bundled AWS, Azure, and GCP starter policy packs",
		FileCount:   totalFiles,
		RuleCount:   totalRules,
	})

	return infos
}

// LoadPolicies loads, deduplicates, and deterministically sorts Rego policies from
// filesystem paths (individual .rego files or directories searched recursively) and/or
// embedded starter packs (aws, azure, gcp, all).
func LoadPolicies(paths []string, packs []string) ([]model.PolicyContent, error) {
	cleanedPaths := make([]string, 0, len(paths))
	for _, p := range paths {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			cleanedPaths = append(cleanedPaths, trimmed)
		}
	}

	expandedPacks, err := resolvePackNames(packs)
	if err != nil {
		return nil, err
	}

	if len(cleanedPaths) == 0 && len(expandedPacks) == 0 {
		return nil, fmt.Errorf("at least one --policy path or --pack name must be provided")
	}

	seen := make(map[string]bool)
	result := make([]model.PolicyContent, 0)

	// 1. Load embedded starter policy packs.
	for _, packName := range expandedPacks {
		embeddedPolicies, err := loadEmbeddedPack(packName)
		if err != nil {
			return nil, err
		}
		for _, ep := range embeddedPolicies {
			if seen[ep.Path] {
				continue
			}
			seen[ep.Path] = true
			result = append(result, ep)
		}
	}

	// 2. Load filesystem policy files and directories.
	for _, rawPath := range cleanedPaths {
		fsPolicies, err := loadFilesystemPath(rawPath)
		if err != nil {
			return nil, err
		}
		for _, fp := range fsPolicies {
			dedupKey := canonicalFileKey(fp.Path)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true
			result = append(result, fp)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no .rego policy files loaded")
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Path < result[j].Path
	})

	return result, nil
}

func resolvePackNames(rawPacks []string) ([]string, error) {
	packSet := make(map[string]bool)
	for _, entry := range rawPacks {
		for _, part := range strings.Split(entry, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			switch name {
			case "aws", "azure", "gcp":
				packSet[name] = true
			case "all":
				packSet["aws"] = true
				packSet["azure"] = true
				packSet["gcp"] = true
			default:
				return nil, fmt.Errorf("unknown policy pack %q: valid packs are aws, azure, gcp, all", strings.TrimSpace(part))
			}
		}
	}

	out := make([]string, 0, len(packSet))
	for name := range packSet {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func loadEmbeddedPack(packName string) ([]model.PolicyContent, error) {
	entries, err := fs.ReadDir(policies.PackFS, packName)
	if err != nil {
		return nil, fmt.Errorf("reading embedded policy pack %q: %w", packName, err)
	}

	fileNames := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(path.Ext(e.Name()), ".rego") {
			fileNames = append(fileNames, e.Name())
		}
	}
	sort.Strings(fileNames)

	if len(fileNames) == 0 {
		return nil, fmt.Errorf("embedded policy pack %q contains no .rego files", packName)
	}

	loaded := make([]model.PolicyContent, 0, len(fileNames))
	for _, name := range fileNames {
		embedPath := path.Join(packName, name)
		content, err := fs.ReadFile(policies.PackFS, embedPath)
		if err != nil {
			return nil, fmt.Errorf("reading embedded policy %q: %w", embedPath, err)
		}
		loaded = append(loaded, model.PolicyContent{
			Path:    "pack://" + embedPath,
			Content: content,
		})
	}

	return loaded, nil
}

func readPolicyFileCapped(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", filePath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxPolicyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", filePath, err)
	}
	if len(data) > maxPolicyFileBytes {
		return nil, fmt.Errorf("policy file %q exceeds maximum allowed size of %d bytes", filePath, maxPolicyFileBytes)
	}
	return data, nil
}

func loadFilesystemPath(rawPath string) ([]model.PolicyContent, error) {
	lfi, err := os.Lstat(rawPath)
	if err != nil {
		return nil, fmt.Errorf("stat policy path %q: %w", rawPath, err)
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("policy path %q is a symlink", rawPath)
	}

	if !lfi.IsDir() {
		content, err := readPolicyFileCapped(rawPath)
		if err != nil {
			return nil, err
		}
		return []model.PolicyContent{
			{
				Path:    rawPath,
				Content: content,
			},
		}, nil
	}

	var regoPaths []string
	err = filepath.WalkDir(rawPath, func(walkPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(walkPath), ".rego") {
			regoPaths = append(regoPaths, walkPath)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking policy directory %q: %w", rawPath, err)
	}

	if len(regoPaths) == 0 {
		return nil, fmt.Errorf("policy directory %q contains no .rego files", rawPath)
	}

	sort.Strings(regoPaths)

	loaded := make([]model.PolicyContent, 0, len(regoPaths))
	for _, p := range regoPaths {
		content, err := readPolicyFileCapped(p)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, model.PolicyContent{
			Path:    p,
			Content: content,
		})
	}

	return loaded, nil
}

func canonicalFileKey(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "file://" + filepath.ToSlash(filepath.Clean(p))
	}
	return "file://" + filepath.ToSlash(filepath.Clean(abs))
}

func inspectEmbeddedPack(packName string) (fileCount int, ruleCount int) {
	entries, err := fs.ReadDir(policies.PackFS, packName)
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(path.Ext(e.Name()), ".rego") {
			continue
		}
		embedPath := path.Join(packName, e.Name())
		content, err := fs.ReadFile(policies.PackFS, embedPath)
		if err != nil {
			continue
		}
		fileCount++
		mod, err := ast.ParseModuleWithOpts("pack://"+embedPath, string(content), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			continue
		}
		for _, r := range mod.Rules {
			head := r.Head.Name.String()
			if head == "deny" || head == "violation" {
				ruleCount++
			}
		}
	}
	return fileCount, ruleCount
}
