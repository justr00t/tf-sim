package policy_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/policy"
	"github.com/justr00t/tf-sim/policies"
)

func TestPackFS_EmbeddedCorpusIntegrity(t *testing.T) {
	t.Parallel()

	var files []string
	err := fs.WalkDir(policies.PackFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir(policies.PackFS) failed: %v", err)
	}

	sort.Strings(files)
	want := []string{
		"aws/ebs.rego",
		"aws/ec2.rego",
		"aws/kms.rego",
		"aws/rds.rego",
		"aws/s3.rego",
		"azure/database.rego",
		"azure/keyvault.rego",
		"azure/storage.rego",
		"gcp/compute.rego",
		"gcp/firewall.rego",
		"gcp/kms.rego",
		"gcp/sql.rego",
		"gcp/storage.rego",
	}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("embedded PackFS files = %v, want %v", files, want)
	}
}

func TestListPacks_MetadataAndDeterministicOrder(t *testing.T) {
	t.Parallel()

	packs := policy.ListPacks()
	wantNames := []string{"aws", "azure", "gcp", "all"}
	wantCounts := map[string]struct {
		files int
		rules int
	}{
		"aws":   {files: 5, rules: 12},
		"azure": {files: 3, rules: 8},
		"gcp":   {files: 5, rules: 8},
		"all":   {files: 13, rules: 28},
	}

	if len(packs) != len(wantNames) {
		t.Fatalf("expected %d packs, got %d: %+v", len(wantNames), len(packs), packs)
	}

	for i, wantName := range wantNames {
		got := packs[i]
		if got.Name != wantName {
			t.Errorf("packs[%d].Name = %q, want %q", i, got.Name, wantName)
		}
		if strings.TrimSpace(got.Provider) == "" {
			t.Errorf("packs[%d] (%s) has empty Provider", i, got.Name)
		}
		if strings.TrimSpace(got.Description) == "" {
			t.Errorf("packs[%d] (%s) has empty Description", i, got.Name)
		}
		exp := wantCounts[wantName]
		if got.FileCount != exp.files {
			t.Errorf("pack %q FileCount = %d, want %d", got.Name, got.FileCount, exp.files)
		}
		if got.RuleCount != exp.rules {
			t.Errorf("pack %q RuleCount = %d, want %d", got.Name, got.RuleCount, exp.rules)
		}
	}

	// Verify deterministic ordering and defensive copy on repeated calls.
	packs[0].Name = "mutated"
	packsAgain := policy.ListPacks()
	if packsAgain[0].Name != "aws" {
		t.Errorf("ListPacks() leaked internal slice mutation: got %q, want %q", packsAgain[0].Name, "aws")
	}
}

func TestLoadPolicies_EmbeddedPacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		packs          []string
		wantCount      int
		wantPrefixes   []string
		forbidPrefixes []string
	}{
		{
			name:           "AWS",
			packs:          []string{"aws"},
			wantCount:      5,
			wantPrefixes:   []string{"pack://aws/"},
			forbidPrefixes: []string{"pack://azure/", "pack://gcp/"},
		},
		{
			name:           "Azure",
			packs:          []string{"azure"},
			wantCount:      3,
			wantPrefixes:   []string{"pack://azure/"},
			forbidPrefixes: []string{"pack://aws/", "pack://gcp/"},
		},
		{
			name:           "GCP",
			packs:          []string{"gcp"},
			wantCount:      5,
			wantPrefixes:   []string{"pack://gcp/"},
			forbidPrefixes: []string{"pack://aws/", "pack://azure/"},
		},
		{
			name:         "All",
			packs:        []string{"all"},
			wantCount:    13,
			wantPrefixes: []string{"pack://aws/", "pack://azure/", "pack://gcp/"},
		},
		{
			name:         "CaseInsensitiveAndTrimmed",
			packs:        []string{"  AWS ", "\tAzure\n"},
			wantCount:    8,
			wantPrefixes: []string{"pack://aws/", "pack://azure/"},
		},
		{
			name:         "CommaSeparated",
			packs:        []string{"aws,gcp"},
			wantCount:    10,
			wantPrefixes: []string{"pack://aws/", "pack://gcp/"},
		},
		{
			name:         "CommaSeparatedWithSpacesAndMixedCase",
			packs:        []string{" Azure , GCP "},
			wantCount:    8,
			wantPrefixes: []string{"pack://azure/", "pack://gcp/"},
		},
		{
			name:         "DuplicateDeduplication_AWSPlusAll",
			packs:        []string{"aws", "all"},
			wantCount:    13,
			wantPrefixes: []string{"pack://aws/", "pack://azure/", "pack://gcp/"},
		},
		{
			name:         "DuplicateDeduplication_RepeatedPacks",
			packs:        []string{"aws,azure", "AWS", "azure"},
			wantCount:    8,
			wantPrefixes: []string{"pack://aws/", "pack://azure/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loaded, err := policy.LoadPolicies(nil, tc.packs)
			if err != nil {
				t.Fatalf("LoadPolicies(nil, %v) returned unexpected error: %v", tc.packs, err)
			}
			if len(loaded) != tc.wantCount {
				t.Fatalf("LoadPolicies(nil, %v) returned %d policies, want %d", tc.packs, len(loaded), tc.wantCount)
			}

			seen := make(map[string]bool, len(loaded))
			paths := make([]string, 0, len(loaded))
			prefixHits := make(map[string]bool)

			for _, p := range loaded {
				if strings.Contains(p.Path, `\`) {
					t.Errorf("embedded policy path contains OS backslash %q; must be slash-normalized", p.Path)
				}
				if !strings.HasPrefix(p.Path, "pack://") || !strings.HasSuffix(p.Path, ".rego") {
					t.Errorf("embedded policy path %q does not match pack://<pack>/<file>.rego", p.Path)
				}
				if len(p.Content) == 0 {
					t.Errorf("embedded policy %q has empty content", p.Path)
				}
				if seen[p.Path] {
					t.Errorf("duplicate policy path returned: %q", p.Path)
				}
				seen[p.Path] = true
				paths = append(paths, p.Path)

				for _, pref := range tc.wantPrefixes {
					if strings.HasPrefix(p.Path, pref) {
						prefixHits[pref] = true
					}
				}
				for _, forbid := range tc.forbidPrefixes {
					if strings.HasPrefix(p.Path, forbid) {
						t.Errorf("unexpected policy %q matched forbidden prefix %q", p.Path, forbid)
					}
				}
			}

			for _, pref := range tc.wantPrefixes {
				if !prefixHits[pref] {
					t.Errorf("expected at least one policy with prefix %q, got paths: %v", pref, paths)
				}
			}

			// Verify deterministic sorted order.
			if !sort.StringsAreSorted(paths) {
				t.Errorf("expected loaded policy paths to be deterministically sorted, got: %v", paths)
			}
		})
	}
}

func TestLoadPolicies_FilesystemAndMixed(t *testing.T) {
	t.Parallel()

	sampleRego := func(pkg string) []byte {
		return []byte("package " + pkg + "\n\nimport rego.v1\n")
	}

	t.Run("SingleFile", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "single.rego")
		content := sampleRego("tfsim.single")
		if err := os.WriteFile(filePath, content, 0o600); err != nil {
			t.Fatalf("failed to write single.rego: %v", err)
		}

		loaded, err := policy.LoadPolicies([]string{filePath}, nil)
		if err != nil {
			t.Fatalf("LoadPolicies single file failed: %v", err)
		}
		if len(loaded) != 1 {
			t.Fatalf("expected 1 policy, got %d", len(loaded))
		}
		if string(loaded[0].Content) != string(content) {
			t.Errorf("content mismatch: got %q, want %q", string(loaded[0].Content), string(content))
		}
	})

	t.Run("RecursiveDirectoryWalk_SortedAndIgnoresNonRego", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		subA := filepath.Join(tmpDir, "a")
		subANested := filepath.Join(subA, "nested")
		subB := filepath.Join(tmpDir, "b")
		for _, d := range []string{subANested, subB} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatalf("failed to mkdir %s: %v", d, err)
			}
		}

		regoFiles := map[string][]byte{
			filepath.Join(subB, "z_rule.rego"):       sampleRego("tfsim.b"),
			filepath.Join(subA, "a_rule.rego"):       sampleRego("tfsim.a"),
			filepath.Join(subANested, "m_rule.rego"): sampleRego("tfsim.nested"),
		}
		for p, c := range regoFiles {
			if err := os.WriteFile(p, c, 0o600); err != nil {
				t.Fatalf("failed to write %s: %v", p, err)
			}
		}

		// Non-.rego files that must be ignored.
		nonRegoFiles := []string{
			filepath.Join(tmpDir, "README.md"),
			filepath.Join(subA, "notes.txt"),
			filepath.Join(subB, "policy.rego.bak"),
			filepath.Join(subANested, "plan.json"),
		}
		for _, p := range nonRegoFiles {
			if err := os.WriteFile(p, []byte("ignored"), 0o600); err != nil {
				t.Fatalf("failed to write %s: %v", p, err)
			}
		}

		loaded1, err := policy.LoadPolicies([]string{tmpDir}, nil)
		if err != nil {
			t.Fatalf("LoadPolicies recursive dir failed: %v", err)
		}
		if len(loaded1) != 3 {
			t.Fatalf("expected 3 .rego files, got %d: %+v", len(loaded1), loaded1)
		}

		paths1 := make([]string, len(loaded1))
		for i, p := range loaded1 {
			if !strings.HasSuffix(p.Path, ".rego") {
				t.Errorf("unexpected non-.rego file loaded: %q", p.Path)
			}
			paths1[i] = p.Path
		}
		if !sort.StringsAreSorted(paths1) {
			t.Errorf("expected sorted paths, got: %v", paths1)
		}

		// Second call must produce identical order.
		loaded2, err := policy.LoadPolicies([]string{tmpDir}, nil)
		if err != nil {
			t.Fatalf("second LoadPolicies failed: %v", err)
		}
		if !reflect.DeepEqual(loaded1, loaded2) {
			t.Errorf("LoadPolicies not deterministic across runs")
		}
	})

	t.Run("MixedPolicyDirAndEmbeddedPack", func(t *testing.T) {
		t.Parallel()
		awsDir := filepath.Join("..", "..", "policies", "aws")
		loaded, err := policy.LoadPolicies([]string{awsDir}, []string{"gcp"})
		if err != nil {
			t.Fatalf("LoadPolicies mixed dir + pack failed: %v", err)
		}
		// 5 AWS files from disk + 5 GCP files from embedded PackFS = 10 total.
		if len(loaded) != 10 {
			t.Fatalf("expected 10 policies (5 AWS disk + 5 GCP pack), got %d", len(loaded))
		}

		var diskCount, packCount int
		for _, p := range loaded {
			if strings.HasPrefix(p.Path, "pack://gcp/") {
				packCount++
			} else if strings.HasSuffix(p.Path, ".rego") {
				diskCount++
			}
		}
		if diskCount != 5 || packCount != 5 {
			t.Errorf("expected 5 disk and 5 pack://gcp/ policies, got disk=%d pack=%d", diskCount, packCount)
		}
	})

	t.Run("DeduplicatesRepeatedFileAndParentDir", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "rule.rego")
		if err := os.WriteFile(filePath, sampleRego("tfsim.dedup"), 0o600); err != nil {
			t.Fatalf("failed to write rule.rego: %v", err)
		}

		loaded, err := policy.LoadPolicies([]string{filePath, tmpDir, filePath}, nil)
		if err != nil {
			t.Fatalf("LoadPolicies dedup failed: %v", err)
		}
		if len(loaded) != 1 {
			t.Fatalf("expected deduplicated count 1, got %d: %+v", len(loaded), loaded)
		}
	})
}

func TestLoadPolicies_ErrorCases(t *testing.T) {
	t.Parallel()

	emptyDir := t.TempDir()
	nonRegoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonRegoDir, "readme.txt"), []byte("no rego here"), 0o600); err != nil {
		t.Fatalf("failed to write readme.txt: %v", err)
	}
	missingPath := filepath.Join(t.TempDir(), "does_not_exist.rego")

	tests := []struct {
		name           string
		paths          []string
		packs          []string
		wantSubstrings []string
	}{
		{
			name:  "NeitherPathsNorPacks_Nil",
			paths: nil,
			packs: nil,
		},
		{
			name:  "NeitherPathsNorPacks_EmptySlices",
			paths: []string{},
			packs: []string{},
		},
		{
			name:  "NeitherPathsNorPacks_WhitespaceOnly",
			paths: []string{"  "},
			packs: []string{" , "},
		},
		{
			name:           "UnknownPackName_ListsValidPacks",
			paths:          nil,
			packs:          []string{"nonexistent"},
			wantSubstrings: []string{"aws", "azure", "gcp", "all"},
		},
		{
			name:           "UnknownPackInCommaList_ListsValidPacks",
			paths:          nil,
			packs:          []string{"aws,oracle"},
			wantSubstrings: []string{"aws", "azure", "gcp", "all"},
		},
		{
			name:           "EmptyDirectory_ZeroRegoFiles",
			paths:          []string{emptyDir},
			packs:          nil,
			wantSubstrings: []string{".rego"},
		},
		{
			name:           "DirectoryWithOnlyNonRegoFiles",
			paths:          []string{nonRegoDir},
			packs:          nil,
			wantSubstrings: []string{".rego"},
		},
		{
			name:  "NonexistentFileOrDirectory",
			paths: []string{missingPath},
			packs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := policy.LoadPolicies(tc.paths, tc.packs)
			if err == nil {
				t.Fatalf("LoadPolicies(%v, %v) expected error, got nil", tc.paths, tc.packs)
			}
			errMsg := strings.ToLower(err.Error())
			for _, sub := range tc.wantSubstrings {
				if !strings.Contains(errMsg, strings.ToLower(sub)) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), sub)
				}
			}
		})
	}
}

func TestLoadPolicies_OversizedPolicyFile_ReturnsSizeLimitError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	oversizedPath := filepath.Join(tmpDir, "oversized.rego")

	// Create a file strictly larger than 2 MiB (33 * 64 KiB = 2,162,688 bytes > 2,097,152 bytes)
	f, err := os.Create(oversizedPath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer f.Close()

	chunk := make([]byte, 64*1024)
	for i := 0; i < 33; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatalf("failed to write chunk: %v", err)
		}
	}
	f.Close()

	t.Run("DirectFilePath", func(t *testing.T) {
		_, err := policy.LoadPolicies([]string{oversizedPath}, nil)
		if err == nil {
			t.Fatalf("expected error for oversized file, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
			t.Errorf("expected size limit error message, got: %v", err)
		}
	})

	t.Run("DirectoryWalk", func(t *testing.T) {
		_, err := policy.LoadPolicies([]string{tmpDir}, nil)
		if err == nil {
			t.Fatalf("expected error for directory containing oversized file, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
			t.Errorf("expected size limit error message, got: %v", err)
		}
	})
}
