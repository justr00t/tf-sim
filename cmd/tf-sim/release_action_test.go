package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}
	return root
}

func resolveBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, candidate := range []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
		} {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	t.Skip("bash not found")
	return ""
}

func resolveNode(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found")
	}
	return p
}

func buildTestBinary(t *testing.T, outDir string) string {
	t.Helper()
	binName := "tf-sim"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(outDir, binName)
	ldflags := "-X main.version=v0.1.0 -X main.commit=testsha -X main.date=2026-11-21T00:00:00Z"
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\n%s", err, string(out))
	}
	return binPath
}

func packageBinaryArchive(t *testing.T, binPath, osName, archName string) (archiveName string, archiveBytes []byte) {
	t.Helper()
	binBytes, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read binary %s: %v", binPath, err)
	}

	var buf bytes.Buffer
	if osName == "windows" {
		archiveName = fmt.Sprintf("tf-sim_0.1.0_%s_%s.zip", osName, archName)
		zw := zip.NewWriter(&buf)
		fw, err := zw.Create("tf-sim.exe")
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := fw.Write(binBytes); err != nil {
			t.Fatalf("zip write: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("zip close: %v", err)
		}
	} else {
		archiveName = fmt.Sprintf("tf-sim_0.1.0_%s_%s.tar.gz", osName, archName)
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		hdr := &tar.Header{
			Name: "tf-sim",
			Mode: 0o755,
			Size: int64(len(binBytes)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(binBytes); err != nil {
			t.Fatalf("tar write: %v", err)
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("tar close: %v", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}
	return archiveName, buf.Bytes()
}

func parseGitHubOutput(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read GITHUB_OUTPUT %s: %v", path, err)
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("readdir %s: %v", src, err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dst, err)
	}
	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyDir(t, srcPath, dstPath)
			continue
		}
		b, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("read %s: %v", srcPath, err)
		}
		if err := os.WriteFile(dstPath, b, 0o600); err != nil {
			t.Fatalf("write %s: %v", dstPath, err)
		}
	}
}

func TestReleaseConfig_ContractAndSchema(t *testing.T) {
	root := repoRoot(t)

	goreleaserBytes, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yaml: %v", err)
	}
	gr := string(goreleaserBytes)

	requiredGoReleaser := []string{
		"version: 2",
		"CGO_ENABLED=0",
		"-trimpath",
		"-X main.version={{.Version}}",
		"-X main.commit={{.Commit}}",
		"-X main.date={{.Date}}",
		"linux",
		"darwin",
		"windows",
		"amd64",
		"arm64",
		"name_template:",
		"tar.gz",
		"zip",
		"checksums.txt",
		"algorithm: sha256",
		"homebrew_casks:",
		"repository:",
		"homebrew-tap",
		"HOMEBREW_TAP_TOKEN",
		"envOrDefault",
		"isEnvSet",
		"skip_upload:",
	}
	for _, token := range requiredGoReleaser {
		if !strings.Contains(gr, token) {
			t.Errorf(".goreleaser.yaml missing required contract token %q", token)
		}
	}
	if !strings.Contains(gr, "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}") &&
		!strings.Contains(gr, "tf-sim_{{ .Version }}_{{ .Os }}_{{ .Arch }}") {
		t.Errorf(".goreleaser.yaml missing archive name_template matching tf-sim_<Version>_<Os>_<Arch>")
	}

	releaseBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read .github/workflows/release.yml: %v", err)
	}
	rw := string(releaseBytes)
	requiredRelease := []string{
		"permissions: {}",
		"contents: write",
		"contents: read",
		"persist-credentials: false",
		"snapshot:",
		"release:",
		"CGO_ENABLED",
		"go mod verify",
		"go vet",
		"go test",
		"goreleaser/goreleaser-action@v7",
		"--snapshot",
		"release --clean",
	}
	for _, token := range requiredRelease {
		if !strings.Contains(rw, token) {
			t.Errorf("release.yml missing required token %q", token)
		}
	}
}

func TestActionInstall_PinnedAndLatestWithSHA256(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	installScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "install.sh"))

	buildDir := t.TempDir()
	binPath := buildTestBinary(t, buildDir)
	archiveName, archiveBytes := packageBinaryArchive(t, binPath, runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(archiveBytes)
	checksumLine := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archiveName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/justr00t/tf-sim/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v0.1.0"}`))
		case "/v0.1.0/" + archiveName:
			_, _ = w.Write(archiveBytes)
		case "/v0.1.0/checksums.txt":
			_, _ = w.Write([]byte(checksumLine))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	runInstall := func(t *testing.T, extraEnv []string) (installDir string, ghPathFile string) {
		t.Helper()
		tmpDir := t.TempDir()
		installDir = filepath.Join(tmpDir, "install")
		ghPathFile = filepath.Join(tmpDir, "github_path.txt")
		if err := os.WriteFile(ghPathFile, nil, 0o600); err != nil {
			t.Fatalf("write GITHUB_PATH: %v", err)
		}

		cmd := exec.Command(bash, installScript)
		cmd.Env = append(os.Environ(),
			"TFSIM_INSTALL_DIR="+filepath.ToSlash(installDir),
			"TFSIM_RELEASE_BASE_URL="+srv.URL,
			"TFSIM_API_BASE_URL="+srv.URL,
			"TFSIM_OS_OVERRIDE="+runtime.GOOS,
			"TFSIM_ARCH_OVERRIDE="+runtime.GOARCH,
			"GITHUB_PATH="+filepath.ToSlash(ghPathFile),
			"RUNNER_TEMP="+filepath.ToSlash(tmpDir),
		)
		cmd.Env = append(cmd.Env, extraEnv...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install.sh failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "tf-sim version 0.1.0") {
			t.Errorf("expected install.sh to run tf-sim --version (0.1.0), got:\n%s", string(out))
		}
		pathBytes, err := os.ReadFile(ghPathFile)
		if err != nil {
			t.Fatalf("read GITHUB_PATH: %v", err)
		}
		if !strings.Contains(string(pathBytes), filepath.ToSlash(installDir)) &&
			!strings.Contains(string(pathBytes), installDir) {
			t.Errorf("expected GITHUB_PATH %q to contain installDir %q", string(pathBytes), installDir)
		}
		return installDir, ghPathFile
	}

	t.Run("PinnedVersion", func(t *testing.T) {
		runInstall(t, []string{"INPUT_VERSION=v0.1.0"})
	})

	t.Run("LatestVersion", func(t *testing.T) {
		runInstall(t, []string{"INPUT_VERSION=latest"})
	})

	t.Run("PrebuiltBinaryPath", func(t *testing.T) {
		runInstall(t, []string{"INPUT_BINARY_PATH=" + filepath.ToSlash(binPath)})
	})
}

func TestActionInstall_TamperedChecksumRejected(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	installScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "install.sh"))

	buildDir := t.TempDir()
	binPath := buildTestBinary(t, buildDir)
	archiveName, archiveBytes := packageBinaryArchive(t, binPath, runtime.GOOS, runtime.GOARCH)
	badHash := strings.Repeat("a", 64)
	checksumLine := fmt.Sprintf("%s  %s\n", badHash, archiveName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0.1.0/" + archiveName:
			_, _ = w.Write(archiveBytes)
		case "/v0.1.0/checksums.txt":
			_, _ = w.Write([]byte(checksumLine))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	installDir := filepath.Join(tmpDir, "install")

	cmd := exec.Command(bash, installScript)
	cmd.Env = append(os.Environ(),
		"INPUT_VERSION=v0.1.0",
		"TFSIM_INSTALL_DIR="+filepath.ToSlash(installDir),
		"TFSIM_RELEASE_BASE_URL="+srv.URL,
		"TFSIM_OS_OVERRIDE="+runtime.GOOS,
		"TFSIM_ARCH_OVERRIDE="+runtime.GOARCH,
		"RUNNER_TEMP="+filepath.ToSlash(tmpDir),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected install.sh to fail on tampered checksum, stdout:\n%s", stdout.String())
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %v; stderr:\n%s", err, stderr.String())
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "checksum") &&
		!strings.Contains(strings.ToLower(stderr.String()), "sha256") {
		t.Errorf("expected checksum mismatch message on stderr, got:\n%s", stderr.String())
	}
	installedBin := filepath.Join(installDir, "tf-sim")
	if runtime.GOOS == "windows" {
		installedBin += ".exe"
	}
	if _, statErr := os.Stat(installedBin); !os.IsNotExist(statErr) {
		t.Errorf("expected binary NOT to be installed at %s on checksum failure", installedBin)
	}
}

func TestActionInstall_MaliciousVersionRejected(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	installScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "install.sh"))

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	for _, badVer := range []string{"../v0.1.0", "v0.1.0; echo pwned", "v0.1.0?foo=bar"} {
		tmpDir := t.TempDir()
		cmd := exec.Command(bash, installScript)
		cmd.Env = append(os.Environ(),
			"INPUT_VERSION="+badVer,
			"TFSIM_INSTALL_DIR="+filepath.ToSlash(filepath.Join(tmpDir, "install")),
			"TFSIM_RELEASE_BASE_URL="+srv.URL,
			"TFSIM_API_BASE_URL="+srv.URL,
			"RUNNER_TEMP="+filepath.ToSlash(tmpDir),
		)
		err := cmd.Run()
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
			t.Errorf("version %q: expected exit code 2, got %v", badVer, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("expected 0 HTTP requests for malicious versions, got %d", hits.Load())
	}
}

func TestActionRun_ModesAuditWarnEnforce(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	runScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "run.sh"))

	binDir := t.TempDir()
	buildTestBinary(t, binDir)

	repoWork := t.TempDir()
	copyDir(t, filepath.Join(root, "testdata", "repos", "payments-aws"), repoWork)
	origMainTF, err := os.ReadFile(filepath.Join(repoWork, "main.tf"))
	if err != nil {
		t.Fatalf("read copied main.tf: %v", err)
	}

	policyPath := filepath.ToSlash(filepath.Join(root, "testdata", "policies", "storage_encryption.rego"))
	schemaPath := filepath.ToSlash(filepath.Join(root, "testdata", "schemas", "multicloud_schema.json"))
	planPath := filepath.ToSlash(filepath.Join(root, "testdata", "plans", "repo_payments_aws.json"))

	cases := []struct {
		mode           string
		deferExit      string
		wantProcExit   int
		wantOutputExit string
		wantWarning    bool
	}{
		{mode: "audit", deferExit: "false", wantProcExit: 0, wantOutputExit: "0"},
		{mode: "warn", deferExit: "false", wantProcExit: 0, wantOutputExit: "0", wantWarning: true},
		{mode: "enforce", deferExit: "false", wantProcExit: 1, wantOutputExit: "1"},
		{mode: "enforce", deferExit: "true", wantProcExit: 0, wantOutputExit: "1"},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_defer_%s", tc.mode, tc.deferExit), func(t *testing.T) {
			tmpOut := t.TempDir()
			ghOutput := filepath.Join(tmpOut, "github_output.txt")
			ghSummary := filepath.Join(tmpOut, "step_summary.md")
			_ = os.WriteFile(ghOutput, nil, 0o600)
			_ = os.WriteFile(ghSummary, nil, 0o600)

			cmd := exec.Command(bash, runScript)
			cmd.Env = append(os.Environ(),
				"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"INPUT_MODE="+tc.mode,
				"INPUT_POLICY="+policyPath,
				"INPUT_SCHEMA="+schemaPath,
				"INPUT_PLAN="+planPath,
				"INPUT_RUN_VERIFY=true",
				"INPUT_REMEDIATE=true",
				"INPUT_TF_DIR="+filepath.ToSlash(repoWork),
				"INPUT_WORKING_DIRECTORY="+filepath.ToSlash(root),
				"INPUT_COMMENT_KEY=payments-aws",
				"TFSIM_DEFER_VIOLATION_EXIT="+tc.deferExit,
				"RUNNER_TEMP="+filepath.ToSlash(tmpOut),
				"GITHUB_OUTPUT="+filepath.ToSlash(ghOutput),
				"GITHUB_STEP_SUMMARY="+filepath.ToSlash(ghSummary),
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			gotExit := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					gotExit = exitErr.ExitCode()
				} else {
					t.Fatalf("run.sh failed unexpectedly: %v", err)
				}
			}
			if gotExit != tc.wantProcExit {
				t.Fatalf("expected process exit %d, got %d; stdout:\n%s\nstderr:\n%s",
					tc.wantProcExit, gotExit, stdout.String(), stderr.String())
			}
			if tc.wantWarning && !strings.Contains(stdout.String(), "::warning") {
				t.Errorf("expected ::warning annotation on stdout in warn mode, got:\n%s", stdout.String())
			}

			outputs := parseGitHubOutput(t, ghOutput)
			if outputs["exit-code"] != tc.wantOutputExit {
				t.Errorf("expected exit-code=%s, got %q", tc.wantOutputExit, outputs["exit-code"])
			}
			if outputs["violations-count"] != "1" {
				t.Errorf("expected violations-count=1, got %q", outputs["violations-count"])
			}
			if outputs["patches-count"] != "1" {
				t.Errorf("expected patches-count=1, got %q", outputs["patches-count"])
			}

			sarifBytes, err := os.ReadFile(outputs["sarif-file"])
			if err != nil {
				t.Fatalf("read sarif-file %q: %v", outputs["sarif-file"], err)
			}
			var sarif map[string]any
			if err := json.Unmarshal(sarifBytes, &sarif); err != nil {
				t.Fatalf("invalid SARIF JSON: %v", err)
			}
			if sarif["version"] != "2.1.0" {
				t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
			}

			mdBytes, err := os.ReadFile(outputs["markdown-file"])
			if err != nil {
				t.Fatalf("read markdown-file %q: %v", outputs["markdown-file"], err)
			}
			md := string(mdBytes)
			if !strings.HasPrefix(md, "<!-- tf-sim-sticky-comment:key=payments-aws -->") {
				t.Errorf("expected sticky comment marker on line 1, got:\n%s", md)
			}
			if !strings.Contains(md, "<details>") || (!strings.Contains(md, "```diff") && !strings.Contains(md, "~~~diff")) {
				t.Errorf("expected collapsible <details> HCL diff in markdown, got:\n%s", md)
			}

			afterMainTF, err := os.ReadFile(filepath.Join(repoWork, "main.tf"))
			if err != nil {
				t.Fatalf("read main.tf after run: %v", err)
			}
			if !bytes.Equal(origMainTF, afterMainTF) {
				t.Errorf("expected main.tf to remain unmutated on disk")
			}
		})
	}
}

func TestActionRun_CompliantPlanPassesAllModes(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	runScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "run.sh"))

	binDir := t.TempDir()
	buildTestBinary(t, binDir)

	tmpOut := t.TempDir()
	ghOutput := filepath.Join(tmpOut, "github_output.txt")
	_ = os.WriteFile(ghOutput, nil, 0o600)

	planPath := filepath.ToSlash(filepath.Join(root, "testdata", "starter_pack_fixtures", "pass", "aws_pass.json"))
	cmd := exec.Command(bash, runScript)
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"INPUT_MODE=enforce",
		"INPUT_PACK=aws",
		"INPUT_PLAN="+planPath,
		"INPUT_RUN_VERIFY=true",
		"INPUT_REMEDIATE=true",
		"INPUT_WORKING_DIRECTORY="+filepath.ToSlash(root),
		"RUNNER_TEMP="+filepath.ToSlash(tmpOut),
		"GITHUB_OUTPUT="+filepath.ToSlash(ghOutput),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected compliant plan to exit 0, got %v\nOutput:\n%s", err, string(out))
	}

	outputs := parseGitHubOutput(t, ghOutput)
	if outputs["exit-code"] != "0" {
		t.Errorf("expected exit-code=0, got %q", outputs["exit-code"])
	}
	if outputs["violations-count"] != "0" {
		t.Errorf("expected violations-count=0, got %q", outputs["violations-count"])
	}
	if outputs["patches-count"] != "0" {
		t.Errorf("expected patches-count=0, got %q", outputs["patches-count"])
	}

	sarifBytes, err := os.ReadFile(outputs["sarif-file"])
	if err != nil {
		t.Fatalf("read sarif-file: %v", err)
	}
	var sarif struct {
		Runs []struct {
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifBytes, &sarif); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if len(sarif.Runs) == 0 || len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected SARIF with 0 results, got %+v", sarif.Runs)
	}

	mdBytes, err := os.ReadFile(outputs["markdown-file"])
	if err != nil {
		t.Fatalf("read markdown-file: %v", err)
	}
	if !strings.Contains(string(mdBytes), "✅") {
		t.Errorf("expected ✅ Passed in markdown summary, got:\n%s", string(mdBytes))
	}
}

func TestActionRun_PreservesExitError2InAuditAndWarn(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	runScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "run.sh"))

	binDir := t.TempDir()
	buildTestBinary(t, binDir)
	policyPath := filepath.ToSlash(filepath.Join(root, "testdata", "policies", "storage_encryption.rego"))

	cases := []struct {
		name string
		env  []string
	}{
		{
			name: "MissingPlan_Audit",
			env: []string{
				"INPUT_MODE=audit",
				"INPUT_POLICY=" + policyPath,
				"INPUT_PLAN=nonexistent.json",
				"TFSIM_DEFER_VIOLATION_EXIT=true",
			},
		},
		{
			name: "MissingPlan_Warn",
			env: []string{
				"INPUT_MODE=warn",
				"INPUT_POLICY=" + policyPath,
				"INPUT_PLAN=nonexistent.json",
				"TFSIM_DEFER_VIOLATION_EXIT=true",
			},
		},
		{
			name: "InvalidMode",
			env: []string{
				"INPUT_MODE=invalid",
				"INPUT_POLICY=" + policyPath,
			},
		},
		{
			name: "EmptyPolicyAndPack_Audit",
			env: []string{
				"INPUT_MODE=audit",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpOut := t.TempDir()
			cmd := exec.Command(bash, runScript)
			cmd.Env = append(os.Environ(),
				"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"INPUT_WORKING_DIRECTORY="+filepath.ToSlash(root),
				"RUNNER_TEMP="+filepath.ToSlash(tmpOut),
			)
			cmd.Env = append(cmd.Env, tc.env...)
			err := cmd.Run()
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
				t.Fatalf("expected ExitError (2), got %v", err)
			}
		})
	}
}

func TestActionCommentScript_CreateUpdateAndPagination(t *testing.T) {
	node := resolveNode(t)
	root := repoRoot(t)
	commentScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "comment.cjs"))

	tmpDir := t.TempDir()
	bodyFile := filepath.Join(tmpDir, "comment.md")
	marker := "<!-- tf-sim-sticky-comment:key=stack-a -->"
	body := marker + "\n## tf-sim Report\n"
	if err := os.WriteFile(bodyFile, []byte(body), 0o600); err != nil {
		t.Fatalf("write comment body: %v", err)
	}

	harness := filepath.Join(tmpDir, "harness.cjs")
	harnessCode := `
const postComment = require(process.argv[2]);
const mode = process.argv[3];

(async () => {
  const calls = { created: [], updated: [], warnings: [] };
  const botUser = { login: "github-actions[bot]", type: "Bot" };
  const humanUser = { login: "attacker", type: "User" };
  const page1 = [{ id: 10, user: botUser, body: "<!-- tf-sim-sticky-comment:key=other -->\nold" }];
  let page2;
  if (mode === "update") {
    page2 = [{ id: 42, user: botUser, body: "<!-- tf-sim-sticky-comment:key=stack-a -->\nprevious" }];
  } else if (mode === "spoofed") {
    page2 = [{ id: 77, user: humanUser, body: "<!-- tf-sim-sticky-comment:key=stack-a -->\nspoofed" }];
  } else {
    page2 = [{ id: 11, user: humanUser, body: "unrelated comment" }];
  }

  const github = {
    paginate: async () => [...page1, ...page2],
    rest: {
      issues: {
        listComments: () => {},
        createComment: async (args) => { calls.created.push(args); return { data: { id: 99 } }; },
        updateComment: async (args) => { calls.updated.push(args); return { data: { id: args.comment_id } }; }
      }
    }
  };
  const context = {
    repo: { owner: "justr00t", repo: "tf-sim" },
    payload: { pull_request: { number: 7 } },
    issue: { number: 7 }
  };
  const core = {
    info: () => {},
    warning: (m) => calls.warnings.push(m)
  };

  const res = await postComment({ github, context, core });
  process.stdout.write(JSON.stringify({ res, calls }));
})();
`
	if err := os.WriteFile(harness, []byte(harnessCode), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	t.Run("CreateWhenAbsent", func(t *testing.T) {
		cmd := exec.Command(node, harness, commentScript, "create")
		cmd.Env = append(os.Environ(),
			"COMMENT_BODY_FILE="+bodyFile,
			"COMMENT_MARKER="+marker,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("node harness failed: %v\n%s", err, string(out))
		}
		var result struct {
			Calls struct {
				Created []map[string]any `json:"created"`
				Updated []map[string]any `json:"updated"`
			} `json:"calls"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("unmarshal harness output: %v\n%s", err, string(out))
		}
		if len(result.Calls.Created) != 1 || len(result.Calls.Updated) != 0 {
			t.Errorf("expected 1 createComment and 0 updateComment, got %+v", result.Calls)
		}
	})

	t.Run("UpdateMatchingOnPage2", func(t *testing.T) {
		cmd := exec.Command(node, harness, commentScript, "update")
		cmd.Env = append(os.Environ(),
			"COMMENT_BODY_FILE="+bodyFile,
			"COMMENT_MARKER="+marker,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("node harness failed: %v\n%s", err, string(out))
		}
		var result struct {
			Calls struct {
				Created []map[string]any `json:"created"`
				Updated []struct {
					CommentID int `json:"comment_id"`
				} `json:"updated"`
			} `json:"calls"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("unmarshal harness output: %v\n%s", err, string(out))
		}
		if len(result.Calls.Updated) != 1 || result.Calls.Updated[0].CommentID != 42 {
			t.Errorf("expected 1 updateComment with comment_id 42, got %+v", result.Calls.Updated)
		}
		if len(result.Calls.Created) != 0 {
			t.Errorf("expected 0 createComment, got %+v", result.Calls.Created)
		}
	})

	t.Run("IgnoreSpoofedNonBotMarker", func(t *testing.T) {
		cmd := exec.Command(node, harness, commentScript, "spoofed")
		cmd.Env = append(os.Environ(),
			"COMMENT_BODY_FILE="+bodyFile,
			"COMMENT_MARKER="+marker,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("node harness failed: %v\n%s", err, string(out))
		}
		var result struct {
			Calls struct {
				Created []map[string]any `json:"created"`
				Updated []map[string]any `json:"updated"`
			} `json:"calls"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("unmarshal harness output: %v\n%s", err, string(out))
		}
		if len(result.Calls.Created) != 1 || len(result.Calls.Updated) != 0 {
			t.Errorf("expected spoofed non-bot comment to be ignored (1 create, 0 update), got %+v", result.Calls)
		}
	})
}

func TestActionCommentScript_ForkPR403GracefulSkip(t *testing.T) {
	node := resolveNode(t)
	root := repoRoot(t)
	commentScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "comment.cjs"))

	tmpDir := t.TempDir()
	bodyFile := filepath.Join(tmpDir, "comment.md")
	marker := "<!-- tf-sim-sticky-comment:key=default -->"
	if err := os.WriteFile(bodyFile, []byte(marker+"\nreport\n"), 0o600); err != nil {
		t.Fatalf("write comment body: %v", err)
	}

	harness := filepath.Join(tmpDir, "harness403.cjs")
	harnessCode := `
const postComment = require(process.argv[2]);
const where = process.argv[3];
(async () => {
  const warnings = [];
  const make403 = () => {
    const err = new Error("Resource not accessible by integration");
    err.status = 403;
    return err;
  };
  const github = {
    paginate: async () => {
      if (where === "list") throw make403();
      return [];
    },
    rest: {
      issues: {
        listComments: () => {},
        createComment: async () => { throw make403(); },
        updateComment: async () => {}
      }
    }
  };
  const context = {
    repo: { owner: "justr00t", repo: "tf-sim" },
    payload: { pull_request: { number: 12 } }
  };
  const core = {
    info: () => {},
    warning: (m) => warnings.push(m)
  };
  const res = await postComment({ github, context, core });
  process.stdout.write(JSON.stringify({ res, warnings }));
})();
`
	if err := os.WriteFile(harness, []byte(harnessCode), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	for _, where := range []string{"create", "list"} {
		t.Run("Forbidden_"+where, func(t *testing.T) {
			cmd := exec.Command(node, harness, commentScript, where)
			cmd.Env = append(os.Environ(),
				"COMMENT_BODY_FILE="+bodyFile,
				"COMMENT_MARKER="+marker,
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("expected fork PR 403 (%s) to resolve cleanly (exit 0), got %v\n%s", where, err, string(out))
			}
			var result struct {
				Res struct {
					Action string `json:"action"`
				} `json:"res"`
				Warnings []string `json:"warnings"`
			}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatalf("unmarshal output: %v\n%s", err, string(out))
			}
			if len(result.Warnings) == 0 {
				t.Errorf("expected core.warning to be called on 403 (%s), got none", where)
			}
			if result.Res.Action != "forbidden-skipped" {
				t.Errorf("expected action=forbidden-skipped (%s), got %q", where, result.Res.Action)
			}
		})
	}
}

func TestActionComment_65kLimitTruncation(t *testing.T) {
	bash := resolveBash(t)
	root := repoRoot(t)
	runScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "run.sh"))

	mockBinDir := t.TempDir()
	mockScript := `#!/usr/bin/env node
const args = process.argv.slice(2);
const cmd = args[0];
const fmtIdx = args.indexOf("--format");
const fmt = fmtIdx >= 0 ? args[fmtIdx + 1] : "table";

if (cmd === "eval") {
  if (fmt === "json") {
    process.stdout.write(JSON.stringify({ passed: false, violations: [{ rule_id: "TEST-001", severity: "high", resource: "aws_s3_bucket.b", message: "bad" }] }));
    process.exit(1);
  }
  if (fmt === "sarif") {
    process.stdout.write(JSON.stringify({ version: "2.1.0", runs: [{ results: [{ ruleId: "TEST-001" }] }] }));
    process.exit(1);
  }
  process.stdout.write("## Eval\n1 violation\n");
  process.exit(1);
}
if (cmd === "remediate") {
  if (fmt === "json") {
    process.stdout.write(JSON.stringify([{ file: "main.tf", resource: "aws_s3_bucket.b" }]));
    process.exit(0);
  }
  const fence = String.fromCharCode(96).repeat(3);
  const hugeDiff = "+  attribute = \"value_padding_1234567890\"\n".repeat(2000);
  process.stdout.write("### Patch\n" + fence + "diff\n" + hugeDiff + fence + "\n");
  process.exit(0);
}
process.exit(0);
`

	mockPath := filepath.Join(mockBinDir, "tf-sim")
	if err := os.WriteFile(mockPath, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("write mock tf-sim: %v", err)
	}
	if runtime.GOOS == "windows" {
		// Create a .cmd shim so Windows bash/PATH resolves tf-sim cleanly if needed.
		cmdShim := "@echo off\r\nnode \"" + mockPath + "\" %*\r\n"
		if err := os.WriteFile(filepath.Join(mockBinDir, "tf-sim.cmd"), []byte(cmdShim), 0o600); err != nil {
			t.Fatalf("write tf-sim.cmd: %v", err)
		}
	}

	tmpOut := t.TempDir()
	ghOutput := filepath.Join(tmpOut, "github_output.txt")
	_ = os.WriteFile(ghOutput, nil, 0o600)

	cmd := exec.Command(bash, runScript)
	cmd.Env = append(os.Environ(),
		"PATH="+mockBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"INPUT_MODE=audit",
		"INPUT_PACK=aws",
		"INPUT_PLAN=plan.json",
		"INPUT_RUN_VERIFY=false",
		"INPUT_REMEDIATE=true",
		"INPUT_WORKING_DIRECTORY="+filepath.ToSlash(root),
		"RUNNER_TEMP="+filepath.ToSlash(tmpOut),
		"GITHUB_OUTPUT="+filepath.ToSlash(ghOutput),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run.sh failed: %v\n%s", err, string(out))
	}

	outputs := parseGitHubOutput(t, ghOutput)
	mdBytes, err := os.ReadFile(outputs["markdown-file"])
	if err != nil {
		t.Fatalf("read markdown-file: %v", err)
	}
	md := string(mdBytes)
	if len(mdBytes) > 65000 {
		t.Errorf("expected comment.md <= 65000 bytes, got %d", len(mdBytes))
	}
	if !strings.HasPrefix(md, "<!-- tf-sim-sticky-comment:key=default -->") {
		t.Errorf("expected line-1 sticky marker preserved")
	}
	if !strings.Contains(md, "</details>") {
		t.Errorf("expected closing </details> tag after truncation")
	}
	if !strings.Contains(strings.ToLower(md), "truncat") {
		t.Errorf("expected truncation notice in comment.md")
	}
}

func TestActionFiles_NoScriptInjectionAndLFEndings(t *testing.T) {
	root := repoRoot(t)

	lfFiles := []string{
		filepath.Join(root, ".gitattributes"),
		filepath.Join(root, ".github", "action", "install.sh"),
		filepath.Join(root, ".github", "action", "run.sh"),
		filepath.Join(root, ".github", "action", "comment.cjs"),
	}
	for _, f := range lfFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if bytes.Contains(b, []byte("\r\n")) {
			t.Errorf("file %s contains CRLF (\\r\\n) bytes; must be pure LF", f)
		}
	}

	yamlFiles := []string{
		filepath.Join(root, "action.yml"),
		filepath.Join(root, ".github", "workflows", "release.yml"),
	}
	runOrScriptHeader := regexp.MustCompile(`^(\s*)(?:-\s*)?(run|script):\s*(.*)$`)
	for _, yf := range yamlFiles {
		b, err := os.ReadFile(yf)
		if err != nil {
			t.Fatalf("read %s: %v", yf, err)
		}
		lines := strings.Split(string(b), "\n")
		inBlock := false
		blockIndent := 0
		for i, raw := range lines {
			line := strings.TrimRight(raw, "\r")
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if inBlock {
				if indent > blockIndent {
					if strings.Contains(line, "${{") {
						t.Errorf("%s:%d: forbidden ${{ }} expression inside run:/script: block: %s", yf, i+1, line)
					}
					continue
				}
				inBlock = false
			}
			if m := runOrScriptHeader.FindStringSubmatch(line); m != nil {
				val := strings.TrimSpace(m[3])
				if strings.HasPrefix(val, "|") || strings.HasPrefix(val, ">") {
					inBlock = true
					blockIndent = len(m[1])
				} else if strings.Contains(val, "${{") {
					t.Errorf("%s:%d: forbidden ${{ }} expression on run:/script: line: %s", yf, i+1, line)
				}
			}
		}
	}
}

func TestReadme_CICDIntegrationSnippets(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(b)

	required := []string{
		"brew install --cask justr00t/tap/tf-sim",
		"checksums.txt",
		"sha256sum",
		"justr00t/tf-sim@v0.1.0",
		".gitlab-ci.yml",
		"repos.yaml",
		"$SHOWFILE",
		"policy_check",
		"tf-sim verify",
		"tf-sim eval",
		"tf-sim remediate",
	}
	for _, token := range required {
		if !strings.Contains(readme, token) {
			t.Errorf("README.md missing required CI/CD or install token %q", token)
		}
	}
}

func TestGitHubAction_RunSh_SkippedDiagnosticsAndLegacyArrayCompat(t *testing.T) {
	bash := resolveBash(t)
	_ = resolveNode(t)
	root := repoRoot(t)
	runScript := filepath.ToSlash(filepath.Join(root, ".github", "action", "run.sh"))

	runMockCase := func(t *testing.T, remJSON string, wantIncludeSkippedFlag bool) (map[string]string, string) {
		t.Helper()
		mockBinDir := t.TempDir()
		mockScript := `#!/usr/bin/env node
const args = process.argv.slice(2);
const cmd = args[0];
const fmtIdx = args.indexOf("--format");
const fmt = fmtIdx >= 0 ? args[fmtIdx + 1] : "table";

if (cmd === "eval") {
  if (fmt === "json") {
    process.stdout.write(JSON.stringify({ passed: false, violations: [{ rule_id: "TEST-001", severity: "high", resource: "aws_s3_bucket.b", message: "bad" }] }));
    process.exit(1);
  }
  if (fmt === "sarif") {
    process.stdout.write(JSON.stringify({ version: "2.1.0", runs: [{ results: [{ ruleId: "TEST-001" }] }] }));
    process.exit(1);
  }
  process.stdout.write("## Eval\n1 violation\n");
  process.exit(1);
}
if (cmd === "remediate") {
  if (fmt === "json") {
    if (process.env.EXPECT_INCLUDE_SKIPPED === "true" && !args.includes("--include-skipped")) {
      process.stderr.write("missing --include-skipped flag");
      process.exit(2);
    }
    process.stdout.write(process.env.MOCK_REM_JSON);
    process.exit(0);
  }
  process.stdout.write("### Patch 1\n" + String.fromCharCode(96).repeat(3) + "diff\n+  encrypted = true\n" + String.fromCharCode(96).repeat(3) + "\n");
  process.exit(0);
}
process.exit(0);
`
		mockPath := filepath.Join(mockBinDir, "tf-sim")
		if err := os.WriteFile(mockPath, []byte(mockScript), 0o755); err != nil {
			t.Fatalf("write mock tf-sim: %v", err)
		}
		if runtime.GOOS == "windows" {
			cmdShim := "@echo off\r\nnode \"" + mockPath + "\" %*\r\n"
			if err := os.WriteFile(filepath.Join(mockBinDir, "tf-sim.cmd"), []byte(cmdShim), 0o600); err != nil {
				t.Fatalf("write tf-sim.cmd: %v", err)
			}
		}

		tmpOut := t.TempDir()
		ghOutput := filepath.Join(tmpOut, "github_output.txt")
		_ = os.WriteFile(ghOutput, nil, 0o600)

		expectFlag := "false"
		if wantIncludeSkippedFlag {
			expectFlag = "true"
		}

		cmd := exec.Command(bash, runScript)
		cmd.Env = append(os.Environ(),
			"PATH="+mockBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"INPUT_MODE=audit",
			"INPUT_PACK=aws",
			"INPUT_PLAN=plan.json",
			"INPUT_RUN_VERIFY=false",
			"INPUT_REMEDIATE=true",
			"INPUT_WORKING_DIRECTORY="+filepath.ToSlash(root),
			"RUNNER_TEMP="+filepath.ToSlash(tmpOut),
			"GITHUB_OUTPUT="+filepath.ToSlash(ghOutput),
			"MOCK_REM_JSON="+remJSON,
			"EXPECT_INCLUDE_SKIPPED="+expectFlag,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run.sh failed: %v\n%s", err, string(out))
		}

		outputs := parseGitHubOutput(t, ghOutput)
		mdBytes, err := os.ReadFile(outputs["markdown-file"])
		if err != nil {
			t.Fatalf("read markdown-file: %v", err)
		}
		return outputs, string(mdBytes)
	}

	t.Run("ReportObject_ZeroPatches_TwoSkipped", func(t *testing.T) {
		payload := `{"patches":[],"skipped":[{"rule_id":"aws-s3-pab-acls","severity":"HIGH","resource_address":"module.ext.aws_s3_bucket_public_access_block.this","reason":"external_module_source","detail":"External | registry\nmodule","guidance":"Pass input | override"},{"rule_id":"gcp-sql-ssl","severity":"HIGH","resource_address":"google_sql_database_instance.db","reason":"missing_remediation_metadata","detail":"Advisory rule","guidance":"Enable SSL"}],"summary":{"total_violations":2,"patched_count":0,"skipped_count":2}}`
		outputs, md := runMockCase(t, payload, true)

		if outputs["patches-count"] != "0" {
			t.Errorf("patches-count = %q, want 0", outputs["patches-count"])
		}
		if outputs["skipped-count"] != "2" {
			t.Errorf("skipped-count = %q, want 2", outputs["skipped-count"])
		}
		if !strings.Contains(md, "| **Manual Review (`remediate`)** | 2 |") {
			t.Errorf("summary.md missing Manual Review row:\n%s", md)
		}
		if !strings.Contains(md, "Manual Remediation Diagnostics (2 skipped violation(s))") {
			t.Errorf("summary.md missing Manual Remediation Diagnostics details block:\n%s", md)
		}
		if strings.Contains(md, "Surgical HCL Auto-Remediation Diff") {
			t.Errorf("summary.md should not render Surgical HCL Auto-Remediation Diff when patches-count=0:\n%s", md)
		}
		if !strings.Contains(md, `\|`) {
			t.Errorf("expected escaped pipe in manual-review table:\n%s", md)
		}
	})

	t.Run("ReportObject_OnePatch_OneSkipped", func(t *testing.T) {
		payload := `{"patches":[{"file_path":"main.tf","resource_address":"aws_ebs_volume.a"}],"skipped":[{"rule_id":"gcp-sql-ssl","severity":"HIGH","resource_address":"google_sql_database_instance.db","reason":"missing_remediation_metadata","detail":"Advisory rule","guidance":"Enable SSL"}],"summary":{"total_violations":2,"patched_count":1,"skipped_count":1}}`
		outputs, md := runMockCase(t, payload, true)

		if outputs["patches-count"] != "1" || outputs["skipped-count"] != "1" {
			t.Errorf("unexpected counts: patches=%q skipped=%q", outputs["patches-count"], outputs["skipped-count"])
		}
		if !strings.Contains(md, "Surgical HCL Auto-Remediation Diff (1 patch(es))") {
			t.Errorf("summary.md missing patch details block:\n%s", md)
		}
		if !strings.Contains(md, "Manual Remediation Diagnostics (1 skipped violation(s))") {
			t.Errorf("summary.md missing skipped details block:\n%s", md)
		}
	})

	t.Run("LegacyArray_BackwardsCompat", func(t *testing.T) {
		payload := `[{"file_path":"main.tf","resource_address":"aws_ebs_volume.a"}]`
		outputs, md := runMockCase(t, payload, false)

		if outputs["patches-count"] != "1" || outputs["skipped-count"] != "0" {
			t.Errorf("unexpected counts for legacy array: patches=%q skipped=%q", outputs["patches-count"], outputs["skipped-count"])
		}
		if strings.Contains(md, "Manual Remediation Diagnostics") {
			t.Errorf("summary.md should not render Manual Remediation Diagnostics for legacy array:\n%s", md)
		}
	})
}
