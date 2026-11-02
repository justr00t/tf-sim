package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// resolveTestWorkspaceRoot locates the repository root directory containing testdata/.
func resolveTestWorkspaceRoot(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", ".."),
		".",
	}
	for _, cand := range candidates {
		abs, err := filepath.Abs(cand)
		if err != nil {
			continue
		}
		if info, statErr := os.Stat(filepath.Join(abs, "testdata", "policies", "storage_encryption.rego")); statErr == nil && !info.IsDir() {
			return abs
		}
	}
	t.Fatal("unable to locate repository workspace root containing testdata/")
	return ""
}

// newTestServer creates a Server pointed at the repository root workspace with AllowWrite disabled.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	wsRoot := resolveTestWorkspaceRoot(t)
	srv, err := NewServer(Config{
		Addr:         "127.0.0.1:0",
		WorkspaceDir: wsRoot,
		PolicyPath:   "testdata/policies/storage_encryption.rego",
		SchemaPath:   "testdata/schemas/multicloud_schema.json",
		CorpusDir:    "testdata/plans",
		ReposDir:     "testdata/repos",
		Workers:      2,
		AllowWrite:   false,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	return srv
}

// copyWorkspaceToTemp copies testdata/{policies,schemas,plans,repos} into an isolated t.TempDir()
// so disk-mutating tests never touch git-tracked files.
func copyWorkspaceToTemp(t *testing.T) string {
	t.Helper()
	srcRoot := resolveTestWorkspaceRoot(t)
	dstRoot := t.TempDir()

	err := filepath.Walk(filepath.Join(srcRoot, "testdata"), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstRoot, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatalf("copying testdata to temp dir failed: %v", err)
	}
	return dstRoot
}

// snapshotTestdataRepos reads the byte contents of all testdata/repos/*/main.tf files to verify immutability.
func snapshotTestdataRepos(t *testing.T, wsRoot string) map[string][]byte {
	t.Helper()
	files := []string{
		filepath.Join(wsRoot, "testdata", "repos", "payments-aws", "main.tf"),
		filepath.Join(wsRoot, "testdata", "repos", "data-azure", "main.tf"),
		filepath.Join(wsRoot, "testdata", "repos", "ml-gcp", "main.tf"),
	}
	out := make(map[string][]byte, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		out[f] = raw
	}
	return out
}

// TestServer_StaticAssetsAndBaselBrassDNA verifies embedded static assets and Basel Brass design tokens.
func TestServer_StaticAssetsAndBaselBrassDNA(t *testing.T) {
	srv := newTestServer(t)

	t.Run("GET_IndexHTML", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for GET /, got %d", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Errorf("expected Content-Type text/html, got %q", ct)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("expected X-Content-Type-Options: nosniff, got %q", rec.Header().Get("X-Content-Type-Options"))
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("expected X-Frame-Options: DENY, got %q", rec.Header().Get("X-Frame-Options"))
		}

		body := rec.Body.String()
		for _, want := range []string{"tf-sim", "styles.css", "app.js", "STAGE A", "STAGE B", "STAGE C"} {
			if !strings.Contains(body, want) {
				t.Errorf("expected index.html to contain %q", want)
			}
		}
	})

	t.Run("GET_StylesCSS_BaselBrassTokensAndZeroRawHexOutsideRoot", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/styles.css", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for GET /styles.css, got %d", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/css") {
			t.Errorf("expected Content-Type text/css, got %q", ct)
		}

		css := rec.Body.String()
		for _, want := range []string{
			"--neutral-1: #fdfdfc",
			"--accent-9: #d4b550",
			"Newsreader",
			"Archivo",
			"IBM Plex Mono",
			"3px 3px 0 var(--text)",
			"tabular-nums",
		} {
			if !strings.Contains(css, want) {
				t.Errorf("expected styles.css to contain %q", want)
			}
		}

		// Verify zero raw #hex color literals appear outside the :root { ... } block.
		rootEnd := strings.Index(css, "}")
		if rootEnd == -1 {
			t.Fatal("could not find closing brace of :root block in styles.css")
		}
		afterRoot := css[rootEnd+1:]
		hexRe := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)
		if matches := hexRe.FindAllString(afterRoot, -1); len(matches) > 0 {
			t.Errorf("found raw #hex color literals outside :root in styles.css: %v", matches)
		}
	})

	t.Run("GET_AppJS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for GET /app.js, got %d", rec.Code)
		}
		js := rec.Body.String()
		for _, endpoint := range []string{"/api/workspace", "/api/backtest", "/api/remediate", "/api/apply"} {
			if !strings.Contains(js, endpoint) {
				t.Errorf("expected app.js to reference endpoint %q", endpoint)
			}
		}
	})
}

// TestServer_GetWorkspace_DefaultViolationsDetected tests GET /api/workspace default state and payload.
func TestServer_GetWorkspace_DefaultViolationsDetected(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/workspace", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp WorkspaceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling WorkspaceResponse: %v", err)
	}

	if resp.State != StateViolationsDetected {
		t.Errorf("expected state %q, got %q", StateViolationsDetected, resp.State)
	}
	if resp.Verification == nil || !resp.Verification.Valid {
		t.Errorf("expected verification.valid == true, got %+v", resp.Verification)
	}
	if resp.Backtest == nil {
		t.Fatal("expected non-nil backtest report")
	}
	if resp.Backtest.TotalReposAnalyzed != 3 {
		t.Errorf("expected TotalReposAnalyzed == 3, got %d", resp.Backtest.TotalReposAnalyzed)
	}
	if resp.Backtest.BlockedPlansCount != 3 {
		t.Errorf("expected BlockedPlansCount == 3, got %d", resp.Backtest.BlockedPlansCount)
	}
	if resp.Backtest.TotalResources != 6 {
		t.Errorf("expected TotalResources == 6, got %d", resp.Backtest.TotalResources)
	}
	if resp.Backtest.TotalViolations != 3 {
		t.Errorf("expected TotalViolations == 3, got %d", resp.Backtest.TotalViolations)
	}
	if len(resp.Patches) != 3 {
		t.Errorf("expected 3 remediation patches, got %d", len(resp.Patches))
	}
	if len(resp.SnapshotRows) != 3 {
		t.Errorf("expected 3 snapshot rows, got %d", len(resp.SnapshotRows))
	}

	// Verify discovered policies, plans, and schema resource types.
	wantPolicies := map[string]bool{
		"storage_encryption.rego": false,
		"broken_fail_open.rego":   false,
	}
	for _, pol := range resp.AvailablePolicies {
		if _, ok := wantPolicies[pol]; ok {
			wantPolicies[pol] = true
		}
	}
	for pol, found := range wantPolicies {
		if !found {
			t.Errorf("expected available_policies to contain %q, got %v", pol, resp.AvailablePolicies)
		}
	}

	wantPlans := map[string]bool{
		"testdata/plans/repo_payments_aws.json": false,
		"testdata/plans/repo_data_azure.json":   false,
		"testdata/plans/repo_ml_gcp.json":       false,
	}
	for _, row := range resp.SnapshotRows {
		if _, ok := wantPlans[row.SourcePath]; ok {
			wantPlans[row.SourcePath] = true
		}
	}
	for plan, found := range wantPlans {
		if !found {
			t.Errorf("expected snapshot_rows to include %q, got %+v", plan, resp.SnapshotRows)
		}
	}

	for _, resType := range []string{"aws_s3_bucket", "azurerm_storage_account", "google_storage_bucket"} {
		if _, ok := resp.Schemas[resType]; !ok {
			t.Errorf("expected schemas map to contain resource type %q", resType)
		}
	}
}

// TestServer_PostVerify_ValidAndBrokenFailOpen tests POST /api/verify across valid, broken fail-open, and live in-memory Rego.
func TestServer_PostVerify_ValidAndBrokenFailOpen(t *testing.T) {
	wsRoot := resolveTestWorkspaceRoot(t)
	srv := newTestServer(t)

	t.Run("ValidPolicy_StorageEncryption", func(t *testing.T) {
		body, _ := json.Marshal(VerifyRequest{
			PolicyPath: "testdata/policies/storage_encryption.rego",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp VerifyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling VerifyResponse: %v", err)
		}
		if !resp.Valid {
			t.Errorf("expected Valid == true, got false (diagnostics: %+v)", resp.Diagnostics)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics, got %d: %+v", len(resp.Diagnostics), resp.Diagnostics)
		}
	})

	t.Run("BrokenFailOpenPolicy_DetectsLine14AndLine30Typos", func(t *testing.T) {
		body, _ := json.Marshal(VerifyRequest{
			PolicyPath: "testdata/policies/broken_fail_open.rego",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp VerifyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling VerifyResponse: %v", err)
		}
		if resp.Valid {
			t.Fatal("expected Valid == false for broken_fail_open.rego")
		}
		if resp.State != StateFailOpenCaught {
			t.Errorf("expected State == %q, got %q", StateFailOpenCaught, resp.State)
		}
		if len(resp.Diagnostics) != 2 {
			t.Fatalf("expected 2 SchemaDiagnostics, got %d: %+v", len(resp.Diagnostics), resp.Diagnostics)
		}

		foundLine14 := false
		foundLine30 := false
		for _, d := range resp.Diagnostics {
			if d.ResourceType == "azurerm_storage_account" && d.InvalidPath == "https_only_enabled" && d.Line == 14 {
				foundLine14 = true
			}
			if d.ResourceType == "aws_s3_bucket" && d.InvalidPath == "invalid_encrypt" && d.Line == 30 {
				foundLine30 = true
			}
		}
		if !foundLine14 {
			t.Errorf("expected diagnostic for https_only_enabled on line 14, got %+v", resp.Diagnostics)
		}
		if !foundLine30 {
			t.Errorf("expected diagnostic for invalid_encrypt on line 30, got %+v", resp.Diagnostics)
		}
	})

	t.Run("InMemoryPolicyContent_LiveEditDoesNotModifyDisk", func(t *testing.T) {
		diskPolicyPath := filepath.Join(wsRoot, "testdata", "policies", "storage_encryption.rego")
		beforeBytes, err := os.ReadFile(diskPolicyPath)
		if err != nil {
			t.Fatalf("reading storage_encryption.rego: %v", err)
		}

		liveContent := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	rc.change.after.non_existent_gcp_attribute == false
	violation := {
		"rule_id": "GCP-LIVE-TYPO-001",
		"severity": "HIGH",
		"message": "live typo check",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
		body, _ := json.Marshal(VerifyRequest{
			PolicyPath:    "testdata/policies/storage_encryption.rego",
			PolicyContent: liveContent,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp VerifyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling VerifyResponse: %v", err)
		}
		if resp.Valid {
			t.Fatal("expected Valid == false for live policy with attribute typo")
		}
		if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].InvalidPath != "non_existent_gcp_attribute" || resp.Diagnostics[0].Line != 8 {
			t.Errorf("expected 1 diagnostic for non_existent_gcp_attribute on line 8, got %+v", resp.Diagnostics)
		}

		afterBytes, err := os.ReadFile(diskPolicyPath)
		if err != nil {
			t.Fatalf("reading storage_encryption.rego after live verify: %v", err)
		}
		if !bytes.Equal(beforeBytes, afterBytes) {
			t.Error("live in-memory verification unexpectedly modified storage_encryption.rego on disk")
		}
	})
}

// TestServer_PostBacktest_MultiCloudCorpus tests POST /api/backtest against the multi-cloud corpus.
func TestServer_PostBacktest_MultiCloudCorpus(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(BacktestRequest{
		PolicyPath: "testdata/policies/storage_encryption.rego",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/backtest", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp BacktestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling BacktestResponse: %v", err)
	}

	if resp.TotalReposAnalyzed != 3 {
		t.Errorf("expected TotalReposAnalyzed == 3, got %d", resp.TotalReposAnalyzed)
	}
	if resp.ImpactedReposCount != 3 {
		t.Errorf("expected ImpactedReposCount == 3, got %d", resp.ImpactedReposCount)
	}
	if resp.BlockedPlansCount != 3 {
		t.Errorf("expected BlockedPlansCount == 3, got %d", resp.BlockedPlansCount)
	}
	if resp.TotalResources != 6 {
		t.Errorf("expected TotalResources == 6, got %d", resp.TotalResources)
	}
	if resp.TotalViolations != 3 {
		t.Errorf("expected TotalViolations == 3, got %d", resp.TotalViolations)
	}

	for _, prov := range []string{"aws", "azurerm", "google"} {
		if resp.BreakdownByProvider[prov] != 1 {
			t.Errorf("expected BreakdownByProvider[%q] == 1, got %d", prov, resp.BreakdownByProvider[prov])
		}
	}
}

// TestServer_PostRemediateAndApply_SandboxVsDisk tests surgical HCL diff generation, sandbox in-memory apply,
// state reset, and isolated temporary workspace disk writes.
func TestServer_PostRemediateAndApply_SandboxVsDisk(t *testing.T) {
	wsRoot := resolveTestWorkspaceRoot(t)
	srv := newTestServer(t)
	beforeRepoSnapshots := snapshotTestdataRepos(t, wsRoot)

	t.Run("PostRemediate_GeneratesThreeCommentPreservingDiffs", func(t *testing.T) {
		body, _ := json.Marshal(RemediateRequest{
			PolicyPath: "testdata/policies/storage_encryption.rego",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/remediate", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp RemediateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling RemediateResponse: %v", err)
		}
		if len(resp.Patches) != 3 {
			t.Fatalf("expected 3 patches, got %d", len(resp.Patches))
		}

		wantKeys := map[string]string{
			"payments-aws": "# Monthly financial reports bucket",
			"data-azure":   "# Legacy toggle - must be remediated to true",
			"ml-gcp":       "# Must enforce uniform bucket-level IAM access",
		}
		for _, p := range resp.Patches {
			expectedComment, ok := wantKeys[p.Key]
			if !ok {
				t.Errorf("unexpected patch key %q", p.Key)
				continue
			}
			if !strings.Contains(p.PatchedHCL, expectedComment) {
				t.Errorf("expected PatchedHCL for %s to preserve comment %q, got:\n%s", p.Key, expectedComment, p.PatchedHCL)
			}
			if !strings.Contains(p.UnifiedDiff, "@@ ") {
				t.Errorf("expected UnifiedDiff for %s to contain hunk header, got:\n%s", p.Key, p.UnifiedDiff)
			}
			delete(wantKeys, p.Key)
		}
		if len(wantKeys) != 0 {
			t.Errorf("missing expected patch keys: %v", wantKeys)
		}
	})

	t.Run("PostApply_SandboxMode_TransitionsToEnforceReadyAndResetRestoresWithoutDiskMutation", func(t *testing.T) {
		applyBody, _ := json.Marshal(ApplyRequest{
			Write: false,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/apply", bytes.NewReader(applyBody))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for sandbox apply, got %d: %s", rec.Code, rec.Body.String())
		}

		var applyResp ApplyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &applyResp); err != nil {
			t.Fatalf("unmarshaling ApplyResponse: %v", err)
		}
		if applyResp.State != StateEnforceReady {
			t.Errorf("expected state %q after sandbox apply, got %q", StateEnforceReady, applyResp.State)
		}
		if !applyResp.Applied {
			t.Error("expected Applied == true")
		}
		if applyResp.WrittenToDisk {
			t.Error("expected WrittenToDisk == false in sandbox mode")
		}
		if applyResp.BlockedPlansCount != 0 || applyResp.TotalViolations != 0 {
			t.Errorf("expected 0 blocked plans and 0 violations after apply, got blocked=%d violations=%d",
				applyResp.BlockedPlansCount, applyResp.TotalViolations)
		}

		// Subsequent POST /api/backtest must report 0 impacted repos (Enforce-Ready).
		btReq := httptest.NewRequest(http.MethodPost, "/api/backtest", bytes.NewReader([]byte(`{}`)))
		btRec := httptest.NewRecorder()
		srv.ServeHTTP(btRec, btReq)
		if btRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on post-apply backtest, got %d", btRec.Code)
		}
		var btResp BacktestResponse
		if err := json.Unmarshal(btRec.Body.Bytes(), &btResp); err != nil {
			t.Fatalf("unmarshaling BacktestResponse: %v", err)
		}
		if btResp.State != StateEnforceReady || btResp.ImpactedReposCount != 0 || btResp.TotalViolations != 0 {
			t.Errorf("expected post-apply backtest to report enforce-ready with 0 impacted repos, got state=%q impacted=%d violations=%d",
				btResp.State, btResp.ImpactedReposCount, btResp.TotalViolations)
		}

		// Reset restores initial violations-detected state (3/3 impacted repos).
		resetBody, _ := json.Marshal(ApplyRequest{Reset: true})
		resetReq := httptest.NewRequest(http.MethodPost, "/api/apply", bytes.NewReader(resetBody))
		resetRec := httptest.NewRecorder()
		srv.ServeHTTP(resetRec, resetReq)
		if resetRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on reset, got %d", resetRec.Code)
		}
		var resetResp ApplyResponse
		if err := json.Unmarshal(resetRec.Body.Bytes(), &resetResp); err != nil {
			t.Fatalf("unmarshaling reset ApplyResponse: %v", err)
		}
		if resetResp.State != StateViolationsDetected || resetResp.BlockedPlansCount != 3 || resetResp.TotalViolations != 3 {
			t.Errorf("expected reset state %q with 3 blocked plans, got state=%q blocked=%d violations=%d",
				StateViolationsDetected, resetResp.State, resetResp.BlockedPlansCount, resetResp.TotalViolations)
		}

		// Verify git-tracked testdata/repos/*.tf files on disk are 100% unmodified.
		afterRepoSnapshots := snapshotTestdataRepos(t, wsRoot)
		for path, before := range beforeRepoSnapshots {
			if !bytes.Equal(before, afterRepoSnapshots[path]) {
				t.Errorf("sandbox apply/reset modified git-tracked file %s", path)
			}
		}
	})

	t.Run("PostApply_AllowWriteTrue_WritesPatchedHCLToTempWorkspacePreservingComments", func(t *testing.T) {
		tmpWs := copyWorkspaceToTemp(t)
		writableSrv, err := NewServer(Config{
			Addr:         "127.0.0.1:0",
			WorkspaceDir: tmpWs,
			PolicyPath:   "testdata/policies/storage_encryption.rego",
			SchemaPath:   "testdata/schemas/multicloud_schema.json",
			CorpusDir:    "testdata/plans",
			ReposDir:     "testdata/repos",
			Workers:      2,
			AllowWrite:   true,
		})
		if err != nil {
			t.Fatalf("NewServer with AllowWrite=true failed: %v", err)
		}

		applyBody, _ := json.Marshal(ApplyRequest{
			Write: true,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/apply", bytes.NewReader(applyBody))
		rec := httptest.NewRecorder()
		writableSrv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for disk write apply, got %d: %s", rec.Code, rec.Body.String())
		}

		var applyResp ApplyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &applyResp); err != nil {
			t.Fatalf("unmarshaling ApplyResponse: %v", err)
		}
		if !applyResp.WrittenToDisk {
			t.Error("expected WrittenToDisk == true when AllowWrite=true and write=true")
		}

		checks := []struct {
			relPath          string
			wantSnippet      string
			preservedComment string
		}{
			{
				relPath:          filepath.Join("testdata", "repos", "payments-aws", "main.tf"),
				wantSnippet:      `sse_algorithm = "aws:kms"`,
				preservedComment: "# Payments Service - AWS Storage Infrastructure",
			},
			{
				relPath:          filepath.Join("testdata", "repos", "data-azure", "main.tf"),
				wantSnippet:      `https_traffic_only_enabled = true`,
				preservedComment: "# Data Platform - Azure Storage Infrastructure",
			},
			{
				relPath:          filepath.Join("testdata", "repos", "ml-gcp", "main.tf"),
				wantSnippet:      `uniform_bucket_level_access = true`,
				preservedComment: "# Machine Learning Platform - GCP Cloud Storage Infrastructure",
			},
		}

		for _, chk := range checks {
			raw, err := os.ReadFile(filepath.Join(tmpWs, chk.relPath))
			if err != nil {
				t.Fatalf("reading patched %s: %v", chk.relPath, err)
			}
			content := string(raw)
			if !strings.Contains(content, chk.wantSnippet) {
				t.Errorf("expected %s on disk to contain %q, got:\n%s", chk.relPath, chk.wantSnippet, content)
			}
			if !strings.Contains(content, chk.preservedComment) {
				t.Errorf("expected %s on disk to preserve comment %q, got:\n%s", chk.relPath, chk.preservedComment, content)
			}
		}
	})
}

// TestServer_PassCompliantExcludedFromCorpus verifies that pass_compliant.json is excluded from multi-repo corpus runs.
func TestServer_PassCompliantExcludedFromCorpus(t *testing.T) {
	tmpWs := copyWorkspaceToTemp(t)
	passCompliantPath := filepath.Join(tmpWs, "testdata", "plans", "pass_compliant.json")
	compliantJSON := `{
  "format_version": "1.2",
  "terraform_version": "1.8.0",
  "resource_changes": [
    {
      "address": "azurerm_storage_account.extra_compliant",
      "mode": "managed",
      "type": "azurerm_storage_account",
      "name": "extra_compliant",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "name": "extracompliant",
          "https_traffic_only_enabled": true
        }
      }
    }
  ]
}`
	if err := os.WriteFile(passCompliantPath, []byte(compliantJSON), 0o600); err != nil {
		t.Fatalf("writing pass_compliant.json: %v", err)
	}

	srv, err := NewServer(Config{
		WorkspaceDir: tmpWs,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/workspace", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	var resp WorkspaceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling WorkspaceResponse: %v", err)
	}
	if resp.Backtest.TotalReposAnalyzed != 3 || resp.Backtest.TotalResources != 6 {
		t.Errorf("expected pass_compliant.json to be excluded (TotalReposAnalyzed=3, TotalResources=6), got repos=%d resources=%d",
			resp.Backtest.TotalReposAnalyzed, resp.Backtest.TotalResources)
	}
}

// TestServer_StateReset_FromEnforceReadyToViolationsDetected tests state query transitions and backtest reset.
func TestServer_StateReset_FromEnforceReadyToViolationsDetected(t *testing.T) {
	srv := newTestServer(t)

	// Transition to enforce-ready via query param.
	reqReady := httptest.NewRequest(http.MethodGet, "/api/workspace?state=enforce-ready", nil)
	recReady := httptest.NewRecorder()
	srv.ServeHTTP(recReady, reqReady)
	if recReady.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for ?state=enforce-ready, got %d", recReady.Code)
	}

	// Reset via POST /api/backtest {"reset": true}.
	btReq := httptest.NewRequest(http.MethodPost, "/api/backtest", bytes.NewReader([]byte(`{"reset": true}`)))
	btRec := httptest.NewRecorder()
	srv.ServeHTTP(btRec, btReq)
	if btRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for backtest reset, got %d", btRec.Code)
	}
	var btResp BacktestResponse
	if err := json.Unmarshal(btRec.Body.Bytes(), &btResp); err != nil {
		t.Fatalf("unmarshaling BacktestResponse: %v", err)
	}
	if btResp.State != StateViolationsDetected || btResp.BlockedPlansCount != 3 {
		t.Errorf("expected reset backtest to return %q with 3 blocked plans, got state=%q blocked=%d",
			StateViolationsDetected, btResp.State, btResp.BlockedPlansCount)
	}

	// Invalid state query parameter returns 400 Bad Request.
	reqBad := httptest.NewRequest(http.MethodGet, "/api/workspace?state=unknown-state", nil)
	recBad := httptest.NewRecorder()
	srv.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for unsupported state param, got %d", recBad.Code)
	}
}

// TestServer_Security_PathTraversalBlocked verifies strict workspace path containment across all endpoints.
func TestServer_Security_PathTraversalBlocked(t *testing.T) {
	srv := newTestServer(t)
	outsideAbs := t.TempDir()

	traversalCases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{
			name:   "GetWorkspace_ParentTraversal",
			method: http.MethodGet,
			path:   "/api/workspace?policy=../../go.mod",
		},
		{
			name:   "PostVerify_ParentGoMod",
			method: http.MethodPost,
			path:   "/api/verify",
			body:   VerifyRequest{PolicyPath: "../../go.mod"},
		},
		{
			name:   "PostVerify_ParentDesignMd",
			method: http.MethodPost,
			path:   "/api/verify",
			body:   VerifyRequest{PolicyPath: "../DESIGN.md"},
		},
		{
			name:   "PostVerify_SchemaTraversal",
			method: http.MethodPost,
			path:   "/api/verify",
			body:   VerifyRequest{SchemaPath: "../../etc/passwd"},
		},
		{
			name:   "PostVerify_AbsolutePathOutsideWorkspace",
			method: http.MethodPost,
			path:   "/api/verify",
			body:   VerifyRequest{PolicyPath: filepath.Join(outsideAbs, "evil.rego")},
		},
		{
			name:   "PostBacktest_CorpusTraversal",
			method: http.MethodPost,
			path:   "/api/backtest",
			body:   BacktestRequest{CorpusDir: "../.."},
		},
		{
			name:   "PostBacktest_PolicyTraversal",
			method: http.MethodPost,
			path:   "/api/backtest",
			body:   BacktestRequest{PolicyPath: "../DESIGN.md"},
		},
		{
			name:   "PostRemediate_ReposTraversal",
			method: http.MethodPost,
			path:   "/api/remediate",
			body:   RemediateRequest{ReposDir: "../../outside"},
		},
		{
			name:   "PostRemediate_PolicyAbsoluteOutside",
			method: http.MethodPost,
			path:   "/api/remediate",
			body:   RemediateRequest{PolicyPath: filepath.Join(outsideAbs, "evil.rego")},
		},
		{
			name:   "PostApply_ReposTraversal",
			method: http.MethodPost,
			path:   "/api/apply",
			body:   ApplyRequest{ReposDir: "../DESIGN.md"},
		},
		{
			name:   "PostApply_PolicyAbsoluteOutside",
			method: http.MethodPost,
			path:   "/api/apply",
			body:   ApplyRequest{PolicyPath: filepath.Join(outsideAbs, "evil.rego")},
		},
	}

	for _, tc := range traversalCases {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tc.body != nil {
				raw, _ := json.Marshal(tc.body)
				bodyReader = bytes.NewReader(raw)
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
				t.Fatalf("expected 400 Bad Request or 403 Forbidden for %s, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}

			var errPayload map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errPayload); err != nil {
				t.Fatalf("expected JSON error body, got %v: %s", err, rec.Body.String())
			}
			if errPayload["code"] != "path_outside_workspace" && !strings.Contains(errPayload["error"], "outside configured workspace") {
				t.Errorf("expected path_outside_workspace error, got %+v", errPayload)
			}
		})
	}
}

// TestServer_Security_WrongMethodAndForbiddenWrite verifies 405 Method Not Allowed and 403 Forbidden when AllowWrite=false.
func TestServer_Security_WrongMethodAndForbiddenWrite(t *testing.T) {
	srv := newTestServer(t)

	methodCases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/workspace"},
		{http.MethodGet, "/api/verify"},
		{http.MethodGet, "/api/backtest"},
		{http.MethodGet, "/api/remediate"},
		{http.MethodGet, "/api/apply"},
		{http.MethodDelete, "/api/apply"},
	}

	for _, mc := range methodCases {
		t.Run(mc.method+"_"+mc.path, func(t *testing.T) {
			req := httptest.NewRequest(mc.method, mc.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 Method Not Allowed for %s %s, got %d", mc.method, mc.path, rec.Code)
			}
		})
	}

	t.Run("PostApply_WriteTrueWhenAllowWriteFalse_Returns403Forbidden", func(t *testing.T) {
		body, _ := json.Marshal(ApplyRequest{
			Write: true,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/apply", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden when write=true and AllowWrite=false, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("PostRemediate_WriteTrueWhenAllowWriteFalse_Returns403Forbidden", func(t *testing.T) {
		body, _ := json.Marshal(RemediateRequest{
			Write: true,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/remediate", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden when write=true and AllowWrite=false, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

// TestServer_Security_MaxBytesReaderOversizedBody verifies that >2 MiB POST bodies are rejected with 413 Request Entity Too Large.
func TestServer_Security_MaxBytesReaderOversizedBody(t *testing.T) {
	srv := newTestServer(t)
	oversized := `{"policy_content":"` + strings.Repeat("a", MaxRequestBodyBytes+1024) + `"}`

	for _, endpoint := range []string{"/api/verify", "/api/backtest", "/api/remediate", "/api/apply"} {
		t.Run("Oversized_"+endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(oversized))
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
				t.Errorf("expected 413 Request Entity Too Large or 400 Bad Request for %s, got %d", endpoint, rec.Code)
			}
		})
	}
}

// TestServer_InvalidJSONAndMissingFiles verifies error handling for malformed JSON and missing files inside the workspace.
func TestServer_InvalidJSONAndMissingFiles(t *testing.T) {
	srv := newTestServer(t)

	t.Run("MalformedJSON_Returns400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/verify", strings.NewReader(`{"policy_path": `))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for malformed JSON, got %d", rec.Code)
		}
	})

	t.Run("MissingPolicyFileInsideWorkspace_Returns404Or400", func(t *testing.T) {
		body, _ := json.Marshal(VerifyRequest{
			PolicyPath: "testdata/policies/does_not_exist.rego",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Errorf("expected 404 Not Found or 400 Bad Request for missing file, got %d", rec.Code)
		}
	})
}

// TestServer_ListenAndServe_EphemeralPortAndGracefulShutdown verifies live TCP binding on 127.0.0.1:0 and context shutdown.
func TestServer_ListenAndServe_EphemeralPortAndGracefulShutdown(t *testing.T) {
	srv := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx)
	}()

	// Wait until srv.Addr() reflects the bound ephemeral port (not ":0").
	var boundAddr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addr := srv.Addr()
		if addr != "" && !strings.HasSuffix(addr, ":0") {
			boundAddr = addr
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if boundAddr == "" {
		cancel()
		t.Fatal("server did not bind to an ephemeral port within timeout")
	}

	resp, err := http.Get("http://" + boundAddr + "/api/workspace")
	if err != nil {
		cancel()
		t.Fatalf("GET /api/workspace over live TCP failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("expected 200 OK from live server, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			t.Fatalf("expected nil error on graceful context shutdown, got %v", serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return within 5s after context cancellation")
	}
}

// TestServer_EmptyWorkspaceAndCustomUpload verifies the 0-loaded empty workspace state,
// starting in a fresh directory without testdata/, browser file uploads via POST /api/workspace/upload,
// and workspace path configuration via POST /api/workspace/configure.
func TestServer_EmptyWorkspaceAndCustomUpload(t *testing.T) {
	t.Run("FreshDirectoryWithoutTestdata_DefaultsToEmptyState", func(t *testing.T) {
		emptyDir := t.TempDir()
		srv, err := NewServer(Config{
			WorkspaceDir: emptyDir,
		})
		if err != nil {
			t.Fatalf("NewServer on empty directory failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/workspace", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on empty workspace, got %d: %s", rec.Code, rec.Body.String())
		}

		var ws WorkspaceResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &ws); err != nil {
			t.Fatalf("unmarshaling empty WorkspaceResponse: %v", err)
		}
		if !ws.EmptyWorkspace || ws.State != StateEmpty {
			t.Errorf("expected EmptyWorkspace=true and state=%q, got EmptyWorkspace=%v state=%q", StateEmpty, ws.EmptyWorkspace, ws.State)
		}
		if ws.Backtest == nil || ws.Backtest.TotalReposAnalyzed != 0 || ws.Backtest.TotalViolations != 0 {
			t.Errorf("expected 0 repos and 0 violations in empty workspace, got %+v", ws.Backtest)
		}
		if len(ws.SnapshotRows) != 0 {
			t.Errorf("expected 0 snapshot rows in empty workspace, got %d", len(ws.SnapshotRows))
		}
	})

	t.Run("UploadCustomFiles_EvaluatesAndGeneratesPatches", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.clearUploadSandbox()

		customPlan := `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "resource_changes": [
    {
      "address": "azurerm_storage_account.custom_upload_acct",
      "mode": "managed",
      "type": "azurerm_storage_account",
      "name": "custom_upload_acct",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "name": "customuploadacct",
          "https_traffic_only_enabled": false
        }
      }
    }
  ]
}`
		customTF := `resource "azurerm_storage_account" "custom_upload_acct" {
  name                       = "customuploadacct"
  https_traffic_only_enabled = false
}
`
		uploadPayload := WorkspaceUploadRequest{
			UseBuiltinSchema: true,
			PlanFiles: []UploadedFile{
				{Name: "my_custom_azure/plan.json", Content: customPlan},
			},
			TFFiles: []UploadedFile{
				{Name: "my_custom_azure/main.tf", Content: customTF},
			},
		}
		body, _ := json.Marshal(uploadPayload)

		req := httptest.NewRequest(http.MethodPost, "/api/workspace/upload", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from /api/workspace/upload, got %d: %s", rec.Code, rec.Body.String())
		}

		var ws WorkspaceResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &ws); err != nil {
			t.Fatalf("unmarshaling uploaded WorkspaceResponse: %v", err)
		}
		if !ws.CustomUploaded || ws.EmptyWorkspace {
			t.Errorf("expected CustomUploaded=true and EmptyWorkspace=false, got CustomUploaded=%v EmptyWorkspace=%v", ws.CustomUploaded, ws.EmptyWorkspace)
		}
		if ws.Backtest == nil || ws.Backtest.TotalReposAnalyzed != 1 || ws.Backtest.TotalViolations != 1 {
			t.Fatalf("expected 1 repo analyzed and 1 violation for custom upload, got %+v", ws.Backtest)
		}
		if len(ws.SnapshotRows) != 1 || ws.SnapshotRows[0].RepoName != "my_custom_azure" {
			t.Errorf("expected SnapshotRows[0].RepoName='my_custom_azure', got %+v", ws.SnapshotRows)
		}
		if len(ws.Patches) != 1 || ws.Patches[0].ResourceAddress != "azurerm_storage_account.custom_upload_acct" {
			t.Errorf("expected 1 surgical HCL patch for azurerm_storage_account.custom_upload_acct, got %+v", ws.Patches)
		}

		// Switching to state=empty should clear the workspace to 0 / 0
		emptyReq := httptest.NewRequest(http.MethodGet, "/api/workspace?state=empty", nil)
		emptyRec := httptest.NewRecorder()
		srv.ServeHTTP(emptyRec, emptyReq)
		if emptyRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for state=empty, got %d", emptyRec.Code)
		}
		var emptyWS WorkspaceResponse
		_ = json.Unmarshal(emptyRec.Body.Bytes(), &emptyWS)
		if !emptyWS.EmptyWorkspace || emptyWS.Backtest.TotalReposAnalyzed != 0 {
			t.Errorf("expected state=empty to reset repos to 0, got %+v", emptyWS.Backtest)
		}
	})

	t.Run("WorkspaceConfigure_ModesAndPathTraversal", func(t *testing.T) {
		srv := newTestServer(t)

		// 1. Configure mode=empty
		emptyBody, _ := json.Marshal(WorkspaceConfigureRequest{Mode: "empty"})
		reqEmpty := httptest.NewRequest(http.MethodPost, "/api/workspace/configure", bytes.NewReader(emptyBody))
		recEmpty := httptest.NewRecorder()
		srv.ServeHTTP(recEmpty, reqEmpty)
		if recEmpty.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for configure mode=empty, got %d", recEmpty.Code)
		}

		// 2. Configure mode=demo restores the 3-cloud corpus
		demoBody, _ := json.Marshal(WorkspaceConfigureRequest{Mode: "demo"})
		reqDemo := httptest.NewRequest(http.MethodPost, "/api/workspace/configure", bytes.NewReader(demoBody))
		recDemo := httptest.NewRecorder()
		srv.ServeHTTP(recDemo, reqDemo)
		if recDemo.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for configure mode=demo, got %d", recDemo.Code)
		}
		var demoWS WorkspaceResponse
		_ = json.Unmarshal(recDemo.Body.Bytes(), &demoWS)
		if demoWS.EmptyWorkspace || demoWS.Backtest.TotalReposAnalyzed != 3 {
			t.Errorf("expected mode=demo to restore 3 repos, got %+v", demoWS.Backtest)
		}

		// 3. Reject path traversal in configure
		badBody, _ := json.Marshal(WorkspaceConfigureRequest{
			Mode:       "paths",
			PolicyPath: "../../../etc/passwd",
		})
		reqBad := httptest.NewRequest(http.MethodPost, "/api/workspace/configure", bytes.NewReader(badBody))
		recBad := httptest.NewRecorder()
		srv.ServeHTTP(recBad, reqBad)
		if recBad.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for path traversal in /api/workspace/configure, got %d", recBad.Code)
		}
	})
}
