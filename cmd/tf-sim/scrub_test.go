package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
)

func TestCLI_Scrub_FileStdinStdoutAndPretty(t *testing.T) {
	ctx := context.Background()
	rawPlan := `{"format_version":"1.2","terraform_version":"1.9.0","prior_state":{"secret":"prior"},"resource_changes":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","change":{"actions":["create"],"before":null,"after":{"bucket":"my-bucket","password":"pw-secret","extra_secret":"custom-val"}}}]}`

	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "in.json")
	if err := os.WriteFile(inPath, []byte(rawPlan), 0o600); err != nil {
		t.Fatalf("write in.json failed: %v", err)
	}

	t.Run("FileToFile_Compact", func(t *testing.T) {
		outPath := filepath.Join(tmpDir, "out.json")
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", inPath, "--out", outPath}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("expected empty stdout when --out is set, got: %s", stdout.String())
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read out.json failed: %v", err)
		}
		trimmed := strings.TrimSpace(string(b))
		if strings.Contains(trimmed, "\n") {
			t.Errorf("expected single-line compact JSON, got:\n%s", trimmed)
		}
		if strings.Contains(trimmed, "pw-secret") || strings.Contains(trimmed, "prior_state") {
			t.Errorf("output leaked secret or prior_state: %s", trimmed)
		}
	})

	t.Run("FileToStdout", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", inPath}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}
		if strings.Contains(stdout.String(), "pw-secret") {
			t.Errorf("stdout leaked secret")
		}
	})

	t.Run("StdinToStdout_ViaRootCmdSetIn", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		rootCmd := NewRootCmd(&stdout, &stderr)
		rootCmd.SetIn(strings.NewReader(rawPlan))
		rootCmd.SetArgs([]string{"scrub", "--plan", "-", "--out", "-"})
		if err := rootCmd.ExecuteContext(ctx); err != nil {
			t.Fatalf("ExecuteContext failed: %v; stderr: %s", err, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}
		if strings.Contains(stdout.String(), "pw-secret") || !strings.Contains(stdout.String(), `"resource_changes"`) {
			t.Errorf("unexpected stdout: %s", stdout.String())
		}
	})

	t.Run("StdinToFile_ViaRootCmdSetIn", func(t *testing.T) {
		outPath := filepath.Join(tmpDir, "stdin_out.json")
		var stdout, stderr bytes.Buffer
		rootCmd := NewRootCmd(&stdout, &stderr)
		rootCmd.SetIn(strings.NewReader(rawPlan))
		rootCmd.SetArgs([]string{"scrub", "--plan", "-", "--out", outPath})
		if err := rootCmd.ExecuteContext(ctx); err != nil {
			t.Fatalf("ExecuteContext failed: %v; stderr: %s", err, stderr.String())
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read stdin_out.json failed: %v", err)
		}
		if strings.Contains(string(b), "pw-secret") {
			t.Errorf("file leaked secret")
		}
	})

	t.Run("PrettyAndRedactKey", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"scrub",
			"--plan", inPath,
			"--pretty",
			"--redact-key", "extra_secret",
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		outStr := stdout.String()
		if !strings.Contains(outStr, "\n  \"format_version\"") {
			t.Errorf("expected 2-space indented JSON, got:\n%s", outStr)
		}
		if strings.Contains(outStr, "custom-val") {
			t.Errorf("expected extra_secret to be redacted, got:\n%s", outStr)
		}
	})
}

func TestCLI_Scrub_MissingPlanFlag(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer
	code := Execute(ctx, []string{"scrub"}, &stdout, &stderr)
	if code != ExitError {
		t.Errorf("expected ExitError (%d), got %d", ExitError, code)
	}
	if stderr.Len() == 0 {
		t.Errorf("expected error message on stderr")
	}
}

func TestCLI_Scrub_PlanNotFoundOrDirectory(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	t.Run("NonexistentPlan", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", filepath.Join(tmpDir, "missing.json")}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("expected ExitError (%d), got %d", ExitError, code)
		}
		if stderr.Len() == 0 {
			t.Errorf("expected error on stderr")
		}
	})

	t.Run("PlanIsDirectory", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", tmpDir}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("expected ExitError (%d), got %d", ExitError, code)
		}
		if stderr.Len() == 0 {
			t.Errorf("expected error on stderr")
		}
	})
}

func TestCLI_Scrub_OutIsDirectoryOrSymlink(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "in.json")
	if err := os.WriteFile(inPath, []byte(`{"format_version":"1.2","resource_changes":[]}`), 0o600); err != nil {
		t.Fatalf("write in.json failed: %v", err)
	}

	t.Run("OutIsDirectory", func(t *testing.T) {
		outDir := filepath.Join(tmpDir, "outdir")
		if err := os.Mkdir(outDir, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", inPath, "--out", outDir}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("expected ExitError (%d), got %d", ExitError, code)
		}
		if stderr.Len() == 0 {
			t.Errorf("expected error on stderr")
		}
	})

	t.Run("OutIsSymlink", func(t *testing.T) {
		targetPath := filepath.Join(tmpDir, "target.json")
		if err := os.WriteFile(targetPath, []byte("original-content"), 0o600); err != nil {
			t.Fatalf("write target failed: %v", err)
		}
		linkPath := filepath.Join(tmpDir, "link.json")
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Skipf("os.Symlink not permitted in this environment: %v", err)
		}

		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", inPath, "--out", linkPath}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("expected ExitError (%d), got %d", ExitError, code)
		}
		b, _ := os.ReadFile(targetPath)
		if string(b) != "original-content" {
			t.Errorf("symlink target was modified: %s", string(b))
		}
	})
}

func TestCLI_Scrub_EmptyRedactKey(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "in.json")
	if err := os.WriteFile(inPath, []byte(`{"format_version":"1.2","resource_changes":[]}`), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Execute(ctx, []string{"scrub", "--plan", inPath, "--redact-key", ""}, &stdout, &stderr)
	if code != ExitError {
		t.Errorf("expected ExitError (%d), got %d", ExitError, code)
	}
	if !strings.Contains(stderr.String(), "--redact-key") {
		t.Errorf("expected --redact-key error message on stderr, got: %s", stderr.String())
	}
}

func TestParity_MultiCloudCorpus_EvalAndBacktest(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	plansDir := filepath.Join("..", "..", "testdata", "plans")
	scrubbedDir := t.TempDir()

	planFiles := []string{"repo_payments_aws.json", "repo_data_azure.json", "repo_ml_gcp.json"}
	for _, name := range planFiles {
		src := filepath.Join(plansDir, name)
		dst := filepath.Join(scrubbedDir, name)
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"scrub", "--plan", src, "--out", dst}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("scrub %s failed (code=%d): %s", name, code, stderr.String())
		}

		// Compare tf-sim eval
		var rawEvalOut, rawEvalErr, scrubEvalOut, scrubEvalErr bytes.Buffer
		rawCode := Execute(ctx, []string{"eval", "--policy", policyPath, "--plan", src, "--format", "json"}, &rawEvalOut, &rawEvalErr)
		scrubCode := Execute(ctx, []string{"eval", "--policy", policyPath, "--plan", dst, "--format", "json"}, &scrubEvalOut, &scrubEvalErr)
		if rawCode != scrubCode {
			t.Fatalf("eval exit code mismatch for %s: raw=%d scrub=%d", name, rawCode, scrubCode)
		}

		var rawRes, scrubRes model.EvalResult
		if err := json.Unmarshal(rawEvalOut.Bytes(), &rawRes); err != nil {
			t.Fatalf("unmarshal raw EvalResult failed: %v", err)
		}
		if err := json.Unmarshal(scrubEvalOut.Bytes(), &scrubRes); err != nil {
			t.Fatalf("unmarshal scrubbed EvalResult failed: %v", err)
		}
		if !reflect.DeepEqual(rawRes, scrubRes) {
			t.Errorf("EvalResult parity mismatch for %s:\nraw: %+v\nscrub: %+v", name, rawRes, scrubRes)
		}
	}

	// Compare tf-sim backtest across the whole corpus
	var rawBtOut, rawBtErr, scrubBtOut, scrubBtErr bytes.Buffer
	rawBtCode := Execute(ctx, []string{"backtest", "--policy", policyPath, "--plans-dir", plansDir, "--concurrency", "2", "--format", "json"}, &rawBtOut, &rawBtErr)
	scrubBtCode := Execute(ctx, []string{"backtest", "--policy", policyPath, "--plans-dir", scrubbedDir, "--concurrency", "2", "--format", "json"}, &scrubBtOut, &scrubBtErr)
	if rawBtCode != scrubBtCode || rawBtCode != ExitViolation {
		t.Fatalf("backtest exit code mismatch: raw=%d scrub=%d (expected %d)", rawBtCode, scrubBtCode, ExitViolation)
	}

	var rawRep, scrubRep model.BlastRadiusReport
	if err := json.Unmarshal(rawBtOut.Bytes(), &rawRep); err != nil {
		t.Fatalf("unmarshal raw BlastRadiusReport failed: %v", err)
	}
	if err := json.Unmarshal(scrubBtOut.Bytes(), &scrubRep); err != nil {
		t.Fatalf("unmarshal scrubbed BlastRadiusReport failed: %v", err)
	}
	if !reflect.DeepEqual(rawRep, scrubRep) {
		t.Errorf("BlastRadiusReport parity mismatch:\nraw: %+v\nscrub: %+v", rawRep, scrubRep)
	}
}

func TestParity_StarterPolicyPackAll28Rules(t *testing.T) {
	ctx := context.Background()
	fixturesRoot := filepath.Join("..", "..", "testdata", "starter_pack_fixtures")

	secretTokens := []string{
		"prior-state-secret-val",
		"var-secret-val",
		"admin-login-pw-secret",
		"AKIA" + "IOSFODNN7EXAMPLE",
		"ghp_" + "0123456789abcdef0123456789abcdef0123",
	}

	for _, kind := range []string{"pass", "fail"} {
		expectedCode := ExitOK
		if kind == "fail" {
			expectedCode = ExitViolation
		}

		rawSubDir := filepath.Join(fixturesRoot, kind)
		entries, err := os.ReadDir(rawSubDir)
		if err != nil {
			t.Fatalf("ReadDir %s failed: %v", rawSubDir, err)
		}

		scrubSubDir := filepath.Join(t.TempDir(), kind)
		if err := os.MkdirAll(scrubSubDir, 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		augSubDir := filepath.Join(t.TempDir(), "aug_"+kind)
		if err := os.MkdirAll(augSubDir, 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			rawPath := filepath.Join(rawSubDir, entry.Name())
			rawBytes, err := os.ReadFile(rawPath)
			if err != nil {
				t.Fatalf("read %s failed: %v", rawPath, err)
			}

			// Augment plan in temp dir with sensitive bloat, masks, password key, and fake tokens
			var planMap map[string]any
			if err := json.Unmarshal(rawBytes, &planMap); err != nil {
				t.Fatalf("unmarshal %s failed: %v", rawPath, err)
			}
			planMap["prior_state"] = map[string]any{"secret": secretTokens[0]}
			planMap["variables"] = map[string]any{"api_secret": map[string]any{"value": secretTokens[1]}}

			if rcs, ok := planMap["resource_changes"].([]any); ok && len(rcs) > 0 {
				if rc, ok := rcs[0].(map[string]any); ok {
					if ch, ok := rc["change"].(map[string]any); ok {
						if after, ok := ch["after"].(map[string]any); ok && after != nil {
							after["administrator_login_password"] = secretTokens[2]
							after["scrub_test_tokens"] = map[string]any{
								"aws": secretTokens[3],
								"gh":  secretTokens[4],
							}
							ch["after_sensitive"] = map[string]any{
								"administrator_login_password": true,
							}
						}
					}
				}
			}

			augBytes, err := json.Marshal(planMap)
			if err != nil {
				t.Fatalf("marshal augmented %s failed: %v", entry.Name(), err)
			}
			augPath := filepath.Join(augSubDir, entry.Name())
			if err := os.WriteFile(augPath, augBytes, 0o600); err != nil {
				t.Fatalf("write augmented %s failed: %v", augPath, err)
			}

			scrubPath := filepath.Join(scrubSubDir, entry.Name())
			var scOut, scErr bytes.Buffer
			if code := Execute(ctx, []string{"scrub", "--plan", augPath, "--out", scrubPath}, &scOut, &scErr); code != ExitOK {
				t.Fatalf("scrub %s failed (code=%d): %s", entry.Name(), code, scErr.String())
			}

			scrubbedBytes, err := os.ReadFile(scrubPath)
			if err != nil {
				t.Fatalf("read scrubbed %s failed: %v", scrubPath, err)
			}
			for _, tok := range secretTokens {
				if strings.Contains(string(scrubbedBytes), tok) {
					t.Errorf("scrubbed %s leaked secret token %q", entry.Name(), tok)
				}
			}

			// Eval raw vs scrubbed with --pack all
			var rawOut, rawErr, scrubOut, scrubErr bytes.Buffer
			rawCode := Execute(ctx, []string{"eval", "--pack", "all", "--plan", rawPath, "--format", "json"}, &rawOut, &rawErr)
			scrubCode := Execute(ctx, []string{"eval", "--pack", "all", "--plan", scrubPath, "--format", "json"}, &scrubOut, &scrubErr)
			if rawCode != expectedCode || scrubCode != expectedCode {
				t.Fatalf("%s eval --pack all exit code mismatch: raw=%d scrub=%d expected=%d", entry.Name(), rawCode, scrubCode, expectedCode)
			}

			var rawRes, scrubRes model.EvalResult
			if err := json.Unmarshal(rawOut.Bytes(), &rawRes); err != nil {
				t.Fatalf("unmarshal raw EvalResult failed: %v", err)
			}
			if err := json.Unmarshal(scrubOut.Bytes(), &scrubRes); err != nil {
				t.Fatalf("unmarshal scrubbed EvalResult failed: %v", err)
			}
			if !reflect.DeepEqual(rawRes.Violations, scrubRes.Violations) {
				t.Errorf("%s violations mismatch:\nraw: %+v\nscrub: %+v", entry.Name(), rawRes.Violations, scrubRes.Violations)
			}
			if kind == "pass" && len(scrubRes.Violations) != 0 {
				t.Errorf("%s expected 0 violations, got %d", entry.Name(), len(scrubRes.Violations))
			}
		}

		// Backtest raw vs scrubbed dir with --pack all
		var rawBtOut, rawBtErr, scrubBtOut, scrubBtErr bytes.Buffer
		rawBtCode := Execute(ctx, []string{"backtest", "--pack", "all", "--plans-dir", rawSubDir, "--format", "json"}, &rawBtOut, &rawBtErr)
		scrubBtCode := Execute(ctx, []string{"backtest", "--pack", "all", "--plans-dir", scrubSubDir, "--format", "json"}, &scrubBtOut, &scrubBtErr)
		if rawBtCode != expectedCode || scrubBtCode != expectedCode {
			t.Fatalf("%s backtest --pack all exit code mismatch: raw=%d scrub=%d expected=%d", kind, rawBtCode, scrubBtCode, expectedCode)
		}

		var rawRep, scrubRep model.BlastRadiusReport
		if err := json.Unmarshal(rawBtOut.Bytes(), &rawRep); err != nil {
			t.Fatalf("unmarshal raw BlastRadiusReport failed: %v", err)
		}
		if err := json.Unmarshal(scrubBtOut.Bytes(), &scrubRep); err != nil {
			t.Fatalf("unmarshal scrubbed BlastRadiusReport failed: %v", err)
		}
		if !reflect.DeepEqual(rawRep, scrubRep) {
			t.Errorf("%s BlastRadiusReport parity mismatch:\nraw: %+v\nscrub: %+v", kind, rawRep, scrubRep)
		}
	}
}
