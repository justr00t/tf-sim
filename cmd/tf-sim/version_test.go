package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLI_Version_DefaultAndFlags(t *testing.T) {
	ctx := context.Background()

	t.Run("RootVersionFlag", func(t *testing.T) {
		for _, flag := range []string{"--version", "-v"} {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{flag}, &stdout, &stderr)
			if code != ExitOK {
				t.Fatalf("%s: expected ExitOK (%d), got %d; stderr: %s", flag, ExitOK, code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("%s: expected empty stderr, got: %s", flag, stderr.String())
			}
			out := stdout.String()
			if !strings.HasPrefix(out, "tf-sim version ") || !strings.Contains(out, "commit:") || !strings.Contains(out, "built:") {
				t.Errorf("%s: unexpected version output: %q", flag, out)
			}
		}
	})

	t.Run("VersionSubcommandTable", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"version"}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}
		out := stdout.String()
		expectedPlatform := runtime.GOOS + "/" + runtime.GOARCH
		if !strings.HasPrefix(out, "tf-sim version ") ||
			!strings.Contains(out, "commit:") ||
			!strings.Contains(out, "built:") ||
			!strings.Contains(out, "go: "+runtime.Version()) ||
			!strings.Contains(out, "platform: "+expectedPlatform) {
			t.Errorf("unexpected table output: %q", out)
		}
	})

	t.Run("VersionSubcommandJSON", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"version", "--format", "json"}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}

		var info BuildInfo
		if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
			t.Fatalf("failed to unmarshal BuildInfo JSON: %v\nOutput: %s", err, stdout.String())
		}
		if info.Version == "" {
			t.Error("expected non-empty Version")
		}
		if info.Commit == "" {
			t.Error("expected non-empty Commit")
		}
		if info.Date == "" {
			t.Error("expected non-empty Date")
		}
		if info.GoVersion != runtime.Version() {
			t.Errorf("expected GoVersion %q, got %q", runtime.Version(), info.GoVersion)
		}
		expectedPlatform := runtime.GOOS + "/" + runtime.GOARCH
		if info.Platform != expectedPlatform {
			t.Errorf("expected Platform %q, got %q", expectedPlatform, info.Platform)
		}
	})
}

func TestCLI_Version_LdflagsInjection(t *testing.T) {
	tmpDir := t.TempDir()
	binName := "tf-sim"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tmpDir, binName)

	ldflags := "-X main.version=v0.1.0 -X main.commit=deadbee -X main.date=2026-11-21T00:00:00Z"
	buildCmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build with ldflags failed: %v\n%s", err, string(out))
	}

	t.Run("JSONOutput", func(t *testing.T) {
		cmd := exec.Command(binPath, "version", "--format", "json")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("tf-sim version --format json failed: %v\n%s", err, string(out))
		}
		var info BuildInfo
		if err := json.Unmarshal(out, &info); err != nil {
			t.Fatalf("failed to unmarshal BuildInfo JSON: %v\nOutput: %s", err, string(out))
		}
		if info.Version != "0.1.0" {
			t.Errorf("expected normalized Version %q, got %q", "0.1.0", info.Version)
		}
		if info.Commit != "deadbee" {
			t.Errorf("expected Commit %q, got %q", "deadbee", info.Commit)
		}
		if info.Date != "2026-11-21T00:00:00Z" {
			t.Errorf("expected Date %q, got %q", "2026-11-21T00:00:00Z", info.Date)
		}
	})

	t.Run("RootVersionFlag", func(t *testing.T) {
		cmd := exec.Command(binPath, "--version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("tf-sim --version failed: %v\n%s", err, string(out))
		}
		want := "tf-sim version 0.1.0 (commit: deadbee, built: 2026-11-21T00:00:00Z)\n"
		if string(out) != want {
			t.Errorf("expected %q, got %q", want, string(out))
		}
	})
}

func TestCLI_Version_InvalidFormatAndExtraArgs(t *testing.T) {
	ctx := context.Background()

	t.Run("InvalidFormat", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"version", "--format", "xml"}, &stdout, &stderr)
		if code != ExitError {
			t.Fatalf("expected ExitError (%d), got %d; stdout: %s", ExitError, code, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Error("expected descriptive error on stderr for invalid format")
		}
	})

	t.Run("ExtraPositionalArgs", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"version", "unexpected-arg"}, &stdout, &stderr)
		if code != ExitError {
			t.Fatalf("expected ExitError (%d), got %d; stdout: %s", ExitError, code, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Error("expected descriptive error on stderr for extra positional arg")
		}
	})
}
