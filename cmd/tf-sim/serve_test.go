package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCLI_Serve_GracefulShutdownAndFlags tests `tf-sim serve` (and alias `ui`) help flags,
// ephemeral port startup (`127.0.0.1:0`), context cancellation shutdown, and invalid workspace error handling.
func TestCLI_Serve_GracefulShutdownAndFlags(t *testing.T) {
	wsRoot := filepath.Dir(filepath.Dir(resolveTestdataPath(t, "policies", "storage_encryption.rego")))
	wsRoot = filepath.Dir(wsRoot)

	t.Run("ServeAndUI_Help_ReturnsExitOK", func(t *testing.T) {
		for _, sub := range []string{"serve", "ui"} {
			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), []string{sub, "--help"}, &stdout, &stderr)
			if code != ExitOK {
				t.Fatalf("expected ExitOK (%d) for %s --help, got %d; stderr: %s", ExitOK, sub, code, stderr.String())
			}
			out := stdout.String()
			for _, flagName := range []string{"--addr", "--workspace", "--policy", "--schema", "--corpus", "--repos", "--allow-write"} {
				if !strings.Contains(out, flagName) {
					t.Errorf("expected %s --help output to mention flag %q, got:\n%s", sub, flagName, out)
				}
			}
		}
	})

	t.Run("Serve_EphemeralPort_StartsAndExitsCleanlyOnContextCancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"serve",
			"--addr", "127.0.0.1:0",
			"--workspace", wsRoot,
		}, &stdout, &stderr)

		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d) on context shutdown, got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "listening on http://") {
			t.Errorf("expected listening banner on stdout, got: %q", stdout.String())
		}
	})

	t.Run("Serve_InvalidWorkspace_ReturnsExitError", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(context.Background(), []string{
			"serve",
			"--workspace", filepath.Join(t.TempDir(), "does_not_exist"),
		}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("expected ExitError (%d) for invalid workspace, got %d", ExitError, code)
		}
	})
}
