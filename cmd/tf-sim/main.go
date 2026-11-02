package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/justr00t/tf-sim/internal/backtest"
	"github.com/justr00t/tf-sim/internal/engine"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"github.com/justr00t/tf-sim/internal/remediate"
	"github.com/justr00t/tf-sim/internal/report"
	"github.com/justr00t/tf-sim/internal/server"
	"github.com/justr00t/tf-sim/internal/verifier"
	"github.com/spf13/cobra"
)

// Standard CLI exit codes.
const (
	ExitOK        = 0
	ExitViolation = 1
	ExitError     = 2
)

// errExitViolation is a sentinel error indicating policy verification failure,
// plan evaluation violations, or blocked historical plans during backtesting.
var errExitViolation = errors.New("policy violation or verification failure detected")

func main() {
	os.Exit(Execute(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// Execute runs the CLI with the given arguments and writers, returning a deterministic exit code (0, 1, or 2).
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if ctx == nil {
		ctx = context.Background()
	}

	rootCmd := NewRootCmd(stdout, stderr)
	rootCmd.SetArgs(args)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if errors.Is(err, errExitViolation) {
			return ExitViolation
		}
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// NewRootCmd constructs the root cobra.Command for tf-sim with verify, eval, backtest, remediate, and serve subcommands.
func NewRootCmd(stdout, stderr io.Writer) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "tf-sim",
		Short:         "Cloud-agnostic Terraform/OpenTofu policy verification, blast-radius simulation, and HCL remediation engine",
		SilenceUsage:  true,
		SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)

	rootCmd.AddCommand(
		newVerifyCmd(stdout, stderr),
		newEvalCmd(stdout, stderr),
		newBacktestCmd(stdout, stderr),
		newRemediateCmd(stdout, stderr),
		newServeCmd(stdout, stderr),
	)

	return rootCmd
}

func newVerifyCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPaths  []string
		schemaPath   string
		passFixtures []string
		failFixtures []string
		format       string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify Rego policy AST(s) against provider schemas to prevent fail-open bugs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cleanedPaths := make([]string, 0, len(policyPaths))
			for _, p := range policyPaths {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					cleanedPaths = append(cleanedPaths, trimmed)
				}
			}
			if len(cleanedPaths) == 0 {
				return fmt.Errorf("--policy is required")
			}

			var schemas model.ProviderSchemaMap
			if strings.TrimSpace(schemaPath) != "" {
				p := parser.NewParser()
				loaded, err := p.LoadProviderSchemas(ctx, schemaPath)
				if err != nil {
					return fmt.Errorf("loading provider schemas: %w", err)
				}
				schemas = loaded
			}

			v := verifier.NewVerifier()
			res, err := v.VerifyPoliciesWithFixtures(ctx, cleanedPaths, schemas, passFixtures, failFixtures)
			if err != nil {
				return fmt.Errorf("verifying policy: %w", err)
			}

			out, err := report.FormatVerificationResult(res, format)
			if err != nil {
				return err
			}
			writeOutput(stdout, out)

			if !res.Valid {
				return errExitViolation
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&policyPaths, "policy", nil, "Path(s) to Rego policy file(s) (.rego)")
	cmd.Flags().StringVar(&schemaPath, "schema", "", "Path to the Terraform provider schema JSON file")
	cmd.Flags().StringSliceVar(&passFixtures, "pass-fixtures", nil, "Path(s) to compliant Terraform plan JSON file(s) or directory that must pass policy evaluation (0 violations)")
	cmd.Flags().StringSliceVar(&failFixtures, "fail-fixtures", nil, "Path(s) to non-compliant Terraform plan JSON file(s) or directory that must trigger policy violations (>= 1 violation)")
	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json|markdown|sarif)")
	_ = cmd.MarkFlagRequired("policy")

	return cmd
}

func newEvalCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPaths []string
		planPath    string
		repoName    string
		format      string
	)

	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate a single Terraform plan JSON against one or more Rego policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if len(policyPaths) == 0 {
				return fmt.Errorf("--policy is required")
			}
			if strings.TrimSpace(planPath) == "" {
				return fmt.Errorf("--plan is required")
			}

			resolvedRepo := strings.TrimSpace(repoName)
			if resolvedRepo == "" {
				base := filepath.Base(planPath)
				resolvedRepo = strings.TrimSuffix(base, filepath.Ext(base))
			}

			p := parser.NewParser()
			snapshot, err := p.ParsePlanFile(ctx, planPath, resolvedRepo)
			if err != nil {
				return fmt.Errorf("parsing plan file: %w", err)
			}

			ev := engine.NewEvaluator()
			res, err := ev.EvaluatePlan(ctx, policyPaths, snapshot)
			if err != nil {
				return fmt.Errorf("evaluating plan: %w", err)
			}

			out, err := report.FormatEvalResult(res, format)
			if err != nil {
				return err
			}
			writeOutput(stdout, out)

			if !res.Passed {
				return errExitViolation
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&policyPaths, "policy", nil, "Path(s) to Rego policy file(s) (.rego)")
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to Terraform plan JSON file")
	cmd.Flags().StringVar(&repoName, "repo", "", "Repository name for reporting (defaults to plan filename stem)")
	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json|markdown|sarif)")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("plan")

	return cmd
}

func newBacktestCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPaths []string
		plansDir    string
		concurrency int
		format      string
	)

	cmd := &cobra.Command{
		Use:   "backtest",
		Short: "Simulate blast radius of Rego policies across a historical corpus of Terraform plans",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if len(policyPaths) == 0 {
				return fmt.Errorf("--policy is required")
			}
			if strings.TrimSpace(plansDir) == "" {
				return fmt.Errorf("--plans-dir is required")
			}

			var opts []backtest.Option
			if concurrency > 0 {
				opts = append(opts, backtest.WithConcurrency(concurrency))
			}

			runner := backtest.NewRunner(opts...)
			snapshots, err := runner.LoadSnapshotsFromDir(ctx, plansDir)
			if err != nil {
				return fmt.Errorf("loading plan snapshots: %w", err)
			}

			rep, err := runner.RunBacktest(ctx, policyPaths, snapshots)
			if err != nil {
				return fmt.Errorf("running backtest: %w", err)
			}

			out, err := report.FormatBlastRadiusReport(rep, format)
			if err != nil {
				return err
			}
			writeOutput(stdout, out)

			if rep.BlockedPlansCount > 0 {
				return errExitViolation
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&policyPaths, "policy", nil, "Path(s) to Rego policy file(s) (.rego)")
	cmd.Flags().StringVar(&plansDir, "plans-dir", "", "Directory containing historical Terraform plan JSON files")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "Worker pool concurrency (defaults to runtime.NumCPU())")
	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json|markdown|sarif)")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("plans-dir")

	return cmd
}

func newRemediateCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPaths []string
		planPath    string
		tfDir       string
		repoName    string
		writeFlag   bool
		format      string
	)

	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Generate surgical HCL AST patches and unified diffs for violated resources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if len(policyPaths) == 0 {
				return fmt.Errorf("--policy is required")
			}
			if strings.TrimSpace(planPath) == "" {
				return fmt.Errorf("--plan is required")
			}
			if strings.TrimSpace(tfDir) == "" {
				return fmt.Errorf("--tf-dir is required")
			}

			resolvedRepo := strings.TrimSpace(repoName)
			if resolvedRepo == "" {
				base := filepath.Base(planPath)
				resolvedRepo = strings.TrimSuffix(base, filepath.Ext(base))
			}

			p := parser.NewParser()
			snapshot, err := p.ParsePlanFile(ctx, planPath, resolvedRepo)
			if err != nil {
				return fmt.Errorf("parsing plan file: %w", err)
			}

			ev := engine.NewEvaluator()
			evalRes, err := ev.EvaluatePlan(ctx, policyPaths, snapshot)
			if err != nil {
				return fmt.Errorf("evaluating plan: %w", err)
			}

			patcher := remediate.NewPatcher(remediate.WithWriteChanges(writeFlag))
			patches, err := patcher.GeneratePatches(ctx, tfDir, evalRes.Violations)
			if err != nil {
				return fmt.Errorf("generating remediation patches: %w", err)
			}

			out, err := report.FormatRemediationPatches(patches, format)
			if err != nil {
				return err
			}
			writeOutput(stdout, out)

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&policyPaths, "policy", nil, "Path(s) to Rego policy file(s) (.rego)")
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to Terraform plan JSON file")
	cmd.Flags().StringVar(&tfDir, "tf-dir", "", "Directory containing Terraform (.tf) source files")
	cmd.Flags().StringVar(&repoName, "repo", "", "Repository name for reporting (defaults to plan filename stem)")
	cmd.Flags().BoolVar(&writeFlag, "write", false, "Write patched HCL changes back to .tf files in-place")
	cmd.Flags().StringVar(&format, "format", report.FormatMarkdown, "Output format (table|json|markdown|sarif)")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("plan")
	_ = cmd.MarkFlagRequired("tf-dir")

	return cmd
}

func newServeCmd(stdout, _ io.Writer) *cobra.Command {
	var (
		addr         string
		workspaceDir string
		policyPath   string
		schemaPath   string
		corpusDir    string
		plansDir     string
		reposDir     string
		reposDirAlt  string
		workers      int
		allowWrite   bool
	)

	cmd := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"ui"},
		Short:   "Launch the local-first Basel Brass Policy Lifecycle & Blast-Radius Control Plane",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sigCtx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			resolvedCorpus := strings.TrimSpace(corpusDir)
			if strings.TrimSpace(plansDir) != "" && !cmd.Flags().Changed("corpus") {
				resolvedCorpus = strings.TrimSpace(plansDir)
			}
			resolvedRepos := strings.TrimSpace(reposDir)
			if strings.TrimSpace(reposDirAlt) != "" && !cmd.Flags().Changed("repos") {
				resolvedRepos = strings.TrimSpace(reposDirAlt)
			}

			srv, err := server.NewServer(server.Config{
				Addr:         addr,
				WorkspaceDir: workspaceDir,
				PolicyPath:   policyPath,
				SchemaPath:   schemaPath,
				CorpusDir:    resolvedCorpus,
				ReposDir:     resolvedRepos,
				Workers:      workers,
				AllowWrite:   allowWrite,
			})
			if err != nil {
				return fmt.Errorf("initializing control-plane server: %w", err)
			}

			fmt.Fprintf(stdout, "tf-sim control-plane listening on http://%s\n", srv.Addr())
			return srv.ListenAndServe(sigCtx)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "Loopback bind address for the local control-plane server")
	cmd.Flags().StringVar(&workspaceDir, "workspace", ".", "Workspace root directory containing policies, schemas, plans, and repos")
	cmd.Flags().StringVar(&policyPath, "policy", filepath.FromSlash("testdata/policies/storage_encryption.rego"), "Default Rego policy file relative to workspace")
	cmd.Flags().StringVar(&schemaPath, "schema", filepath.FromSlash("testdata/schemas/multicloud_schema.json"), "Default Terraform provider schema JSON file relative to workspace")
	cmd.Flags().StringVar(&corpusDir, "corpus", filepath.FromSlash("testdata/plans"), "Directory containing historical Terraform plan JSON snapshots relative to workspace")
	cmd.Flags().StringVar(&plansDir, "plans-dir", "", "Alias for --corpus directory containing historical Terraform plan JSON snapshots")
	cmd.Flags().StringVar(&reposDir, "repos", filepath.FromSlash("testdata/repos"), "Directory containing target Terraform (.tf) repositories relative to workspace")
	cmd.Flags().StringVar(&reposDirAlt, "repos-dir", "", "Alias for --repos directory containing target Terraform (.tf) repositories")
	cmd.Flags().IntVar(&workers, "workers", 0, "Worker pool concurrency for corpus simulation (defaults to runtime.NumCPU())")
	cmd.Flags().BoolVar(&allowWrite, "allow-write", false, "Allow POST /api/apply with write=true to mutate .tf files on disk")

	return cmd
}

func writeOutput(w io.Writer, out string) {
	if strings.HasSuffix(out, "\n") {
		fmt.Fprint(w, out)
	} else {
		fmt.Fprintln(w, out)
	}
}
