package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/boomer/tf-sim/internal/backtest"
	"github.com/boomer/tf-sim/internal/engine"
	"github.com/boomer/tf-sim/internal/model"
	"github.com/boomer/tf-sim/internal/parser"
	"github.com/boomer/tf-sim/internal/remediate"
	"github.com/boomer/tf-sim/internal/report"
	"github.com/boomer/tf-sim/internal/verifier"
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

// NewRootCmd constructs the root cobra.Command for tf-sim with verify, eval, backtest, and remediate subcommands.
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
	)

	return rootCmd
}

func newVerifyCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		policyPath string
		schemaPath string
		format     string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Rego policy AST against provider schemas to prevent fail-open bugs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if strings.TrimSpace(policyPath) == "" {
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
			res, err := v.VerifyPolicy(ctx, policyPath, schemas)
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

	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to the Rego policy file (.rego)")
	cmd.Flags().StringVar(&schemaPath, "schema", "", "Path to the Terraform provider schema JSON file")
	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json|markdown)")
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
	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json|markdown)")
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
	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json|markdown)")
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
	cmd.Flags().StringVar(&format, "format", report.FormatMarkdown, "Output format (table|json|markdown)")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("plan")
	_ = cmd.MarkFlagRequired("tf-dir")

	return cmd
}

func writeOutput(w io.Writer, out string) {
	if strings.HasSuffix(out, "\n") {
		fmt.Fprint(w, out)
	} else {
		fmt.Fprintln(w, out)
	}
}
