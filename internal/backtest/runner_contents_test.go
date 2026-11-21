package backtest

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/policy"
)

func TestRunBacktestContents_StarterPackMultiCloudDeterministic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policies, err := policy.LoadPolicies(nil, []string{"all"})
	if err != nil {
		t.Fatalf("LoadPolicies(all) failed: %v", err)
	}

	runner := NewRunner(WithConcurrency(4))
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")
	snapshots, err := runner.LoadSnapshotsFromDir(ctx, failDir)
	if err != nil {
		t.Fatalf("LoadSnapshotsFromDir(%s) failed: %v", failDir, err)
	}
	if len(snapshots) != 3 {
		t.Fatalf("expected 3 fail snapshots (aws, azure, gcp), got %d", len(snapshots))
	}

	var firstJSON []byte
	for run := 0; run < 5; run++ {
		report, err := runner.RunBacktestContents(ctx, policies, snapshots)
		if err != nil {
			t.Fatalf("run %d RunBacktestContents failed: %v", run, err)
		}
		if report.TotalReposAnalyzed != 3 {
			t.Errorf("TotalReposAnalyzed = %d, want 3", report.TotalReposAnalyzed)
		}
		if report.ImpactedReposCount != 3 {
			t.Errorf("ImpactedReposCount = %d, want 3", report.ImpactedReposCount)
		}
		if report.TotalPlansAnalyzed != 3 {
			t.Errorf("TotalPlansAnalyzed = %d, want 3", report.TotalPlansAnalyzed)
		}
		if report.BlockedPlansCount != 3 {
			t.Errorf("BlockedPlansCount = %d, want 3", report.BlockedPlansCount)
		}
		// 12 AWS rules * 2 + 8 Azure rules * 2 + 8 GCP rules * 2 = 56 total violations.
		if report.TotalViolations != 56 {
			t.Errorf("TotalViolations = %d, want 56", report.TotalViolations)
		}

		wantBreakdown := map[string]int{
			"aws":     24,
			"azurerm": 16,
			"google":  16,
		}
		for prov, wantCount := range wantBreakdown {
			if report.BreakdownByProvider[prov] != wantCount {
				t.Errorf("BreakdownByProvider[%q] = %d, want %d", prov, report.BreakdownByProvider[prov], wantCount)
			}
		}

		// RepoImpacts must be sorted deterministically by RepoName.
		wantRepos := []string{"aws_fail", "azure_fail", "gcp_fail"}
		if len(report.RepoImpacts) != len(wantRepos) {
			t.Fatalf("len(RepoImpacts) = %d, want %d", len(report.RepoImpacts), len(wantRepos))
		}
		for i, wantRepo := range wantRepos {
			if report.RepoImpacts[i].RepoName != wantRepo {
				t.Errorf("RepoImpacts[%d].RepoName = %q, want %q", i, report.RepoImpacts[i].RepoName, wantRepo)
			}
		}

		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("json.Marshal(report) failed: %v", err)
		}
		if run == 0 {
			firstJSON = raw
		} else if string(raw) != string(firstJSON) {
			t.Fatalf("run %d produced non-deterministic JSON compared to run 0", run)
		}
	}
}

func TestRunBacktestContents_CleanPassFixtures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policies, err := policy.LoadPolicies(nil, []string{"all"})
	if err != nil {
		t.Fatalf("LoadPolicies(all) failed: %v", err)
	}

	runner := NewRunner()
	passDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "pass")
	snapshots, err := runner.LoadSnapshotsFromDir(ctx, passDir)
	if err != nil {
		t.Fatalf("LoadSnapshotsFromDir(%s) failed: %v", passDir, err)
	}

	report, err := runner.RunBacktestContents(ctx, policies, snapshots)
	if err != nil {
		t.Fatalf("RunBacktestContents(pass) failed: %v", err)
	}
	if report.TotalReposAnalyzed != 3 {
		t.Errorf("TotalReposAnalyzed = %d, want 3", report.TotalReposAnalyzed)
	}
	if report.ImpactedReposCount != 0 || report.BlockedPlansCount != 0 || report.TotalViolations != 0 {
		t.Errorf("expected clean pass report with 0 violations, got impacted=%d blocked=%d violations=%d",
			report.ImpactedReposCount, report.BlockedPlansCount, report.TotalViolations)
	}
}

// legacyMockEvaluator implements ONLY model.PolicyEvaluator (not ContentPolicyEvaluator)
// to prove backward interface compatibility and Runner.RunBacktestContents fallback handling.
type legacyMockEvaluator struct {
	called int
}

var _ model.PolicyEvaluator = (*legacyMockEvaluator)(nil)

func (m *legacyMockEvaluator) EvaluatePlan(_ context.Context, _ []string, snapshot *model.PlanSnapshot) (*model.EvalResult, error) {
	m.called++
	return &model.EvalResult{
		SnapshotID:     snapshot.SnapshotID,
		RepoName:       snapshot.RepoName,
		TotalResources: len(snapshot.ResourceChanges),
		Passed:         true,
		Violations:     []model.PolicyViolation{},
	}, nil
}

func TestRunBacktestContents_ValidationAndLegacyMockCompatibility(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policies, err := policy.LoadPolicies(nil, []string{"aws"})
	if err != nil {
		t.Fatalf("LoadPolicies(aws) failed: %v", err)
	}

	t.Run("EmptyPoliciesReturnsError", func(t *testing.T) {
		t.Parallel()
		runner := NewRunner()
		if _, err := runner.RunBacktestContents(ctx, nil, []*model.PlanSnapshot{}); err == nil {
			t.Fatal("expected error for empty policies, got nil")
		}
	})

	t.Run("NilSnapshotReturnsError", func(t *testing.T) {
		t.Parallel()
		runner := NewRunner()
		if _, err := runner.RunBacktestContents(ctx, policies, []*model.PlanSnapshot{nil}); err == nil {
			t.Fatal("expected error for nil snapshot, got nil")
		}
	})

	t.Run("CanceledContextReturnsError", func(t *testing.T) {
		t.Parallel()
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		runner := NewRunner()
		snap := &model.PlanSnapshot{SnapshotID: "s1", RepoName: "r1"}
		_, err := runner.RunBacktestContents(canceledCtx, policies, []*model.PlanSnapshot{snap})
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("LegacyPolicyEvaluatorMockFallbackWorks", func(t *testing.T) {
		t.Parallel()
		mock := &legacyMockEvaluator{}
		runner := NewRunner(WithEvaluator(mock), WithConcurrency(1))
		snap := &model.PlanSnapshot{SnapshotID: "s-mock", RepoName: "repo-mock"}

		report, err := runner.RunBacktestContents(ctx, policies, []*model.PlanSnapshot{snap})
		if err != nil {
			t.Fatalf("RunBacktestContents with legacy mock evaluator failed: %v", err)
		}
		if mock.called != 1 {
			t.Errorf("expected legacy mock EvaluatePlan to be invoked once, got %d", mock.called)
		}
		if report.TotalReposAnalyzed != 1 || report.TotalViolations != 0 {
			t.Errorf("unexpected report from legacy mock: %+v", report)
		}
	})
}
