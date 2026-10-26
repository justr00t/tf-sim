package backtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/justr00t/tf-sim/internal/engine"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"golang.org/x/sync/errgroup"
)

// Ensure Runner satisfies model.BacktestRunner at compile time.
var _ model.BacktestRunner = (*Runner)(nil)

// Runner coordinates concurrent evaluation of historical plan snapshots against candidate policies.
type Runner struct {
	evaluator   model.PolicyEvaluator
	parser      model.PlanParser
	concurrency int
}

// Option configures Runner instances.
type Option func(*Runner)

// WithEvaluator injects a custom PolicyEvaluator (defaults to engine.NewEvaluator()).
func WithEvaluator(eval model.PolicyEvaluator) Option {
	return func(r *Runner) {
		if eval != nil {
			r.evaluator = eval
		}
	}
}

// WithParser injects a custom PlanParser (defaults to parser.NewParser()).
func WithParser(p model.PlanParser) Option {
	return func(r *Runner) {
		if p != nil {
			r.parser = p
		}
	}
}

// WithConcurrency configures the maximum number of worker goroutines (defaults to runtime.NumCPU(), min 1).
func WithConcurrency(workers int) Option {
	return func(r *Runner) {
		if workers < 1 {
			workers = 1
		}
		r.concurrency = workers
	}
}

// NewRunner creates a new BacktestRunner instance with configured or default options.
func NewRunner(opts ...Option) *Runner {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	r := &Runner{
		evaluator:   engine.NewEvaluator(),
		parser:      parser.NewParser(),
		concurrency: workers,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.concurrency < 1 {
		r.concurrency = 1
	}
	if r.evaluator == nil {
		r.evaluator = engine.NewEvaluator()
	}
	if r.parser == nil {
		r.parser = parser.NewParser()
	}
	return r
}

// ExtractProviderName extracts a cloud provider identifier from a resource change's ProviderName
// or ResourceType in a 100% cloud-agnostic manner.
func ExtractProviderName(rcProviderName, resourceType string) string {
	rcProviderName = strings.TrimSpace(rcProviderName)
	if rcProviderName != "" {
		lastSlash := strings.LastIndex(rcProviderName, "/")
		if lastSlash >= 0 && lastSlash < len(rcProviderName)-1 {
			res := rcProviderName[lastSlash+1:]
			if res != "" {
				return res
			}
		}
		if lastSlash < 0 {
			return rcProviderName
		}
	}
	resourceType = strings.TrimSpace(resourceType)
	if strings.Contains(resourceType, "_") {
		parts := strings.SplitN(resourceType, "_", 2)
		if parts[0] != "" {
			return parts[0]
		}
	}
	return "unknown"
}

// extractProviderName is an unexported alias delegating to ExtractProviderName.
func extractProviderName(rcProviderName, resourceType string) string {
	return ExtractProviderName(rcProviderName, resourceType)
}

// RunBacktest evaluates the given policy files concurrently across the provided plan snapshots.
func (r *Runner) RunBacktest(ctx context.Context, policyPaths []string, snapshots []*model.PlanSnapshot) (*model.BlastRadiusReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(policyPaths) == 0 {
		return nil, fmt.Errorf("at least one policy path must be provided")
	}

	report := &model.BlastRadiusReport{
		PolicyPath:          strings.Join(policyPaths, ", "),
		TotalReposAnalyzed:  0,
		ImpactedReposCount:  0,
		TotalPlansAnalyzed:  0,
		BlockedPlansCount:   0,
		TotalResources:      0,
		TotalViolations:     0,
		BreakdownByProvider: make(map[string]int),
		RepoImpacts:         make([]model.RepoImpact, 0),
	}

	if len(snapshots) == 0 {
		return report, nil
	}

	for i, snap := range snapshots {
		if snap == nil {
			return nil, fmt.Errorf("plan snapshot at index %d cannot be nil", i)
		}
	}

	results := make([]*model.EvalResult, len(snapshots))
	g, gctx := errgroup.WithContext(ctx)
	concurrency := r.concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	g.SetLimit(concurrency)

	for i, snap := range snapshots {
		idx := i
		s := snap
		g.Go(func() error {
			res, err := r.evaluator.EvaluatePlan(gctx, policyPaths, s)
			if err != nil {
				return fmt.Errorf("evaluating plan %s (repo %s): %w", s.SnapshotID, s.RepoName, err)
			}
			results[idx] = res
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Multi-Snapshot Repository Aggregation & Deterministic Sorting
	type repoAccumulator struct {
		repoName          string
		totalPlansTested  int
		blockedPlansCount int
		violations        []model.PolicyViolation
	}

	repoMap := make(map[string]*repoAccumulator)
	breakdownByProvider := make(map[string]int)

	totalResources := 0
	totalViolations := 0
	blockedPlansCount := 0

	for i, snap := range snapshots {
		res := results[i]
		totalResources += len(snap.ResourceChanges)
		totalViolations += len(res.Violations)
		if !res.Passed {
			blockedPlansCount++
		}

		// Provider lookup
		addrToProvider := make(map[string]string, len(snap.ResourceChanges))
		for _, rc := range snap.ResourceChanges {
			addrToProvider[rc.Address] = rc.ProviderName
		}
		for _, v := range res.Violations {
			rcProv := addrToProvider[v.ResourceAddress]
			prov := ExtractProviderName(rcProv, v.ResourceType)
			breakdownByProvider[prov]++
		}

		// Repo aggregation
		acc, ok := repoMap[snap.RepoName]
		if !ok {
			acc = &repoAccumulator{
				repoName:   snap.RepoName,
				violations: make([]model.PolicyViolation, 0),
			}
			repoMap[snap.RepoName] = acc
		}
		acc.totalPlansTested++
		if !res.Passed {
			acc.blockedPlansCount++
		}
		acc.violations = append(acc.violations, res.Violations...)
	}

	// Deterministic sorting of violations and repo impacts
	repoImpacts := make([]model.RepoImpact, 0, len(repoMap))
	impactedReposCount := 0

	for _, acc := range repoMap {
		if acc.blockedPlansCount > 0 {
			impactedReposCount++
		}
		// Sort Violations: ResourceAddress ASC, RuleID ASC, Message ASC
		sort.Slice(acc.violations, func(i, j int) bool {
			if acc.violations[i].ResourceAddress != acc.violations[j].ResourceAddress {
				return acc.violations[i].ResourceAddress < acc.violations[j].ResourceAddress
			}
			if acc.violations[i].RuleID != acc.violations[j].RuleID {
				return acc.violations[i].RuleID < acc.violations[j].RuleID
			}
			return acc.violations[i].Message < acc.violations[j].Message
		})

		vList := acc.violations
		if vList == nil {
			vList = make([]model.PolicyViolation, 0)
		}
		repoImpacts = append(repoImpacts, model.RepoImpact{
			RepoName:          acc.repoName,
			TotalPlansTested:  acc.totalPlansTested,
			BlockedPlansCount: acc.blockedPlansCount,
			Violations:        vList,
		})
	}

	// Sort RepoImpacts: RepoName ASC
	sort.Slice(repoImpacts, func(i, j int) bool {
		return repoImpacts[i].RepoName < repoImpacts[j].RepoName
	})

	report.TotalReposAnalyzed = len(repoMap)
	report.ImpactedReposCount = impactedReposCount
	report.TotalPlansAnalyzed = len(snapshots)
	report.BlockedPlansCount = blockedPlansCount
	report.TotalResources = totalResources
	report.TotalViolations = totalViolations
	report.BreakdownByProvider = breakdownByProvider
	report.RepoImpacts = repoImpacts

	return report, nil
}

// LoadSnapshotsFromDir recursively walks dirPath, discovers all .json files in alphabetical order,
// parses each into a PlanSnapshot, and infers repoName from directory or filename stems.
func (r *Runner) LoadSnapshotsFromDir(ctx context.Context, dirPath string) ([]*model.PlanSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fi, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("stat directory %q: %w", dirPath, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("path %q is not a directory", dirPath)
	}

	var jsonPaths []string
	err = filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".json") {
			jsonPaths = append(jsonPaths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory %q: %w", dirPath, err)
	}

	if len(jsonPaths) == 0 {
		return []*model.PlanSnapshot{}, nil
	}

	sort.Strings(jsonPaths)

	snapshots := make([]*model.PlanSnapshot, 0, len(jsonPaths))
	for _, path := range jsonPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(dirPath, path)
		if err != nil {
			return nil, fmt.Errorf("resolving relative path for %s: %w", path, err)
		}
		relDir := filepath.Dir(rel)
		var repoName string
		if relDir != "." && relDir != "" {
			parts := strings.Split(filepath.ToSlash(relDir), "/")
			repoName = parts[0]
		} else {
			base := filepath.Base(path)
			repoName = strings.TrimSuffix(base, filepath.Ext(base))
		}

		snap, err := r.parser.ParsePlanFile(ctx, path, repoName)
		if err != nil {
			return nil, fmt.Errorf("parsing plan file %s: %w", path, err)
		}
		snapshots = append(snapshots, snap)
	}

	return snapshots, nil
}
