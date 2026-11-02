package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/justr00t/tf-sim/internal/backtest"
	"github.com/justr00t/tf-sim/internal/engine"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"github.com/justr00t/tf-sim/internal/remediate"
	"github.com/justr00t/tf-sim/internal/verifier"
)

//go:embed static/*
var staticEmbedFS embed.FS

// Default server configuration constants and security limits.
const (
	DefaultAddr         = "127.0.0.1:8080"
	DefaultWorkspaceDir = "."
	DefaultPolicyPath   = "testdata/policies/storage_encryption.rego"
	DefaultSchemaPath   = "testdata/schemas/multicloud_schema.json"
	DefaultCorpusDir    = "testdata/plans"
	DefaultReposDir     = "testdata/repos"
	MaxRequestBodyBytes = 2 << 20  // 2 MiB maximum JSON request payload
	MaxUploadBodyBytes  = 10 << 20 // 10 MiB maximum file upload JSON payload

	StateEmpty              = "empty"
	StateViolationsDetected = "violations-detected"
	StateFailOpenCaught     = "fail-open-caught"
	StateEnforceReady       = "enforce-ready"
)

// ErrPathTraversal is returned when a user-supplied path escapes the configured workspace root.
var ErrPathTraversal = errors.New("path resolves outside configured workspace directory")

// Config configures the local-first HTTP control plane server.
type Config struct {
	Addr         string
	WorkspaceDir string
	PolicyPath   string
	SchemaPath   string
	CorpusDir    string
	PlansDir     string // Optional alias for CorpusDir
	ReposDir     string
	PassFixtures []string
	FailFixtures []string
	Workers      int
	AllowWrite   bool
}

// PolicyLine represents a single numbered line of Rego source code annotated with AST diagnostics.
type PolicyLine struct {
	Line       int                     `json:"line"`
	Text       string                  `json:"text"`
	HasError   bool                    `json:"has_error"`
	Diagnostic *model.SchemaDiagnostic `json:"diagnostic,omitempty"`
}

// SnapshotRow represents a single repository row in the Stage A Blast-Radius Matrix.
type SnapshotRow struct {
	RepoName        string                  `json:"repo_name"`
	SourcePath      string                  `json:"source_path"`
	Provider        string                  `json:"provider"`
	ProviderFull    string                  `json:"provider_full"`
	TotalResources  int                     `json:"total_resources"`
	PassedResources int                     `json:"passed_resources"`
	FailedResources int                     `json:"failed_resources"`
	Blocked         bool                    `json:"blocked"`
	Violations      []model.PolicyViolation `json:"violations"`
	PatchKey        string                  `json:"patch_key"`
}

// PatchView represents a surgical hclwrite remediation patch for Stage C review and export.
type PatchView struct {
	Key             string                 `json:"key"`
	RepoName        string                 `json:"repo_name"`
	FilePath        string                 `json:"file_path"`
	ResourceAddress string                 `json:"resource_address"`
	RuleID          string                 `json:"rule_id"`
	Severity        string                 `json:"severity"`
	Remediation     *model.RemediationSpec `json:"remediation,omitempty"`
	OriginalHCL     string                 `json:"original_hcl"`
	PatchedHCL      string                 `json:"patched_hcl"`
	UnifiedDiff     string                 `json:"unified_diff"`
	Applied         bool                   `json:"applied"`
}

// WorkspaceResponse encapsulates the full control plane state returned by GET /api/workspace.
type WorkspaceResponse struct {
	State             string                    `json:"state"`
	EmptyWorkspace    bool                      `json:"empty_workspace"`
	CustomUploaded    bool                      `json:"custom_uploaded"`
	ActivePolicy      string                    `json:"active_policy"`
	ActivePolicyName  string                    `json:"active_policy_name"`
	AvailablePolicies []string                  `json:"available_policies"`
	CorpusDir         string                    `json:"corpus_dir"`
	SchemaPath        string                    `json:"schema_path"`
	ReposDir          string                    `json:"repos_dir"`
	Workers           int                       `json:"workers"`
	EvalDurationMs    float64                   `json:"eval_duration_ms"`
	Verification      *model.VerificationResult `json:"verification"`
	PolicyLines       []PolicyLine              `json:"policy_lines"`
	RawPolicySource   string                    `json:"raw_policy_source"`
	PolicySource      string                    `json:"policy_source"`
	Schemas           model.ProviderSchemaMap   `json:"schemas"`
	Backtest          *model.BlastRadiusReport  `json:"backtest"`
	SnapshotRows      []SnapshotRow             `json:"snapshot_rows"`
	Patches           []PatchView               `json:"patches"`
	AllowWrite        bool                      `json:"allow_write"`
}

// UploadedFile represents a single file uploaded from the browser UI.
type UploadedFile struct {
	Name    string `json:"name"`
	Repo    string `json:"repo,omitempty"`
	Content string `json:"content"`
}

// WorkspaceUploadRequest defines the JSON request payload for POST /api/workspace/upload.
type WorkspaceUploadRequest struct {
	PolicyFile       *UploadedFile  `json:"policy_file,omitempty"`
	SchemaFile       *UploadedFile  `json:"schema_file,omitempty"`
	UseBuiltinSchema bool           `json:"use_builtin_schema"`
	PlanFiles        []UploadedFile `json:"plan_files"`
	TFFiles          []UploadedFile `json:"tf_files,omitempty"`
}

// WorkspaceConfigureRequest defines the JSON request payload for POST /api/workspace/configure.
type WorkspaceConfigureRequest struct {
	Mode       string `json:"mode,omitempty"` // "empty", "demo", or "paths"
	PolicyPath string `json:"policy_path,omitempty"`
	SchemaPath string `json:"schema_path,omitempty"`
	CorpusDir  string `json:"corpus_dir,omitempty"`
	ReposDir   string `json:"repos_dir,omitempty"`
}

// VerifyRequest defines the JSON request payload for POST /api/verify.
type VerifyRequest struct {
	PolicyPath    string   `json:"policy_path"`
	PolicyContent string   `json:"policy_content"`
	SchemaPath    string   `json:"schema_path"`
	PassFixtures  []string `json:"pass_fixtures,omitempty"`
	FailFixtures  []string `json:"fail_fixtures,omitempty"`
}

// VerifyResponse defines the JSON response payload for POST /api/verify.
type VerifyResponse struct {
	State            string                    `json:"state"`
	PolicyPath       string                    `json:"policy_path"`
	PackageName      string                    `json:"package_name"`
	Valid            bool                      `json:"valid"`
	Diagnostics      []model.SchemaDiagnostic  `json:"diagnostics"`
	ActivePolicy     string                    `json:"active_policy"`
	ActivePolicyName string                    `json:"active_policy_name"`
	Verification     *model.VerificationResult `json:"verification"`
	PolicyLines      []PolicyLine              `json:"policy_lines"`
	RawPolicySource  string                    `json:"raw_policy_source"`
	PolicySource     string                    `json:"policy_source"`
	Schemas          model.ProviderSchemaMap   `json:"schemas"`
}

// BacktestRequest defines the JSON request payload for POST /api/backtest.
type BacktestRequest struct {
	PolicyPath    string `json:"policy_path"`
	PolicyContent string `json:"policy_content"`
	CorpusDir     string `json:"corpus_dir"`
	PlansDir      string `json:"plans_dir"`
	Reset         bool   `json:"reset"`
}

// BacktestResponse defines the JSON response payload for POST /api/backtest.
type BacktestResponse struct {
	State               string                    `json:"state"`
	PolicyPath          string                    `json:"policy_path"`
	TotalReposAnalyzed  int                       `json:"total_repos_analyzed"`
	ImpactedReposCount  int                       `json:"impacted_repos_count"`
	TotalPlansAnalyzed  int                       `json:"total_plans_analyzed"`
	BlockedPlansCount   int                       `json:"blocked_plans_count"`
	TotalResources      int                       `json:"total_resources"`
	TotalViolations     int                       `json:"total_violations"`
	BreakdownByProvider map[string]int            `json:"breakdown_by_provider"`
	RepoImpacts         []model.RepoImpact        `json:"repo_impacts"`
	EvalDurationMs      float64                   `json:"eval_duration_ms"`
	EvalMs              float64                   `json:"eval_ms"`
	Workers             int                       `json:"workers"`
	PolicySource        string                    `json:"policy_source"`
	Diagnostics         []model.SchemaDiagnostic  `json:"diagnostics"`
	Verification        *model.VerificationResult `json:"verification"`
	Backtest            *model.BlastRadiusReport  `json:"backtest"`
	SnapshotRows        []SnapshotRow             `json:"snapshot_rows"`
	Patches             []PatchView               `json:"patches"`
}

// RemediateRequest defines the JSON request payload for POST /api/remediate.
type RemediateRequest struct {
	PolicyPath      string `json:"policy_path"`
	CorpusDir       string `json:"corpus_dir"`
	PlansDir        string `json:"plans_dir"`
	ReposDir        string `json:"repos_dir"`
	ResourceAddress string `json:"resource_address"`
	PatchKey        string `json:"patch_key"`
	Apply           bool   `json:"apply"`
	Write           bool   `json:"write"`
}

// RemediateResponse defines the JSON response payload for POST /api/remediate.
type RemediateResponse struct {
	State         string                   `json:"state"`
	Patches       []PatchView              `json:"patches"`
	RawPatches    []model.RemediationPatch `json:"raw_patches"`
	Applied       bool                     `json:"applied"`
	WrittenToDisk bool                     `json:"written_to_disk"`
	Backtest      *model.BlastRadiusReport `json:"backtest,omitempty"`
	SnapshotRows  []SnapshotRow            `json:"snapshot_rows,omitempty"`
}

// ApplyRequest defines the JSON request payload for POST /api/apply.
type ApplyRequest struct {
	PolicyPath      string `json:"policy_path"`
	ReposDir        string `json:"repos_dir"`
	ResourceAddress string `json:"resource_address"`
	PatchKey        string `json:"patch_key"`
	Repo            string `json:"repo"`
	Write           bool   `json:"write"`
	Reset           bool   `json:"reset"`
}

// ApplyResponse defines the JSON response payload for POST /api/apply.
type ApplyResponse struct {
	State              string                    `json:"state"`
	Applied            bool                      `json:"applied"`
	WrittenToDisk      bool                      `json:"written_to_disk"`
	AppliedCount       int                       `json:"applied_count"`
	EvalMs             float64                   `json:"eval_ms"`
	Workers            int                       `json:"workers"`
	Patches            []PatchView               `json:"patches"`
	Backtest           *model.BlastRadiusReport  `json:"backtest"`
	SnapshotRows       []SnapshotRow             `json:"snapshot_rows"`
	Verification       *model.VerificationResult `json:"verification"`
	TotalReposAnalyzed int                       `json:"total_repos_analyzed"`
	BlockedPlansCount  int                       `json:"blocked_plans_count"`
	TotalResources     int                       `json:"total_resources"`
	TotalViolations    int                       `json:"total_violations"`
}

// Server implements the local-first HTTP control plane and satisfies http.Handler.
type Server struct {
	cfg          Config
	workspaceAbs string
	boundAddr    string

	parser    *parser.Parser
	verifier  *verifier.Verifier
	evaluator *engine.Evaluator
	runner    *backtest.Runner
	patcher   *remediate.Patcher
	mux       *http.ServeMux

	mu                  sync.RWMutex
	activePolicyRel     string
	forcedState         string
	remediatedResources map[string]*model.RemediationSpec
	patchedHCLByFile    map[string]string

	// Custom upload / dynamic workspace paths
	uploadDirAbs    string
	customPolicyRel string
	customSchemaRel string
	customCorpusRel string
	customReposRel  string
}

// Ensure Server satisfies http.Handler at compile time.
var _ http.Handler = (*Server)(nil)

// NewServer validates configuration, enforces workspace containment on configured paths,
// and initializes the HTTP control plane server.
func NewServer(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = DefaultAddr
	}
	if strings.TrimSpace(cfg.WorkspaceDir) == "" {
		cfg.WorkspaceDir = DefaultWorkspaceDir
	}
	if strings.TrimSpace(cfg.PolicyPath) == "" {
		cfg.PolicyPath = DefaultPolicyPath
	}
	if strings.TrimSpace(cfg.SchemaPath) == "" {
		cfg.SchemaPath = DefaultSchemaPath
	}
	if strings.TrimSpace(cfg.CorpusDir) == "" && strings.TrimSpace(cfg.PlansDir) != "" {
		cfg.CorpusDir = strings.TrimSpace(cfg.PlansDir)
	}
	if strings.TrimSpace(cfg.CorpusDir) == "" {
		cfg.CorpusDir = DefaultCorpusDir
	}
	if strings.TrimSpace(cfg.ReposDir) == "" {
		cfg.ReposDir = DefaultReposDir
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
		if cfg.Workers < 1 {
			cfg.Workers = 1
		}
	}

	wsAbs, err := filepath.Abs(filepath.Clean(cfg.WorkspaceDir))
	if err != nil {
		return nil, fmt.Errorf("resolving workspace directory %q: %w", cfg.WorkspaceDir, err)
	}
	wsInfo, err := os.Stat(wsAbs)
	if err != nil {
		return nil, fmt.Errorf("stat workspace directory %q: %w", wsAbs, err)
	}
	if !wsInfo.IsDir() {
		return nil, fmt.Errorf("workspace path %q is not a directory", wsAbs)
	}

	p := parser.NewParser()
	v := verifier.NewVerifier()
	eval := engine.NewEvaluator()
	runner := backtest.NewRunner(
		backtest.WithEvaluator(eval),
		backtest.WithParser(p),
		backtest.WithConcurrency(cfg.Workers),
	)
	patcher := remediate.NewPatcher(remediate.WithWriteChanges(false))

	s := &Server{
		cfg:                 cfg,
		workspaceAbs:        wsAbs,
		boundAddr:           cfg.Addr,
		parser:              p,
		verifier:            v,
		evaluator:           eval,
		runner:              runner,
		patcher:             patcher,
		mux:                 http.NewServeMux(),
		remediatedResources: make(map[string]*model.RemediationSpec),
		patchedHCLByFile:    make(map[string]string),
	}

	// Validate configured default paths are strictly contained within WorkspaceDir.
	_, policyRel, err := s.ResolveWorkspaceRel(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("invalid policy path %q: %w", cfg.PolicyPath, err)
	}
	if _, _, err := s.ResolveWorkspaceRel(cfg.SchemaPath); err != nil {
		return nil, fmt.Errorf("invalid schema path %q: %w", cfg.SchemaPath, err)
	}
	if _, _, err := s.ResolveWorkspaceRel(cfg.CorpusDir); err != nil {
		return nil, fmt.Errorf("invalid corpus directory %q: %w", cfg.CorpusDir, err)
	}
	if _, _, err := s.ResolveWorkspaceRel(cfg.ReposDir); err != nil {
		return nil, fmt.Errorf("invalid repos directory %q: %w", cfg.ReposDir, err)
	}
	s.activePolicyRel = policyRel

	staticSubFS, err := fs.Sub(staticEmbedFS, "static")
	if err != nil {
		return nil, fmt.Errorf("initializing embedded static filesystem: %w", err)
	}
	fileServer := http.FileServer(http.FS(staticSubFS))

	s.mux.HandleFunc("/api/workspace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handleGetWorkspace(w, r)
	})
	s.mux.HandleFunc("/api/workspace/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handlePostWorkspaceUpload(w, r)
	})
	s.mux.HandleFunc("/api/workspace/configure", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handlePostWorkspaceConfigure(w, r)
	})
	s.mux.HandleFunc("/api/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handlePostVerify(w, r)
	})
	s.mux.HandleFunc("/api/backtest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handlePostBacktest(w, r)
	})
	s.mux.HandleFunc("/api/remediate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handlePostRemediate(w, r)
	})
	s.mux.HandleFunc("/api/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.handlePostApply(w, r)
	})
	s.mux.Handle("/", fileServer)

	return s, nil
}

// Addr returns the configured or bound TCP address (host:port) of the server.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.boundAddr
}

// ServeHTTP implements http.Handler with defensive security headers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	s.mux.ServeHTTP(w, r)
}

// ListenAndServe starts the HTTP server on the configured address and shuts down gracefully
// when ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.Addr, err)
	}

	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()

	httpSrv := &http.Server{
		Addr:              s.boundAddr,
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if serveErr := httpSrv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return <-errCh
	case serveErr := <-errCh:
		return serveErr
	}
}

// activeWorkspaceAbs returns the active root directory (either the temporary uploaded sandbox
// directory when a browser upload is active, or the configured WorkspaceDir).
func (s *Server) activeWorkspaceAbs() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.uploadDirAbs != "" {
		return s.uploadDirAbs
	}
	return s.workspaceAbs
}

func (s *Server) defaultPolicyPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.customPolicyRel != "" {
		return s.customPolicyRel
	}
	return s.cfg.PolicyPath
}

func (s *Server) defaultSchemaPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.customSchemaRel != "" {
		return s.customSchemaRel
	}
	return s.cfg.SchemaPath
}

func (s *Server) defaultCorpusDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.customCorpusRel != "" {
		return s.customCorpusRel
	}
	return s.cfg.CorpusDir
}

func (s *Server) defaultReposDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.customReposRel != "" {
		return s.customReposRel
	}
	return s.cfg.ReposDir
}

func (s *Server) isCustomUploaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.uploadDirAbs != ""
}

// ResolveWorkspacePath resolves relOrAbs against the server's configured WorkspaceDir
// and verifies that the resolved path (including any existing symlinks) stays strictly inside WorkspaceDir.
func (s *Server) ResolveWorkspacePath(relOrAbs string) (string, error) {
	absPath, _, err := s.ResolveWorkspaceRel(relOrAbs)
	return absPath, err
}

// ResolveWorkspaceRel resolves userPath against the active workspace root, returning both the absolute path
// and the forward-slash workspace-relative path, or ErrPathTraversal if the path escapes the workspace root.
func (s *Server) ResolveWorkspaceRel(userPath string) (string, string, error) {
	return resolvePathUnderRoot(s.activeWorkspaceAbs(), userPath)
}

func resolvePathUnderRoot(rootAbs, userPath string) (string, string, error) {
	trimmed := strings.TrimSpace(userPath)
	if trimmed == "" {
		return "", "", fmt.Errorf("path cannot be empty")
	}
	if strings.ContainsRune(trimmed, '\x00') {
		return "", "", ErrPathTraversal
	}

	wsSlash := filepath.ToSlash(rootAbs)
	trimmedSlash := filepath.ToSlash(trimmed)

	// Reject root-anchored paths on Windows (e.g. "/etc/passwd" or "\Windows") that don't match rootAbs.
	if (strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, `\`)) && !strings.HasPrefix(trimmedSlash, wsSlash) {
		return "", "", ErrPathTraversal
	}

	var targetAbs string
	if filepath.IsAbs(trimmed) {
		targetAbs = filepath.Clean(trimmed)
	} else {
		targetAbs = filepath.Clean(filepath.Join(rootAbs, filepath.FromSlash(trimmed)))
	}

	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return "", "", ErrPathTraversal
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", ErrPathTraversal
	}

	// Verify symlink containment when workspace and target (or its parent) exist on disk.
	wsReal, wsErr := filepath.EvalSymlinks(rootAbs)
	if wsErr == nil {
		checkPath := targetAbs
		if _, statErr := os.Lstat(checkPath); statErr != nil {
			checkPath = filepath.Dir(targetAbs)
		}
		if targetReal, evalErr := filepath.EvalSymlinks(checkPath); evalErr == nil {
			relReal, relErr := filepath.Rel(wsReal, targetReal)
			if relErr != nil || relReal == ".." || strings.HasPrefix(relReal, ".."+string(filepath.Separator)) || filepath.IsAbs(relReal) {
				return "", "", ErrPathTraversal
			}
		}
	}

	return targetAbs, filepath.ToSlash(rel), nil
}

// handleGetWorkspace handles GET /api/workspace.
func (s *Server) handleGetWorkspace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	stateParam := strings.TrimSpace(query.Get("state"))
	policyParam := strings.TrimSpace(query.Get("policy"))

	var policyOverride string
	if policyParam != "" {
		_, rel, err := s.ResolveWorkspaceRel(policyParam)
		if err != nil {
			s.writeError(w, err)
			return
		}
		policyOverride = rel
	}

	if stateParam != "" {
		switch stateParam {
		case StateEmpty:
			s.clearUploadSandbox()
			s.mu.Lock()
			s.remediatedResources = make(map[string]*model.RemediationSpec)
			s.patchedHCLByFile = make(map[string]string)
			s.forcedState = StateEmpty
			s.mu.Unlock()
		case StateViolationsDetected:
			s.clearUploadSandbox()
			_, defRel, defErr := resolvePathUnderRoot(s.workspaceAbs, s.cfg.PolicyPath)
			s.mu.Lock()
			s.remediatedResources = make(map[string]*model.RemediationSpec)
			s.patchedHCLByFile = make(map[string]string)
			s.forcedState = StateViolationsDetected
			if policyOverride == "" {
				if defErr == nil {
					s.activePolicyRel = defRel
				}
			} else {
				s.activePolicyRel = policyOverride
			}
			s.mu.Unlock()
		case StateFailOpenCaught:
			s.clearUploadSandbox()
			brokenCandidate := filepath.ToSlash(filepath.Join(filepath.Dir(s.cfg.PolicyPath), "broken_fail_open.rego"))
			absBroken, relBroken, brokenErr := resolvePathUnderRoot(s.workspaceAbs, brokenCandidate)
			s.mu.Lock()
			s.forcedState = StateFailOpenCaught
			if policyOverride != "" {
				s.activePolicyRel = policyOverride
			} else if brokenErr == nil {
				if _, statErr := os.Stat(absBroken); statErr == nil {
					s.activePolicyRel = relBroken
				}
			}
			s.mu.Unlock()
		case StateEnforceReady:
			s.clearUploadSandbox()
			_, defRel, defErr := resolvePathUnderRoot(s.workspaceAbs, s.cfg.PolicyPath)
			s.mu.Lock()
			s.forcedState = StateEnforceReady
			if policyOverride != "" {
				s.activePolicyRel = policyOverride
			} else if defErr == nil {
				s.activePolicyRel = defRel
			}
			s.mu.Unlock()
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("unsupported workspace state %q", stateParam),
			})
			return
		}
	} else if policyOverride != "" {
		s.mu.Lock()
		s.activePolicyRel = policyOverride
		if s.forcedState == StateEmpty {
			s.forcedState = ""
		} else {
			s.forcedState = ""
		}
		s.mu.Unlock()
	}

	resp, err := s.buildWorkspaceState(ctx, "", "")
	if err != nil {
		s.writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) clearUploadSandbox() {
	s.mu.Lock()
	oldDir := s.uploadDirAbs
	s.uploadDirAbs = ""
	s.customPolicyRel = ""
	s.customSchemaRel = ""
	s.customCorpusRel = ""
	s.customReposRel = ""
	s.mu.Unlock()
	if oldDir != "" {
		_ = os.RemoveAll(oldDir)
	}
}

func sanitizeUploadedFilename(name, defaultExt string) string {
	cleaned := filepath.ToSlash(strings.TrimSpace(name))
	base := path.Base(cleaned)
	var b strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	res := strings.Trim(b.String(), ".")
	if res == "" {
		res = "uploaded" + defaultExt
	}
	if defaultExt != "" && !strings.HasSuffix(strings.ToLower(res), defaultExt) {
		res += defaultExt
	}
	return res
}

func sanitizeRepoDirName(rawName string, idx int) string {
	cleaned := filepath.ToSlash(strings.TrimSpace(rawName))
	parts := strings.Split(cleaned, "/")
	var candidate string
	if len(parts) >= 2 {
		candidate = parts[len(parts)-2]
	} else {
		base := path.Base(cleaned)
		ext := path.Ext(base)
		candidate = strings.TrimSuffix(base, ext)
	}
	if candidate == "" || strings.EqualFold(candidate, "plan") || strings.EqualFold(candidate, "tfplan") {
		candidate = fmt.Sprintf("uploaded_repo_%d", idx+1)
	}
	var b strings.Builder
	for _, r := range candidate {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	res := strings.Trim(b.String(), "_")
	if res == "" {
		res = fmt.Sprintf("uploaded_repo_%d", idx+1)
	}
	return res
}

// handlePostWorkspaceUpload handles POST /api/workspace/upload, allowing users to upload
// their own .rego policy, plan.json files, provider schema.json, and .tf files directly from the browser UI.
func (s *Server) handlePostWorkspaceUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Body == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing upload request body"})
		return
	}
	limited := http.MaxBytesReader(w, r.Body, MaxUploadBodyBytes)
	defer limited.Close()

	raw, err := io.ReadAll(limited)
	if err != nil {
		s.writeError(w, err)
		return
	}
	var req WorkspaceUploadRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid upload JSON: %v", err)})
		return
	}

	if len(req.PlanFiles) == 0 && (req.PolicyFile == nil || strings.TrimSpace(req.PolicyFile.Content) == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "upload requires at least one Terraform plan JSON file (.json) or Rego policy file (.rego)",
		})
		return
	}

	tmpDir, err := os.MkdirTemp("", "tfsim-upload-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("creating upload sandbox: %v", err)})
		return
	}

	policiesDir := filepath.Join(tmpDir, "policies")
	schemasDir := filepath.Join(tmpDir, "schemas")
	plansDir := filepath.Join(tmpDir, "plans")
	reposDir := filepath.Join(tmpDir, "repos")
	for _, d := range []string{policiesDir, schemasDir, plansDir, reposDir} {
		if mkErr := os.MkdirAll(d, 0o755); mkErr != nil {
			_ = os.RemoveAll(tmpDir)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("creating sandbox subdirectory: %v", mkErr)})
			return
		}
	}

	// 1. Write Policy File (or copy workspace default / built-in fallback)
	policyFilename := "uploaded_policy.rego"
	var policyContent []byte
	if req.PolicyFile != nil && strings.TrimSpace(req.PolicyFile.Content) != "" {
		policyFilename = sanitizeUploadedFilename(req.PolicyFile.Name, ".rego")
		policyContent = []byte(req.PolicyFile.Content)
	} else {
		origPolicyAbs := filepath.Join(s.workspaceAbs, filepath.FromSlash(s.cfg.PolicyPath))
		if b, readErr := os.ReadFile(origPolicyAbs); readErr == nil {
			policyFilename = filepath.Base(origPolicyAbs)
			policyContent = b
		} else {
			policyContent = []byte(builtinFallbackRegoPolicy)
		}
	}
	if writeErr := os.WriteFile(filepath.Join(policiesDir, policyFilename), policyContent, 0o600); writeErr != nil {
		_ = os.RemoveAll(tmpDir)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("writing policy file: %v", writeErr)})
		return
	}

	// 2. Write Provider Schema File (or copy built-in multi-cloud schema)
	schemaFilename := "multicloud_schema.json"
	var schemaContent []byte
	if req.SchemaFile != nil && strings.TrimSpace(req.SchemaFile.Content) != "" && !req.UseBuiltinSchema {
		schemaFilename = sanitizeUploadedFilename(req.SchemaFile.Name, ".json")
		schemaContent = []byte(req.SchemaFile.Content)
	} else {
		origSchemaAbs := filepath.Join(s.workspaceAbs, filepath.FromSlash(s.cfg.SchemaPath))
		if b, readErr := os.ReadFile(origSchemaAbs); readErr == nil {
			schemaContent = b
		} else {
			schemaContent = []byte(builtinFallbackProviderSchema)
		}
	}
	if writeErr := os.WriteFile(filepath.Join(schemasDir, schemaFilename), schemaContent, 0o600); writeErr != nil {
		_ = os.RemoveAll(tmpDir)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("writing schema file: %v", writeErr)})
		return
	}

	// 3. Write Plan JSON files into plans/<repo>/plan.json
	usedRepoNames := make(map[string]int)
	var firstRepoName string
	for idx, pf := range req.PlanFiles {
		if strings.TrimSpace(pf.Content) == "" {
			continue
		}
		repoName := sanitizeRepoDirName(pf.Name, idx)
		if count, exists := usedRepoNames[repoName]; exists {
			usedRepoNames[repoName] = count + 1
			repoName = fmt.Sprintf("%s_%d", repoName, count+1)
		} else {
			usedRepoNames[repoName] = 1
		}
		if firstRepoName == "" {
			firstRepoName = repoName
		}
		repoPlanDir := filepath.Join(plansDir, repoName)
		if mkErr := os.MkdirAll(repoPlanDir, 0o755); mkErr != nil {
			_ = os.RemoveAll(tmpDir)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("creating plan directory: %v", mkErr)})
			return
		}
		if writeErr := os.WriteFile(filepath.Join(repoPlanDir, "plan.json"), []byte(pf.Content), 0o600); writeErr != nil {
			_ = os.RemoveAll(tmpDir)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("writing plan file: %v", writeErr)})
			return
		}
	}

	// 4. Write optional .tf files into repos/<repo>/<file>.tf
	for idx, tf := range req.TFFiles {
		if strings.TrimSpace(tf.Content) == "" {
			continue
		}
		repoName := sanitizeRepoDirName(tf.Name, idx)
		if strings.HasPrefix(repoName, "uploaded_repo_") && firstRepoName != "" {
			repoName = firstRepoName
		}
		tfFileName := sanitizeUploadedFilename(tf.Name, ".tf")
		repoTFDir := filepath.Join(reposDir, repoName)
		if mkErr := os.MkdirAll(repoTFDir, 0o755); mkErr != nil {
			_ = os.RemoveAll(tmpDir)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("creating repo directory: %v", mkErr)})
			return
		}
		if writeErr := os.WriteFile(filepath.Join(repoTFDir, tfFileName), []byte(tf.Content), 0o600); writeErr != nil {
			_ = os.RemoveAll(tmpDir)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("writing tf file: %v", writeErr)})
			return
		}
	}

	s.mu.Lock()
	oldUploadDir := s.uploadDirAbs
	s.uploadDirAbs = tmpDir
	s.customPolicyRel = filepath.ToSlash(filepath.Join("policies", policyFilename))
	s.customSchemaRel = filepath.ToSlash(filepath.Join("schemas", schemaFilename))
	s.customCorpusRel = "plans"
	s.customReposRel = "repos"
	s.activePolicyRel = s.customPolicyRel
	s.forcedState = ""
	s.remediatedResources = make(map[string]*model.RemediationSpec)
	s.patchedHCLByFile = make(map[string]string)
	s.mu.Unlock()

	if oldUploadDir != "" {
		_ = os.RemoveAll(oldUploadDir)
	}

	wsResp, err := s.buildWorkspaceState(ctx, "", "")
	if err != nil {
		s.writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wsResp)
}

// handlePostWorkspaceConfigure handles POST /api/workspace/configure, allowing users to switch
// between "empty" (0 loaded), "demo" (default configured workspace paths), or custom workspace-relative paths.
func (s *Server) handlePostWorkspaceConfigure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req WorkspaceConfigureRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	switch mode {
	case "empty":
		s.clearUploadSandbox()
		s.mu.Lock()
		s.remediatedResources = make(map[string]*model.RemediationSpec)
		s.patchedHCLByFile = make(map[string]string)
		s.forcedState = StateEmpty
		s.mu.Unlock()
	case "demo", "reset":
		s.clearUploadSandbox()
		_, defRel, _ := resolvePathUnderRoot(s.workspaceAbs, s.cfg.PolicyPath)
		s.mu.Lock()
		s.remediatedResources = make(map[string]*model.RemediationSpec)
		s.patchedHCLByFile = make(map[string]string)
		s.forcedState = ""
		if defRel != "" {
			s.activePolicyRel = defRel
		}
		s.mu.Unlock()
	default:
		// Configure workspace-relative paths under s.workspaceAbs
		s.clearUploadSandbox()
		policyRel := s.cfg.PolicyPath
		if strings.TrimSpace(req.PolicyPath) != "" {
			_, rel, err := resolvePathUnderRoot(s.workspaceAbs, req.PolicyPath)
			if err != nil {
				s.writeError(w, err)
				return
			}
			policyRel = rel
		}
		schemaRel := s.cfg.SchemaPath
		if strings.TrimSpace(req.SchemaPath) != "" {
			_, rel, err := resolvePathUnderRoot(s.workspaceAbs, req.SchemaPath)
			if err != nil {
				s.writeError(w, err)
				return
			}
			schemaRel = rel
		}
		corpusRel := s.cfg.CorpusDir
		if strings.TrimSpace(req.CorpusDir) != "" {
			_, rel, err := resolvePathUnderRoot(s.workspaceAbs, req.CorpusDir)
			if err != nil {
				s.writeError(w, err)
				return
			}
			corpusRel = rel
		}
		reposRel := s.cfg.ReposDir
		if strings.TrimSpace(req.ReposDir) != "" {
			_, rel, err := resolvePathUnderRoot(s.workspaceAbs, req.ReposDir)
			if err != nil {
				s.writeError(w, err)
				return
			}
			reposRel = rel
		}

		s.mu.Lock()
		s.customPolicyRel = policyRel
		s.customSchemaRel = schemaRel
		s.customCorpusRel = corpusRel
		s.customReposRel = reposRel
		s.activePolicyRel = policyRel
		s.forcedState = ""
		s.remediatedResources = make(map[string]*model.RemediationSpec)
		s.patchedHCLByFile = make(map[string]string)
		s.mu.Unlock()
	}

	wsResp, err := s.buildWorkspaceState(ctx, "", "")
	if err != nil {
		s.writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wsResp)
}

// handlePostVerify handles POST /api/verify.
func (s *Server) handlePostVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req VerifyRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	policyRel := s.getActivePolicyRel()
	if strings.TrimSpace(req.PolicyPath) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.PolicyPath)
		if err != nil {
			s.writeError(w, err)
			return
		}
		policyRel = rel
	}

	schemaRel := s.defaultSchemaPath()
	if strings.TrimSpace(req.SchemaPath) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.SchemaPath)
		if err != nil {
			s.writeError(w, err)
			return
		}
		schemaRel = rel
	}

	schemaAbs, _, err := s.ResolveWorkspaceRel(schemaRel)
	if err != nil {
		s.writeError(w, err)
		return
	}
	schemas, err := s.parser.LoadProviderSchemas(ctx, schemaAbs)
	if err != nil {
		s.writeError(w, err)
		return
	}

	verRes, rawSource, policyLines, err := s.verifyPolicyOrContent(ctx, policyRel, req.PolicyContent, schemas, req.PassFixtures, req.FailFixtures)
	if err != nil {
		s.writeError(w, err)
		return
	}

	s.mu.Lock()
	s.activePolicyRel = policyRel
	if !verRes.Valid {
		s.forcedState = StateFailOpenCaught
	} else if s.forcedState == StateFailOpenCaught {
		s.forcedState = ""
	}
	s.mu.Unlock()

	state := StateViolationsDetected
	if !verRes.Valid {
		state = StateFailOpenCaught
	} else if s.isEnforceReady() {
		state = StateEnforceReady
	}

	diags := verRes.Diagnostics
	if diags == nil {
		diags = []model.SchemaDiagnostic{}
	}

	resp := VerifyResponse{
		State:            state,
		PolicyPath:       verRes.PolicyPath,
		PackageName:      verRes.PackageName,
		Valid:            verRes.Valid,
		Diagnostics:      diags,
		ActivePolicy:     policyRel,
		ActivePolicyName: filepath.Base(policyRel),
		Verification:     verRes,
		PolicyLines:      policyLines,
		RawPolicySource:  rawSource,
		PolicySource:     rawSource,
		Schemas:          schemas,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handlePostBacktest handles POST /api/backtest.
func (s *Server) handlePostBacktest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req BacktestRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	if req.Reset {
		s.mu.Lock()
		s.remediatedResources = make(map[string]*model.RemediationSpec)
		s.patchedHCLByFile = make(map[string]string)
		s.forcedState = ""
		s.mu.Unlock()
	}

	policyRel := s.getActivePolicyRel()
	if strings.TrimSpace(req.PolicyPath) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.PolicyPath)
		if err != nil {
			s.writeError(w, err)
			return
		}
		policyRel = rel
		s.mu.Lock()
		s.activePolicyRel = policyRel
		s.forcedState = ""
		s.mu.Unlock()
	}

	corpusRel := s.defaultCorpusDir()
	rawCorpus := strings.TrimSpace(req.CorpusDir)
	if rawCorpus == "" {
		rawCorpus = strings.TrimSpace(req.PlansDir)
	}
	if rawCorpus != "" {
		_, rel, err := s.ResolveWorkspaceRel(rawCorpus)
		if err != nil {
			s.writeError(w, err)
			return
		}
		corpusRel = rel
	}

	wsResp, err := s.buildWorkspaceState(ctx, policyRel, corpusRel)
	if err != nil {
		s.writeError(w, err)
		return
	}

	// If live policy_content was supplied, evaluate against the in-memory content.
	if strings.TrimSpace(req.PolicyContent) != "" {
		wsResp, err = s.evaluateLivePolicyWorkspace(ctx, policyRel, req.PolicyContent, corpusRel)
		if err != nil {
			s.writeError(w, err)
			return
		}
	}

	var diags []model.SchemaDiagnostic
	if wsResp.Verification != nil && wsResp.Verification.Diagnostics != nil {
		diags = wsResp.Verification.Diagnostics
	} else {
		diags = []model.SchemaDiagnostic{}
	}

	rep := wsResp.Backtest
	resp := BacktestResponse{
		State:               wsResp.State,
		PolicyPath:          rep.PolicyPath,
		TotalReposAnalyzed:  rep.TotalReposAnalyzed,
		ImpactedReposCount:  rep.ImpactedReposCount,
		TotalPlansAnalyzed:  rep.TotalPlansAnalyzed,
		BlockedPlansCount:   rep.BlockedPlansCount,
		TotalResources:      rep.TotalResources,
		TotalViolations:     rep.TotalViolations,
		BreakdownByProvider: rep.BreakdownByProvider,
		RepoImpacts:         rep.RepoImpacts,
		EvalDurationMs:      wsResp.EvalDurationMs,
		EvalMs:              wsResp.EvalDurationMs,
		Workers:             wsResp.Workers,
		PolicySource:        wsResp.RawPolicySource,
		Diagnostics:         diags,
		Verification:        wsResp.Verification,
		Backtest:            rep,
		SnapshotRows:        wsResp.SnapshotRows,
		Patches:             wsResp.Patches,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handlePostRemediate handles POST /api/remediate.
func (s *Server) handlePostRemediate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req RemediateRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	policyRel := s.getActivePolicyRel()
	if strings.TrimSpace(req.PolicyPath) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.PolicyPath)
		if err != nil {
			s.writeError(w, err)
			return
		}
		policyRel = rel
	}

	corpusRel := s.defaultCorpusDir()
	rawCorpus := strings.TrimSpace(req.CorpusDir)
	if rawCorpus == "" {
		rawCorpus = strings.TrimSpace(req.PlansDir)
	}
	if rawCorpus != "" {
		_, rel, err := s.ResolveWorkspaceRel(rawCorpus)
		if err != nil {
			s.writeError(w, err)
			return
		}
		corpusRel = rel
	}

	reposRel := s.defaultReposDir()
	if strings.TrimSpace(req.ReposDir) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.ReposDir)
		if err != nil {
			s.writeError(w, err)
			return
		}
		reposRel = rel
	}

	policyAbs, _, err := s.ResolveWorkspaceRel(policyRel)
	if err != nil {
		s.writeError(w, err)
		return
	}
	if _, statErr := os.Stat(policyAbs); statErr != nil {
		s.writeError(w, statErr)
		return
	}

	corpusAbs, _, err := s.ResolveWorkspaceRel(corpusRel)
	if err != nil {
		s.writeError(w, err)
		return
	}
	reposAbs, _, err := s.ResolveWorkspaceRel(reposRel)
	if err != nil {
		s.writeError(w, err)
		return
	}

	// Load raw (unremediated) snapshots to generate patches for all underlying violations.
	snapshots, err := s.loadCorpusSnapshots(ctx, corpusAbs, false)
	if err != nil {
		s.writeError(w, err)
		return
	}

	backtestRep, err := s.runner.RunBacktest(ctx, []string{policyAbs}, snapshots)
	if err != nil {
		s.writeError(w, err)
		return
	}

	patchViews, rawPatches, allViolations, err := s.generateCorpusPatches(ctx, reposAbs, backtestRep)
	if err != nil {
		s.writeError(w, err)
		return
	}

	// Filter if ResourceAddress or PatchKey was requested.
	filterAddr := strings.TrimSpace(req.ResourceAddress)
	filterKey := strings.TrimSpace(req.PatchKey)
	if filterAddr != "" || filterKey != "" {
		var filteredViews []PatchView
		var filteredRaw []model.RemediationPatch
		for i, pv := range patchViews {
			if (filterAddr != "" && pv.ResourceAddress == filterAddr) || (filterKey != "" && pv.Key == filterKey) {
				filteredViews = append(filteredViews, pv)
				if i < len(rawPatches) {
					filteredRaw = append(filteredRaw, rawPatches[i])
				}
			}
		}
		patchViews = filteredViews
		rawPatches = filteredRaw
	}

	if req.Write && !s.cfg.AllowWrite {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "disk writes are disabled; start server with --allow-write to permit mutating .tf files on disk",
			"code":  "write_forbidden",
		})
		return
	}

	applied := false
	writtenToDisk := false
	if req.Apply || req.Write {
		applied = true
		writtenToDisk, err = s.applyPatchesInternal(ctx, reposAbs, patchViews, rawPatches, allViolations, req.Write)
		if err != nil {
			s.writeError(w, err)
			return
		}
		for i := range patchViews {
			patchViews[i].Applied = true
		}
	}

	wsResp, err := s.buildWorkspaceState(ctx, policyRel, corpusRel)
	if err != nil {
		s.writeError(w, err)
		return
	}

	resp := RemediateResponse{
		State:         wsResp.State,
		Patches:       patchViews,
		RawPatches:    rawPatches,
		Applied:       applied,
		WrittenToDisk: writtenToDisk,
		Backtest:      wsResp.Backtest,
		SnapshotRows:  wsResp.SnapshotRows,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handlePostApply handles POST /api/apply.
func (s *Server) handlePostApply(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req ApplyRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	if req.Write && !s.cfg.AllowWrite {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "disk writes are disabled; start server with --allow-write to permit mutating .tf files on disk",
			"code":  "write_forbidden",
		})
		return
	}

	if req.Reset {
		s.mu.Lock()
		s.remediatedResources = make(map[string]*model.RemediationSpec)
		s.patchedHCLByFile = make(map[string]string)
		s.forcedState = StateViolationsDetected
		s.mu.Unlock()

		wsResp, err := s.buildWorkspaceState(ctx, "", "")
		if err != nil {
			s.writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, ApplyResponse{
			State:              wsResp.State,
			Applied:            false,
			WrittenToDisk:      false,
			AppliedCount:       0,
			Patches:            wsResp.Patches,
			Backtest:           wsResp.Backtest,
			SnapshotRows:       wsResp.SnapshotRows,
			Verification:       wsResp.Verification,
			TotalReposAnalyzed: wsResp.Backtest.TotalReposAnalyzed,
			BlockedPlansCount:  wsResp.Backtest.BlockedPlansCount,
			TotalResources:     wsResp.Backtest.TotalResources,
			TotalViolations:    wsResp.Backtest.TotalViolations,
		})
		return
	}

	policyRel := s.getActivePolicyRel()
	if strings.TrimSpace(req.PolicyPath) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.PolicyPath)
		if err != nil {
			s.writeError(w, err)
			return
		}
		policyRel = rel
	} else {
		// Ensure we apply against the valid baseline policy if currently on broken_fail_open.rego.
		if strings.HasSuffix(policyRel, "broken_fail_open.rego") {
			if _, defRel, err := s.ResolveWorkspaceRel(s.defaultPolicyPath()); err == nil {
				policyRel = defRel
			}
		}
	}

	reposRel := s.defaultReposDir()
	if strings.TrimSpace(req.ReposDir) != "" {
		_, rel, err := s.ResolveWorkspaceRel(req.ReposDir)
		if err != nil {
			s.writeError(w, err)
			return
		}
		reposRel = rel
	}

	policyAbs, _, err := s.ResolveWorkspaceRel(policyRel)
	if err != nil {
		s.writeError(w, err)
		return
	}
	if _, statErr := os.Stat(policyAbs); statErr != nil {
		s.writeError(w, statErr)
		return
	}

	corpusAbs, _, err := s.ResolveWorkspaceRel(s.defaultCorpusDir())
	if err != nil {
		s.writeError(w, err)
		return
	}
	reposAbs, _, err := s.ResolveWorkspaceRel(reposRel)
	if err != nil {
		s.writeError(w, err)
		return
	}

	rawSnapshots, err := s.loadCorpusSnapshots(ctx, corpusAbs, false)
	if err != nil {
		s.writeError(w, err)
		return
	}
	rawBacktest, err := s.runner.RunBacktest(ctx, []string{policyAbs}, rawSnapshots)
	if err != nil {
		s.writeError(w, err)
		return
	}

	patchViews, rawPatches, allViolations, err := s.generateCorpusPatches(ctx, reposAbs, rawBacktest)
	if err != nil {
		s.writeError(w, err)
		return
	}

	filterAddr := strings.TrimSpace(req.ResourceAddress)
	filterKey := strings.TrimSpace(req.PatchKey)
	if filterKey == "" && strings.TrimSpace(req.Repo) != "" && strings.TrimSpace(req.Repo) != "all" {
		filterKey = strings.TrimSpace(req.Repo)
	}
	targetViews := patchViews
	targetRaw := rawPatches
	targetViolations := allViolations

	if filterAddr != "" || filterKey != "" {
		targetViews = nil
		targetRaw = nil
		targetViolations = nil
		for i, pv := range patchViews {
			if (filterAddr != "" && pv.ResourceAddress == filterAddr) || (filterKey != "" && pv.Key == filterKey) {
				targetViews = append(targetViews, pv)
				if i < len(rawPatches) {
					targetRaw = append(targetRaw, rawPatches[i])
				}
			}
		}
		for _, v := range allViolations {
			if filterAddr != "" && v.ResourceAddress == filterAddr {
				targetViolations = append(targetViolations, v)
			}
		}
		if len(targetViolations) == 0 && len(targetViews) > 0 {
			for _, pv := range targetViews {
				for _, v := range allViolations {
					if v.ResourceAddress == pv.ResourceAddress {
						targetViolations = append(targetViolations, v)
					}
				}
			}
		}
	}

	writtenToDisk, err := s.applyPatchesInternal(ctx, reposAbs, targetViews, targetRaw, targetViolations, req.Write)
	if err != nil {
		s.writeError(w, err)
		return
	}

	s.mu.Lock()
	s.activePolicyRel = policyRel
	if filterAddr == "" && filterKey == "" {
		s.forcedState = StateEnforceReady
	} else {
		s.forcedState = ""
	}
	s.mu.Unlock()

	wsResp, err := s.buildWorkspaceState(ctx, policyRel, s.defaultCorpusDir())
	if err != nil {
		s.writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ApplyResponse{
		State:              wsResp.State,
		Applied:            true,
		WrittenToDisk:      writtenToDisk,
		AppliedCount:       len(targetViews),
		EvalMs:             wsResp.EvalDurationMs,
		Workers:            wsResp.Workers,
		Patches:            wsResp.Patches,
		Backtest:           wsResp.Backtest,
		SnapshotRows:       wsResp.SnapshotRows,
		Verification:       wsResp.Verification,
		TotalReposAnalyzed: wsResp.Backtest.TotalReposAnalyzed,
		BlockedPlansCount:  wsResp.Backtest.BlockedPlansCount,
		TotalResources:     wsResp.Backtest.TotalResources,
		TotalViolations:    wsResp.Backtest.TotalViolations,
	})
}

// applyPatchesInternal records applied patches in the server's sandbox state and optionally writes
// them to disk when Server.cfg.AllowWrite is true.
func (s *Server) applyPatchesInternal(
	ctx context.Context,
	reposAbs string,
	patchViews []PatchView,
	rawPatches []model.RemediationPatch,
	violations []model.PolicyViolation,
	requestWrite bool,
) (bool, error) {
	s.mu.Lock()
	for _, v := range violations {
		if v.Remediation != nil {
			specCopy := *v.Remediation
			s.remediatedResources[v.ResourceAddress] = &specCopy
		} else {
			s.remediatedResources[v.ResourceAddress] = &model.RemediationSpec{}
		}
	}
	for _, pv := range patchViews {
		if pv.Remediation != nil {
			specCopy := *pv.Remediation
			s.remediatedResources[pv.ResourceAddress] = &specCopy
		} else if _, ok := s.remediatedResources[pv.ResourceAddress]; !ok {
			s.remediatedResources[pv.ResourceAddress] = &model.RemediationSpec{}
		}
		if pv.FilePath != "" && pv.PatchedHCL != "" {
			s.patchedHCLByFile[pv.FilePath] = pv.PatchedHCL
		}
	}
	s.mu.Unlock()

	writtenToDisk := false
	if s.cfg.AllowWrite && len(rawPatches) > 0 && (requestWrite || s.cfg.AllowWrite) {
		if err := s.patcher.ApplyPatches(ctx, reposAbs, rawPatches); err != nil {
			return false, fmt.Errorf("applying patches to disk: %w", err)
		}
		writtenToDisk = true
	}

	return writtenToDisk, nil
}

// buildEmptyWorkspaceResponse returns a clean 0-loaded WorkspaceResponse when no files are loaded yet
// or when the user explicitly selects the empty workspace state.
func (s *Server) buildEmptyWorkspaceResponse(elapsedMs float64) *WorkspaceResponse {
	if elapsedMs < 0.1 {
		elapsedMs = 0.1
	}
	return &WorkspaceResponse{
		State:             StateEmpty,
		EmptyWorkspace:    true,
		CustomUploaded:    false,
		ActivePolicy:      "",
		ActivePolicyName:  "No policy loaded",
		AvailablePolicies: []string{},
		CorpusDir:         "",
		SchemaPath:        "",
		ReposDir:          "",
		Workers:           s.cfg.Workers,
		EvalDurationMs:    elapsedMs,
		Verification: &model.VerificationResult{
			PolicyPath:  "",
			PackageName: "terraform.guardrails",
			Valid:       true,
			Diagnostics: []model.SchemaDiagnostic{},
		},
		PolicyLines:     []PolicyLine{},
		RawPolicySource: "",
		PolicySource:    "",
		Schemas:         model.ProviderSchemaMap{},
		Backtest: &model.BlastRadiusReport{
			PolicyPath:          "",
			TotalReposAnalyzed:  0,
			ImpactedReposCount:  0,
			TotalPlansAnalyzed:  0,
			BlockedPlansCount:   0,
			TotalResources:      0,
			TotalViolations:     0,
			BreakdownByProvider: map[string]int{},
			RepoImpacts:         []model.RepoImpact{},
		},
		SnapshotRows: []SnapshotRow{},
		Patches:      []PatchView{},
		AllowWrite:   s.cfg.AllowWrite,
	}
}

// buildWorkspaceState computes the complete WorkspaceResponse for the active policy and corpus.
func (s *Server) buildWorkspaceState(ctx context.Context, policyRelOverride, corpusRelOverride string) (*WorkspaceResponse, error) {
	startTime := time.Now()

	s.mu.RLock()
	forcedInitial := s.forcedState
	s.mu.RUnlock()

	if forcedInitial == StateEmpty && strings.TrimSpace(policyRelOverride) == "" && strings.TrimSpace(corpusRelOverride) == "" {
		elapsedMs := float64(time.Since(startTime).Microseconds()) / 1000.0
		return s.buildEmptyWorkspaceResponse(elapsedMs), nil
	}

	policyRel := s.getActivePolicyRel()
	if strings.TrimSpace(policyRelOverride) != "" {
		policyRel = policyRelOverride
	}

	corpusRel := s.defaultCorpusDir()
	if strings.TrimSpace(corpusRelOverride) != "" {
		corpusRel = corpusRelOverride
	}
	_, corpusRelSlash, err := s.ResolveWorkspaceRel(corpusRel)
	if err != nil {
		return nil, err
	}

	schemaAbs, schemaRelSlash, err := s.ResolveWorkspaceRel(s.defaultSchemaPath())
	if err != nil {
		return nil, err
	}
	reposAbs, reposRelSlash, err := s.ResolveWorkspaceRel(s.defaultReposDir())
	if err != nil {
		return nil, err
	}
	corpusAbs, _, err := s.ResolveWorkspaceRel(corpusRelSlash)
	if err != nil {
		return nil, err
	}
	policyAbs, policyRelSlash, err := s.ResolveWorkspaceRel(policyRel)
	if err != nil {
		return nil, err
	}

	// If no explicit override was passed and the default policy or corpus directory does not exist on disk
	// (e.g. a freshly cloned or empty repository without testdata/), return the clean 0-loaded empty state.
	if strings.TrimSpace(policyRelOverride) == "" && strings.TrimSpace(corpusRelOverride) == "" && !s.isCustomUploaded() {
		_, policyStatErr := os.Stat(policyAbs)
		_, schemaStatErr := os.Stat(schemaAbs)
		_, corpusStatErr := os.Stat(corpusAbs)
		if errors.Is(policyStatErr, os.ErrNotExist) || errors.Is(schemaStatErr, os.ErrNotExist) || errors.Is(corpusStatErr, os.ErrNotExist) {
			elapsedMs := float64(time.Since(startTime).Microseconds()) / 1000.0
			return s.buildEmptyWorkspaceResponse(elapsedMs), nil
		}
	}

	schemas, err := s.parser.LoadProviderSchemas(ctx, schemaAbs)
	if err != nil {
		return nil, fmt.Errorf("loading provider schemas: %w", err)
	}

	var passFixtures, failFixtures []string
	if !s.isCustomUploaded() {
		passFixtures = s.cfg.PassFixtures
		failFixtures = s.cfg.FailFixtures
	}
	verRes, rawSource, policyLines, err := s.verifyPolicyOrContent(ctx, policyRelSlash, "", schemas, passFixtures, failFixtures)
	if err != nil {
		return nil, err
	}

	// Load unremediated snapshots; if an uploaded workspace only uploaded a policy without plans, allow 0 snapshots.
	rawSnapshots, err := s.loadCorpusSnapshots(ctx, corpusAbs, false)
	if err != nil {
		if s.isCustomUploaded() {
			rawSnapshots = []*model.PlanSnapshot{}
		} else {
			return nil, err
		}
	}

	var rawBacktest *model.BlastRadiusReport
	if len(rawSnapshots) == 0 {
		rawBacktest = &model.BlastRadiusReport{
			PolicyPath:          policyRelSlash,
			TotalReposAnalyzed:  0,
			ImpactedReposCount:  0,
			TotalPlansAnalyzed:  0,
			BlockedPlansCount:   0,
			TotalResources:      0,
			TotalViolations:     0,
			BreakdownByProvider: map[string]int{},
			RepoImpacts:         []model.RepoImpact{},
		}
	} else {
		rawBacktest, err = s.runner.RunBacktest(ctx, []string{policyAbs}, rawSnapshots)
		if err != nil {
			return nil, fmt.Errorf("running baseline backtest: %w", err)
		}
		rawBacktest.PolicyPath = policyRelSlash
	}

	patchViews, _, allViolations, err := s.generateCorpusPatches(ctx, reposAbs, rawBacktest)
	if err != nil {
		return nil, err
	}

	// If forcedState is StateEnforceReady, ensure all baseline violations are registered in remediatedResources.
	s.mu.Lock()
	if s.forcedState == StateEnforceReady {
		for _, v := range allViolations {
			if v.Remediation != nil {
				specCopy := *v.Remediation
				s.remediatedResources[v.ResourceAddress] = &specCopy
			} else {
				s.remediatedResources[v.ResourceAddress] = &model.RemediationSpec{}
			}
		}
	}
	applySandbox := len(s.remediatedResources) > 0 || s.forcedState == StateEnforceReady
	s.mu.Unlock()

	activeSnapshots := rawSnapshots
	activeBacktest := rawBacktest
	if applySandbox && verRes.Valid && len(rawSnapshots) > 0 {
		activeSnapshots, err = s.loadCorpusSnapshots(ctx, corpusAbs, true)
		if err != nil {
			return nil, err
		}
		activeBacktest, err = s.runner.RunBacktest(ctx, []string{policyAbs}, activeSnapshots)
		if err != nil {
			return nil, fmt.Errorf("running sandboxed backtest: %w", err)
		}
		activeBacktest.PolicyPath = policyRelSlash
	}

	s.mu.RLock()
	for i := range patchViews {
		if _, ok := s.remediatedResources[patchViews[i].ResourceAddress]; ok || s.forcedState == StateEnforceReady {
			patchViews[i].Applied = true
		}
	}
	forced := s.forcedState
	s.mu.RUnlock()

	snapshotRows := s.buildSnapshotRows(activeSnapshots, activeBacktest, patchViews)

	state := StateViolationsDetected
	if !verRes.Valid || forced == StateFailOpenCaught {
		state = StateFailOpenCaught
	} else if activeBacktest.BlockedPlansCount == 0 || forced == StateEnforceReady {
		state = StateEnforceReady
	}

	elapsedMs := float64(time.Since(startTime).Microseconds()) / 1000.0
	if elapsedMs < 0.1 {
		elapsedMs = 0.1
	}

	return &WorkspaceResponse{
		State:             state,
		EmptyWorkspace:    false,
		CustomUploaded:    s.isCustomUploaded(),
		ActivePolicy:      policyRelSlash,
		ActivePolicyName:  filepath.Base(policyRelSlash),
		AvailablePolicies: s.discoverAvailablePolicies(filepath.Dir(policyAbs)),
		CorpusDir:         corpusRelSlash,
		SchemaPath:        schemaRelSlash,
		ReposDir:          reposRelSlash,
		Workers:           s.cfg.Workers,
		EvalDurationMs:    elapsedMs,
		Verification:      verRes,
		PolicyLines:       policyLines,
		RawPolicySource:   rawSource,
		PolicySource:      rawSource,
		Schemas:           schemas,
		Backtest:          activeBacktest,
		SnapshotRows:      snapshotRows,
		Patches:           patchViews,
		AllowWrite:        s.cfg.AllowWrite,
	}, nil
}

// evaluateLivePolicyWorkspace runs AST verification and corpus backtesting against in-memory Rego content.
func (s *Server) evaluateLivePolicyWorkspace(ctx context.Context, policyRel, policyContent, corpusRel string) (*WorkspaceResponse, error) {
	startTime := time.Now()

	schemaAbs, schemaRelSlash, err := s.ResolveWorkspaceRel(s.defaultSchemaPath())
	if err != nil {
		return nil, err
	}
	corpusAbs, corpusRelSlash, err := s.ResolveWorkspaceRel(corpusRel)
	if err != nil {
		return nil, err
	}
	reposAbs, reposRelSlash, err := s.ResolveWorkspaceRel(s.defaultReposDir())
	if err != nil {
		return nil, err
	}

	schemas, err := s.parser.LoadProviderSchemas(ctx, schemaAbs)
	if err != nil {
		return nil, err
	}

	verRes, rawSource, policyLines, err := s.verifyPolicyOrContent(ctx, policyRel, policyContent, schemas, nil, nil)
	if err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "tfsim-live-*.rego")
	if err != nil {
		return nil, fmt.Errorf("creating temporary policy file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(policyContent); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("writing temporary policy file: %w", err)
	}
	_ = tmpFile.Close()

	snapshots, err := s.loadCorpusSnapshots(ctx, corpusAbs, s.isEnforceReady())
	if err != nil {
		if s.isCustomUploaded() {
			snapshots = []*model.PlanSnapshot{}
		} else {
			return nil, err
		}
	}

	var backtestRep *model.BlastRadiusReport
	if verRes.Valid && len(snapshots) > 0 {
		backtestRep, err = s.runner.RunBacktest(ctx, []string{tmpPath}, snapshots)
		if err != nil {
			// If policy fails evaluation, surface empty report with fail-open state.
			backtestRep = &model.BlastRadiusReport{
				PolicyPath:          policyRel,
				TotalReposAnalyzed:  len(snapshots),
				TotalPlansAnalyzed:  len(snapshots),
				BreakdownByProvider: map[string]int{},
				RepoImpacts:         []model.RepoImpact{},
			}
		} else {
			backtestRep.PolicyPath = policyRel
		}
	} else {
		backtestRep = &model.BlastRadiusReport{
			PolicyPath:          policyRel,
			TotalReposAnalyzed:  len(snapshots),
			TotalPlansAnalyzed:  len(snapshots),
			BreakdownByProvider: map[string]int{},
			RepoImpacts:         []model.RepoImpact{},
		}
	}

	patchViews, _, _, _ := s.generateCorpusPatches(ctx, reposAbs, backtestRep)
	snapshotRows := s.buildSnapshotRows(snapshots, backtestRep, patchViews)

	state := StateViolationsDetected
	if !verRes.Valid {
		state = StateFailOpenCaught
	} else if backtestRep.BlockedPlansCount == 0 {
		state = StateEnforceReady
	}

	elapsedMs := float64(time.Since(startTime).Microseconds()) / 1000.0
	if elapsedMs < 0.1 {
		elapsedMs = 0.1
	}

	return &WorkspaceResponse{
		State:             state,
		EmptyWorkspace:    false,
		CustomUploaded:    s.isCustomUploaded(),
		ActivePolicy:      policyRel,
		ActivePolicyName:  filepath.Base(policyRel),
		AvailablePolicies: s.discoverAvailablePolicies(filepath.Join(s.activeWorkspaceAbs(), filepath.FromSlash(filepath.Dir(policyRel)))),
		CorpusDir:         corpusRelSlash,
		SchemaPath:        schemaRelSlash,
		ReposDir:          reposRelSlash,
		Workers:           s.cfg.Workers,
		EvalDurationMs:    elapsedMs,
		Verification:      verRes,
		PolicyLines:       policyLines,
		RawPolicySource:   rawSource,
		PolicySource:      rawSource,
		Schemas:           schemas,
		Backtest:          backtestRep,
		SnapshotRows:      snapshotRows,
		Patches:           patchViews,
		AllowWrite:        s.cfg.AllowWrite,
	}, nil
}

// verifyPolicyOrContent verifies either a workspace policy file or live in-memory policy_content
// against the loaded provider schemas.
func (s *Server) verifyPolicyOrContent(
	ctx context.Context,
	policyRel string,
	policyContent string,
	schemas model.ProviderSchemaMap,
	passFixtures []string,
	failFixtures []string,
) (*model.VerificationResult, string, []PolicyLine, error) {
	var targetPath string
	var rawSource string

	if strings.TrimSpace(policyContent) != "" {
		rawSource = strings.ReplaceAll(policyContent, "\r\n", "\n")
		tmpFile, err := os.CreateTemp("", "tfsim-verify-*.rego")
		if err != nil {
			return nil, "", nil, fmt.Errorf("creating temporary policy file: %w", err)
		}
		targetPath = tmpFile.Name()
		defer os.Remove(targetPath)

		if _, err := tmpFile.WriteString(rawSource); err != nil {
			_ = tmpFile.Close()
			return nil, "", nil, fmt.Errorf("writing temporary policy file: %w", err)
		}
		_ = tmpFile.Close()
	} else {
		policyAbs, _, err := s.ResolveWorkspaceRel(policyRel)
		if err != nil {
			return nil, "", nil, err
		}
		rawBytes, err := os.ReadFile(policyAbs)
		if err != nil {
			return nil, "", nil, err
		}
		rawSource = strings.ReplaceAll(string(rawBytes), "\r\n", "\n")
		targetPath = policyAbs
	}

	var resolvedPass []string
	for _, pf := range passFixtures {
		if strings.TrimSpace(pf) == "" {
			continue
		}
		absPF, _, err := s.ResolveWorkspaceRel(pf)
		if err != nil {
			return nil, "", nil, err
		}
		resolvedPass = append(resolvedPass, absPF)
	}
	var resolvedFail []string
	for _, ff := range failFixtures {
		if strings.TrimSpace(ff) == "" {
			continue
		}
		absFF, _, err := s.ResolveWorkspaceRel(ff)
		if err != nil {
			return nil, "", nil, err
		}
		resolvedFail = append(resolvedFail, absFF)
	}

	verRes, err := s.verifier.VerifyPoliciesWithFixtures(ctx, []string{targetPath}, schemas, resolvedPass, resolvedFail)
	if err != nil {
		return nil, "", nil, err
	}

	verRes.PolicyPath = policyRel
	for i := range verRes.Diagnostics {
		verRes.Diagnostics[i].PolicyFile = policyRel
	}
	if verRes.Diagnostics == nil {
		verRes.Diagnostics = []model.SchemaDiagnostic{}
	}

	lines := buildAnnotatedPolicyLines(rawSource, verRes.Diagnostics)
	return verRes, rawSource, lines, nil
}

// buildAnnotatedPolicyLines splits raw Rego source into 1-indexed lines annotated with any matching SchemaDiagnostic.
func buildAnnotatedPolicyLines(rawSource string, diagnostics []model.SchemaDiagnostic) []PolicyLine {
	diagByLine := make(map[int]model.SchemaDiagnostic, len(diagnostics))
	for _, d := range diagnostics {
		if d.Line > 0 {
			if _, exists := diagByLine[d.Line]; !exists {
				diagByLine[d.Line] = d
			}
		}
	}

	trimmed := strings.TrimRight(rawSource, "\n")
	rawLines := strings.Split(trimmed, "\n")
	if trimmed == "" {
		rawLines = []string{}
	}

	out := make([]PolicyLine, 0, len(rawLines))
	for idx, text := range rawLines {
		lineNum := idx + 1
		pl := PolicyLine{
			Line: lineNum,
			Text: text,
		}
		if d, ok := diagByLine[lineNum]; ok {
			dCopy := d
			pl.HasError = true
			pl.Diagnostic = &dCopy
		}
		out = append(out, pl)
	}
	return out
}

// loadCorpusSnapshots loads historical plan snapshots from corpusAbs, excluding fixture-only
// pass_compliant.json / compliant_plan.json when multiple plans are present, and optionally
// applying sandbox in-memory attribute remediations.
func (s *Server) loadCorpusSnapshots(ctx context.Context, corpusAbs string, applySandboxRemediation bool) ([]*model.PlanSnapshot, error) {
	allSnapshots, err := s.runner.LoadSnapshotsFromDir(ctx, corpusAbs)
	if err != nil {
		return nil, err
	}

	filtered := make([]*model.PlanSnapshot, 0, len(allSnapshots))
	if len(allSnapshots) > 1 {
		for _, snap := range allSnapshots {
			base := strings.ToLower(filepath.Base(snap.SourcePath))
			repoLower := strings.ToLower(snap.RepoName)
			if base == "pass_compliant.json" || base == "compliant_plan.json" || repoLower == "pass_compliant" || repoLower == "compliant_plan" {
				continue
			}
			filtered = append(filtered, snap)
		}
	}
	if len(filtered) == 0 {
		filtered = allSnapshots
	}

	if !applySandboxRemediation {
		return filtered, nil
	}

	s.mu.RLock()
	remediatedMap := make(map[string]*model.RemediationSpec, len(s.remediatedResources))
	for k, v := range s.remediatedResources {
		remediatedMap[k] = v
	}
	forceAll := s.forcedState == StateEnforceReady
	s.mu.RUnlock()

	cloned := make([]*model.PlanSnapshot, 0, len(filtered))
	for _, snap := range filtered {
		snapCopy := *snap
		rcs := make([]model.ResourceChange, len(snap.ResourceChanges))
		for i, rc := range snap.ResourceChanges {
			rcCopy := rc
			afterCopy := cloneMap(rc.After)
			if afterCopy == nil {
				afterCopy = make(map[string]any)
			}

			spec, isRemediated := remediatedMap[rc.Address]
			if isRemediated || forceAll {
				applySandboxAttributeRemediation(rc.Type, afterCopy, spec)
			}
			rcCopy.After = afterCopy
			rcs[i] = rcCopy
		}
		snapCopy.ResourceChanges = rcs
		cloned = append(cloned, &snapCopy)
	}

	return cloned, nil
}

// applySandboxAttributeRemediation mutates an in-memory resource's After map according to
// RemediationSpec or standard storage encryption guardrails so sandboxed re-evaluation passes.
func applySandboxAttributeRemediation(resourceType string, after map[string]any, spec *model.RemediationSpec) {
	if spec != nil && len(spec.AttributePath) > 0 && spec.SuggestedVal != nil {
		if len(spec.AttributePath) == 1 {
			after[spec.AttributePath[0]] = spec.SuggestedVal
			return
		}
		// Build nested []any{map[string]any{...}} structure matching Terraform plan JSON block representation.
		curr := map[string]any{
			spec.AttributePath[len(spec.AttributePath)-1]: spec.SuggestedVal,
		}
		for i := len(spec.AttributePath) - 2; i >= 1; i-- {
			curr = map[string]any{
				spec.AttributePath[i]: []any{curr},
			}
		}
		after[spec.AttributePath[0]] = []any{curr}
		return
	}

	// Fallback for forceAll when spec is empty.
	switch resourceType {
	case "aws_s3_bucket":
		after["server_side_encryption_configuration"] = []any{
			map[string]any{
				"rule": []any{
					map[string]any{
						"apply_server_side_encryption_by_default": []any{
							map[string]any{
								"sse_algorithm": "aws:kms",
							},
						},
					},
				},
			},
		}
	case "azurerm_storage_account":
		after["https_traffic_only_enabled"] = true
	case "google_storage_bucket":
		after["uniform_bucket_level_access"] = true
	}
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	raw, err := json.Marshal(src)
	if err != nil {
		dst := make(map[string]any, len(src))
		for k, v := range src {
			dst[k] = v
		}
		return dst
	}
	var dst map[string]any
	if err := json.Unmarshal(raw, &dst); err != nil {
		return src
	}
	return dst
}

// generateCorpusPatches collects all violations from the backtest report and invokes remediate.Patcher
// to produce surgical hclwrite diffs without mutating disk.
func (s *Server) generateCorpusPatches(
	ctx context.Context,
	reposAbs string,
	backtestRep *model.BlastRadiusReport,
) ([]PatchView, []model.RemediationPatch, []model.PolicyViolation, error) {
	if backtestRep == nil {
		return []PatchView{}, []model.RemediationPatch{}, []model.PolicyViolation{}, nil
	}

	var allViolations []model.PolicyViolation
	violationByAddr := make(map[string]model.PolicyViolation)
	repoByAddr := make(map[string]string)

	for _, ri := range backtestRep.RepoImpacts {
		for _, v := range ri.Violations {
			allViolations = append(allViolations, v)
			violationByAddr[v.ResourceAddress] = v
			repoByAddr[v.ResourceAddress] = ri.RepoName
		}
	}

	if len(allViolations) == 0 {
		return []PatchView{}, []model.RemediationPatch{}, []model.PolicyViolation{}, nil
	}

	if _, err := os.Stat(reposAbs); err != nil {
		return []PatchView{}, []model.RemediationPatch{}, allViolations, nil
	}

	rawPatches, err := s.patcher.GeneratePatches(ctx, reposAbs, allViolations)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating HCL remediation patches: %w", err)
	}

	_, reposRelSlash, _ := s.ResolveWorkspaceRel(reposAbs)

	views := make([]PatchView, 0, len(rawPatches))
	for _, rp := range rawPatches {
		v := violationByAddr[rp.ResourceAddress]
		repoName := repoByAddr[rp.ResourceAddress]
		key := derivePatchKey(rp.FilePath, repoName)
		fullRelPath := filepath.ToSlash(filepath.Join(reposRelSlash, rp.FilePath))

		views = append(views, PatchView{
			Key:             key,
			RepoName:        repoName,
			FilePath:        fullRelPath,
			ResourceAddress: rp.ResourceAddress,
			RuleID:          v.RuleID,
			Severity:        v.Severity,
			Remediation:     v.Remediation,
			OriginalHCL:     rp.OriginalHCL,
			PatchedHCL:      rp.PatchedHCL,
			UnifiedDiff:     rp.UnifiedDiff,
			Applied:         false,
		})
	}

	return views, rawPatches, allViolations, nil
}

func derivePatchKey(filePath, repoName string) string {
	slash := filepath.ToSlash(filePath)
	parts := strings.Split(slash, "/")
	if len(parts) > 1 && parts[0] != "" && parts[0] != "." {
		return parts[0]
	}
	trimmed := strings.TrimPrefix(repoName, "repo_")
	return strings.ReplaceAll(trimmed, "_", "-")
}

// buildSnapshotRows joins parsed plan snapshots with backtest evaluation results for Stage A table rendering.
func (s *Server) buildSnapshotRows(
	snapshots []*model.PlanSnapshot,
	backtestRep *model.BlastRadiusReport,
	patches []PatchView,
) []SnapshotRow {
	impactByRepo := make(map[string]model.RepoImpact)
	if backtestRep != nil {
		for _, ri := range backtestRep.RepoImpacts {
			impactByRepo[ri.RepoName] = ri
		}
	}

	patchKeyByRepo := make(map[string]string)
	for _, p := range patches {
		if p.RepoName != "" && p.Key != "" {
			patchKeyByRepo[p.RepoName] = p.Key
		}
	}

	rows := make([]SnapshotRow, 0, len(snapshots))
	for _, snap := range snapshots {
		_, relSource, err := s.ResolveWorkspaceRel(snap.SourcePath)
		if err != nil {
			relSource = filepath.ToSlash(snap.SourcePath)
		}

		provShort := "unknown"
		provFull := ""
		if len(snap.ResourceChanges) > 0 {
			provFull = snap.ResourceChanges[0].ProviderName
			provShort = backtest.ExtractProviderName(provFull, snap.ResourceChanges[0].Type)
		}

		ri := impactByRepo[snap.RepoName]
		violations := ri.Violations
		if violations == nil {
			violations = []model.PolicyViolation{}
		}

		totalRes := len(snap.ResourceChanges)
		failedRes := len(violations)
		passedRes := totalRes - failedRes
		if passedRes < 0 {
			passedRes = 0
		}

		patchKey := patchKeyByRepo[snap.RepoName]
		if patchKey == "" {
			patchKey = derivePatchKey("", snap.RepoName)
		}

		rows = append(rows, SnapshotRow{
			RepoName:        snap.RepoName,
			SourcePath:      relSource,
			Provider:        provShort,
			ProviderFull:    provFull,
			TotalResources:  totalRes,
			PassedResources: passedRes,
			FailedResources: failedRes,
			Blocked:         ri.BlockedPlansCount > 0,
			Violations:      violations,
			PatchKey:        patchKey,
		})
	}

	return rows
}

func (s *Server) discoverAvailablePolicies(policyDir string) []string {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return []string{filepath.Base(s.cfg.PolicyPath)}
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".rego") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func (s *Server) getActivePolicyRel() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activePolicyRel != "" {
		return s.activePolicyRel
	}
	if s.customPolicyRel != "" {
		return s.customPolicyRel
	}
	return filepath.ToSlash(s.cfg.PolicyPath)
}

func (s *Server) isEnforceReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forcedState == StateEnforceReady || len(s.remediatedResources) > 0
}

// decodeJSONBody wraps r.Body with http.MaxBytesReader (2 MiB limit) and decodes JSON into dst.
// An empty request body is permitted and leaves dst at its zero value.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	limited := http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	defer limited.Close()

	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON request body: %w", err)
	}
	return nil
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesErr) || strings.Contains(err.Error(), "request body too large"):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": "request body exceeds maximum allowed size (2 MiB)",
		})
	case errors.Is(err, ErrPathTraversal):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
			"code":  "path_outside_workspace",
		})
	case errors.Is(err, os.ErrNotExist):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

const builtinFallbackProviderSchema = `{
  "format_version": "1.0",
  "provider_schemas": {
    "registry.terraform.io/hashicorp/aws": {
      "resource_schemas": {
        "aws_s3_bucket": {
          "version": 0,
          "block": {
            "attributes": {
              "id": { "type": "string", "computed": true },
              "bucket": { "type": "string", "optional": true }
            },
            "block_types": {
              "server_side_encryption_configuration": {
                "nesting_mode": "list",
                "block": {
                  "block_types": {
                    "rule": {
                      "nesting_mode": "list",
                      "block": {
                        "block_types": {
                          "apply_server_side_encryption_by_default": {
                            "nesting_mode": "list",
                            "max_items": 1,
                            "block": {
                              "attributes": {
                                "sse_algorithm": { "type": "string", "required": true },
                                "kms_master_key_id": { "type": "string", "optional": true }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "registry.terraform.io/hashicorp/azurerm": {
      "resource_schemas": {
        "azurerm_storage_account": {
          "version": 4,
          "block": {
            "attributes": {
              "id": { "type": "string", "computed": true },
              "name": { "type": "string", "required": true },
              "https_traffic_only_enabled": { "type": "bool", "optional": true },
              "min_tls_version": { "type": "string", "optional": true }
            }
          }
        }
      }
    },
    "registry.terraform.io/hashicorp/google": {
      "resource_schemas": {
        "google_storage_bucket": {
          "version": 0,
          "block": {
            "attributes": {
              "id": { "type": "string", "computed": true },
              "name": { "type": "string", "required": true },
              "location": { "type": "string", "required": true },
              "uniform_bucket_level_access": { "type": "bool", "optional": true },
              "public_access_prevention": { "type": "string", "optional": true }
            }
          }
        }
      }
    }
  }
}
`

const builtinFallbackRegoPolicy = `package terraform.guardrails

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not has_valid_s3_encryption(rc)
	violation := {
		"rule_id": "AWS-S3-ENCRYPT-001",
		"severity": "HIGH",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"message": sprintf("S3 bucket '%s' must configure server-side encryption (AES256 or aws:kms)", [rc.address]),
		"remediation": {
			"attribute_path": ["server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "sse_algorithm"],
			"suggested_value": "aws:kms",
			"description": "Configure server_side_encryption_configuration with sse_algorithm = \"aws:kms\"",
		},
	}
}

has_valid_s3_encryption(rc) if {
	some sse in rc.change.after.server_side_encryption_configuration
	some rule in sse.rule
	some by_default in rule.apply_server_side_encryption_by_default
	by_default.sse_algorithm in ["AES256", "aws:kms"]
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	not rc.change.after.https_traffic_only_enabled == true
	violation := {
		"rule_id": "AZURE-STORAGE-HTTPS-001",
		"severity": "HIGH",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"message": sprintf("Azure Storage Account '%s' must enforce HTTPS traffic only (https_traffic_only_enabled = true)", [rc.address]),
		"remediation": {
			"attribute_path": ["https_traffic_only_enabled"],
			"suggested_value": true,
			"description": "Set https_traffic_only_enabled = true on the azurerm_storage_account resource",
		},
	}
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	not rc.change.after.uniform_bucket_level_access == true
	violation := {
		"rule_id": "GCP-STORAGE-UBLA-001",
		"severity": "MEDIUM",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"message": sprintf("GCS bucket '%s' must enable uniform_bucket_level_access = true", [rc.address]),
		"remediation": {
			"attribute_path": ["uniform_bucket_level_access"],
			"suggested_value": true,
			"description": "Set uniform_bucket_level_access = true on the google_storage_bucket resource",
		},
	}
}
`
