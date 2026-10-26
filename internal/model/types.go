package model

import "context"

// ResourceChange represents a single cloud-agnostic resource mutation extracted from a Terraform plan.
type ResourceChange struct {
	Address       string         `json:"address"`        // e.g., "module.db.aws_s3_bucket.logs"
	ModuleAddress string         `json:"module_address"` // e.g., "module.db"
	Type          string         `json:"type"`           // e.g., "aws_s3_bucket", "azurerm_storage_account", "google_storage_bucket"
	Name          string         `json:"name"`           // e.g., "logs"
	ProviderName  string         `json:"provider_name"`  // e.g., "registry.terraform.io/hashicorp/aws"
	Actions       []string       `json:"actions"`        // e.g., ["create"], ["update"], ["delete"]
	Before        map[string]any `json:"before"`         // Resolved attributes prior to change
	After         map[string]any `json:"after"`          // Resolved attributes after change
}

// PlanSnapshot represents metadata + extracted resource changes for a single Terraform plan execution.
type PlanSnapshot struct {
	SnapshotID      string           `json:"snapshot_id"`
	RepoName        string           `json:"repo_name"`
	CommitSHA       string           `json:"commit_sha,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"`
	TerraformVer    string           `json:"terraform_version,omitempty"`
	SourcePath      string           `json:"source_path"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

// ResourceSchema represents the valid attributes and nested blocks for a single Terraform resource type.
type ResourceSchema struct {
	ResourceType string                    `json:"resource_type"`
	Attributes   map[string]AttributeDef   `json:"attributes"`
	NestedBlocks map[string]ResourceSchema `json:"nested_blocks,omitempty"`
}

// AttributeDef describes an individual attribute within a resource or nested block.
type AttributeDef struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "string", "bool", "number", "list", "map", "object"
	Optional bool   `json:"optional"`
	Required bool   `json:"required"`
	Computed bool   `json:"computed"`
}

// ProviderSchemaMap maps a Terraform resource type (e.g. "aws_s3_bucket") to its schema definition.
type ProviderSchemaMap map[string]ResourceSchema

// SchemaDiagnostic represents a static analysis finding in a Rego policy.
type SchemaDiagnostic struct {
	PolicyFile   string `json:"policy_file"`
	Line         int    `json:"line"`
	ResourceType string `json:"resource_type,omitempty"`
	InvalidPath  string `json:"invalid_path,omitempty"`
	Message      string `json:"message"`
	Severity     string `json:"severity"` // "ERROR" | "WARNING"
}

// VerificationResult is returned by ASTVerifier.VerifyPolicy.
type VerificationResult struct {
	PolicyPath  string             `json:"policy_path"`
	PackageName string             `json:"package_name"`
	Valid       bool               `json:"valid"`
	Diagnostics []SchemaDiagnostic `json:"diagnostics"`
}

// RemediationSpec describes a deterministic HCL attribute fix emitted by a Rego deny rule.
type RemediationSpec struct {
	AttributePath []string `json:"attribute_path"` // e.g., ["server_side_encryption_configuration", "rule", "bucket_key_enabled"]
	SuggestedVal  any      `json:"suggested_value"` // string, bool, number
	Description   string   `json:"description"`
}

// PolicyViolation represents a single non-compliant resource flagged during policy evaluation.
type PolicyViolation struct {
	RuleID          string           `json:"rule_id"`
	Severity        string           `json:"severity"`         // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Message         string           `json:"message"`
	ResourceAddress string           `json:"resource_address"` // e.g., "azurerm_storage_account.main"
	ResourceType    string           `json:"resource_type"`    // e.g., "azurerm_storage_account"
	ResourceName    string           `json:"resource_name"`    // e.g., "main"
	Remediation     *RemediationSpec `json:"remediation,omitempty"`
}

// EvalResult summarizes policy evaluation against a single PlanSnapshot.
type EvalResult struct {
	SnapshotID     string            `json:"snapshot_id"`
	RepoName       string            `json:"repo_name"`
	TotalResources int               `json:"total_resources"`
	Passed         bool              `json:"passed"`
	Violations     []PolicyViolation `json:"violations"`
}

// RepoImpact summarizes how a proposed policy affects a specific repository's historical plans.
type RepoImpact struct {
	RepoName          string            `json:"repo_name"`
	TotalPlansTested  int               `json:"total_plans_tested"`
	BlockedPlansCount int               `json:"blocked_plans_count"`
	Violations        []PolicyViolation `json:"violations"`
}

// BlastRadiusReport aggregates the cross-repo impact of flipping a policy to "deny" mode.
type BlastRadiusReport struct {
	PolicyPath          string         `json:"policy_path"`
	TotalReposAnalyzed  int            `json:"total_repos_analyzed"`
	ImpactedReposCount  int            `json:"impacted_repos_count"`
	TotalPlansAnalyzed  int            `json:"total_plans_analyzed"`
	BlockedPlansCount   int            `json:"blocked_plans_count"`
	TotalResources      int            `json:"total_resources"`
	TotalViolations     int            `json:"total_violations"`
	BreakdownByProvider map[string]int `json:"breakdown_by_provider"`
	RepoImpacts         []RepoImpact   `json:"repo_impacts"`
}

// RemediationPatch contains the surgical HCL mutation and unified diff for a violated resource.
type RemediationPatch struct {
	FilePath        string `json:"file_path"`
	ResourceAddress string `json:"resource_address"`
	OriginalHCL     string `json:"original_hcl"`
	PatchedHCL      string `json:"patched_hcl"`
	UnifiedDiff     string `json:"unified_diff"`
}

// PlanParser defines the contract for plan and provider schema parsing.
type PlanParser interface {
	ParsePlanFile(ctx context.Context, path string, repoName string) (*PlanSnapshot, error)
	LoadProviderSchemas(ctx context.Context, schemaPath string) (ProviderSchemaMap, error)
}

// ASTVerifier defines the contract for static Rego AST schema verification.
type ASTVerifier interface {
	VerifyPolicy(ctx context.Context, policyPath string, schemas ProviderSchemaMap) (*VerificationResult, error)
}

// PolicyEvaluator defines the contract for running Rego policies against a PlanSnapshot.
type PolicyEvaluator interface {
	EvaluatePlan(ctx context.Context, policyPaths []string, snapshot *PlanSnapshot) (*EvalResult, error)
}

// BacktestRunner defines the contract for cross-repo blast-radius evaluation.
type BacktestRunner interface {
	RunBacktest(ctx context.Context, policyPaths []string, snapshots []*PlanSnapshot) (*BlastRadiusReport, error)
}

// RemediationGenerator defines the contract for surgical HCL AST patching.
type RemediationGenerator interface {
	GeneratePatches(ctx context.Context, tfDir string, violations []PolicyViolation) ([]RemediationPatch, error)
}
