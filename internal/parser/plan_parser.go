package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/justr00t/tf-sim/internal/model"
	tfjson "github.com/hashicorp/terraform-json"
)

// Ensure Parser strictly implements model.PlanParser
var _ model.PlanParser = (*Parser)(nil)

// Parser handles streaming parsing of Terraform JSON plans and provider schemas.
type Parser struct {
	includeNoOp bool
	includeRead bool
}

// Option configures Parser behavior.
type Option func(*Parser)

// WithIncludeNoOp configures the parser to retain no-op resource changes.
func WithIncludeNoOp(include bool) Option {
	return func(p *Parser) {
		p.includeNoOp = include
	}
}

// WithIncludeRead configures the parser to retain read (data source) resource changes.
func WithIncludeRead(include bool) Option {
	return func(p *Parser) {
		p.includeRead = include
	}
}

// NewParser creates a new Parser with the provided options.
func NewParser(opts ...Option) *Parser {
	p := &Parser{
		includeNoOp: false,
		includeRead: false,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ParsePlanFile opens the specified plan file and parses it into a PlanSnapshot.
func (p *Parser) ParsePlanFile(ctx context.Context, path string, repoName string) (*model.PlanSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat plan file %s: %w", path, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open plan file %s: %w", path, err)
	}
	defer f.Close()

	return p.ParsePlanReader(ctx, f, repoName, path)
}

// ParsePlanReader streams and parses a Terraform JSON plan from an io.Reader.
func (p *Parser) ParsePlanReader(ctx context.Context, r io.Reader, repoName, sourcePath string) (*model.PlanSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(r)

	// The root of a terraform plan JSON is an object: '{'
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read initial plan token: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("expected object delimiter '{', got %v", tok)
	}

	var tfVer string
	resourceChanges := make([]model.ResourceChange, 0)

	for dec.More() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read object key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %v", keyTok)
		}

		switch key {
		case "terraform_version":
			if err := dec.Decode(&tfVer); err != nil {
				return nil, fmt.Errorf("decode terraform_version: %w", err)
			}
		case "resource_changes":
			arrTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("read resource_changes array token: %w", err)
			}
			arrDelim, ok := arrTok.(json.Delim)
			if !ok || arrDelim != '[' {
				return nil, fmt.Errorf("expected array delimiter '[', got %v", arrTok)
			}

			for dec.More() {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				default:
				}

				var rc tfjson.ResourceChange
				if err := dec.Decode(&rc); err != nil {
					return nil, fmt.Errorf("decode resource_change: %w", err)
				}

				if rc.Change == nil {
					continue
				}

				if len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == tfjson.ActionNoop && !p.includeNoOp {
					continue
				}
				if len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == tfjson.ActionRead && !p.includeRead {
					continue
				}

				actions := make([]string, len(rc.Change.Actions))
				for i, a := range rc.Change.Actions {
					actions[i] = string(a)
				}

				change := model.ResourceChange{
					Address:       rc.Address,
					ModuleAddress: rc.ModuleAddress,
					Type:          rc.Type,
					Name:          rc.Name,
					ProviderName:  rc.ProviderName,
					Actions:       actions,
					Before:        toMapStringAny(rc.Change.Before),
					After:         toMapStringAny(rc.Change.After),
				}
				resourceChanges = append(resourceChanges, change)
			}

			closingArrTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("read closing resource_changes delimiter: %w", err)
			}
			if d, ok := closingArrTok.(json.Delim); !ok || d != ']' {
				return nil, fmt.Errorf("expected closing array delimiter ']', got %v", closingArrTok)
			}

		default:
			if err := skipValue(dec); err != nil {
				return nil, fmt.Errorf("skip value for key %q: %w", key, err)
			}
		}
	}

	closingObjTok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read closing object delimiter: %w", err)
	}
	if d, ok := closingObjTok.(json.Delim); !ok || d != '}' {
		return nil, fmt.Errorf("expected closing object delimiter '}', got %v", closingObjTok)
	}

	var snapshotID string
	base := ""
	if sourcePath != "" {
		base = strings.TrimSuffix(filepath.Base(sourcePath), filepath.Ext(sourcePath))
	}
	if repoName != "" && base != "" {
		snapshotID = fmt.Sprintf("%s-%s", repoName, base)
	} else if repoName != "" {
		snapshotID = repoName
	} else if base != "" {
		snapshotID = base
	} else {
		snapshotID = "snapshot"
	}

	return &model.PlanSnapshot{
		SnapshotID:      snapshotID,
		RepoName:        repoName,
		TerraformVer:    tfVer,
		SourcePath:      sourcePath,
		ResourceChanges: resourceChanges,
	}, nil
}

func toMapStringAny(v any) map[string]any {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// skipValue discards the next complete JSON token or object/array tree from the stream
// using O(1) memory without allocating memory buffers for large subtrees.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	_, isDelim := tok.(json.Delim)
	if !isDelim {
		// Primitive token (string, number, bool, null) consumed.
		return nil
	}
	// Opening delimiter '{' or '[': track balance until depth returns to 0.
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else if d == '}' || d == ']' {
				depth--
			}
		}
	}
	return nil
}
