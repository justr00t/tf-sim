package scrubber

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/justr00t/tf-sim/internal/model"
)

// Ensure Scrubber strictly implements model.PlanScrubber.
var _ model.PlanScrubber = (*Scrubber)(nil)

const maxSkipDepth = 10000

// Scrubber stream-sanitizes Terraform/OpenTofu JSON plans in bounded memory.
type Scrubber struct {
	customRedactKeys map[string]struct{}
	indent           string
}

// Option configures Scrubber behavior.
type Option func(*Scrubber)

// WithRedactKeys configures additional attribute or map key names to redact with [REDACTED].
func WithRedactKeys(keys ...string) Option {
	return func(s *Scrubber) {
		for _, k := range keys {
			if norm := normalizeKey(k); norm != "" {
				s.customRedactKeys[norm] = struct{}{}
			}
		}
	}
}

// WithIndent configures JSON indentation (for example, "  " for pretty-printed output).
func WithIndent(indent string) Option {
	return func(s *Scrubber) {
		s.indent = indent
	}
}

// NewScrubber creates a new Scrubber configured with the provided options.
func NewScrubber(opts ...Option) *Scrubber {
	s := &Scrubber{
		customRedactKeys: make(map[string]struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

type rawResourceChange struct {
	Address         string     `json:"address"`
	PreviousAddress string     `json:"previous_address,omitempty"`
	ModuleAddress   string     `json:"module_address,omitempty"`
	Mode            string     `json:"mode,omitempty"`
	Type            string     `json:"type"`
	Name            string     `json:"name"`
	Index           any        `json:"index,omitempty"`
	ProviderName    string     `json:"provider_name,omitempty"`
	DeposedKey      string     `json:"deposed,omitempty"`
	ActionReason    string     `json:"action_reason,omitempty"`
	Change          *rawChange `json:"change,omitempty"`
}

type rawChange struct {
	Actions         []string `json:"actions"`
	Before          any      `json:"before"`
	After           any      `json:"after"`
	BeforeSensitive any      `json:"before_sensitive"`
	AfterSensitive  any      `json:"after_sensitive"`
}

type scrubbedResourceChange struct {
	Address         string          `json:"address"`
	PreviousAddress string          `json:"previous_address,omitempty"`
	ModuleAddress   string          `json:"module_address,omitempty"`
	Mode            string          `json:"mode,omitempty"`
	Type            string          `json:"type"`
	Name            string          `json:"name"`
	Index           any             `json:"index,omitempty"`
	ProviderName    string          `json:"provider_name,omitempty"`
	DeposedKey      string          `json:"deposed,omitempty"`
	ActionReason    string          `json:"action_reason,omitempty"`
	Change          *scrubbedChange `json:"change,omitempty"`
}

type scrubbedChange struct {
	Actions []string `json:"actions,omitempty"`
	Before  any      `json:"before"`
	After   any      `json:"after"`
}

// ScrubStream reads a raw Terraform/OpenTofu plan JSON stream from r and writes the
// sanitized, allowlisted plan JSON stream to w.
func (s *Scrubber) ScrubStream(ctx context.Context, r io.Reader, w io.Writer) (*model.ScrubSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("input reader cannot be nil")
	}
	if w == nil {
		return nil, fmt.Errorf("output writer cannot be nil")
	}

	dec := json.NewDecoder(r)
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read initial plan token: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("expected object delimiter '{', got %s", tokenKind(tok))
	}

	bw := bufio.NewWriterSize(w, 64*1024)
	summary := &model.ScrubSummary{}

	var (
		seenFormatVer       bool
		seenTFVer           bool
		seenResourceChanges bool
		emittedFormatVer    bool
		emittedTFVer        bool
		startedObj          bool
		topLevelCount       int
	)

	ensureStarted := func() error {
		if startedObj {
			return nil
		}
		startedObj = true
		if s.indent != "" {
			_, err := bw.WriteString("{\n")
			return err
		}
		return bw.WriteByte('{')
	}

	writeKeyPrefix := func(key string) error {
		if err := ensureStarted(); err != nil {
			return err
		}
		if topLevelCount > 0 {
			if s.indent != "" {
				if _, err := bw.WriteString(",\n"); err != nil {
					return err
				}
			} else {
				if err := bw.WriteByte(','); err != nil {
					return err
				}
			}
		}
		topLevelCount++
		if s.indent != "" {
			if _, err := bw.WriteString(s.indent); err != nil {
				return err
			}
		}
		keyBytes, err := marshalJSONNoEscape(key, "", "")
		if err != nil {
			return err
		}
		if _, err := bw.Write(keyBytes); err != nil {
			return err
		}
		if s.indent != "" {
			_, err = bw.WriteString(": ")
			return err
		}
		return bw.WriteByte(':')
	}

	writeKV := func(key string, val any) error {
		if err := writeKeyPrefix(key); err != nil {
			return err
		}
		valBytes, err := marshalJSONNoEscape(val, "", "")
		if err != nil {
			return err
		}
		_, err = bw.Write(valBytes)
		return err
	}

	flushHeader := func() error {
		if !emittedFormatVer && summary.FormatVersion != "" {
			if err := writeKV("format_version", summary.FormatVersion); err != nil {
				return err
			}
			emittedFormatVer = true
		}
		if !emittedTFVer && summary.TerraformVersion != "" {
			if err := writeKV("terraform_version", summary.TerraformVersion); err != nil {
				return err
			}
			emittedTFVer = true
		}
		return nil
	}

	for dec.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read object key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %s", tokenKind(keyTok))
		}

		switch key {
		case "format_version":
			if seenFormatVer {
				return nil, fmt.Errorf("duplicate top-level key %q", key)
			}
			seenFormatVer = true
			var fv string
			if err := dec.Decode(&fv); err != nil {
				return nil, fmt.Errorf("decode format_version: %w", err)
			}
			summary.FormatVersion = fv
			if seenResourceChanges && fv != "" {
				if err := writeKV("format_version", fv); err != nil {
					return nil, err
				}
				emittedFormatVer = true
			}

		case "terraform_version":
			if seenTFVer {
				return nil, fmt.Errorf("duplicate top-level key %q", key)
			}
			seenTFVer = true
			var tv string
			if err := dec.Decode(&tv); err != nil {
				return nil, fmt.Errorf("decode terraform_version: %w", err)
			}
			summary.TerraformVersion = tv
			if seenResourceChanges && tv != "" {
				if err := writeKV("terraform_version", tv); err != nil {
					return nil, err
				}
				emittedTFVer = true
			}

		case "resource_changes":
			if seenResourceChanges {
				return nil, fmt.Errorf("duplicate top-level key %q", key)
			}
			seenResourceChanges = true

			if err := flushHeader(); err != nil {
				return nil, err
			}

			arrTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("read resource_changes token: %w", err)
			}
			if arrTok == nil {
				if err := writeKeyPrefix("resource_changes"); err != nil {
					return nil, err
				}
				if _, err := bw.WriteString("[]"); err != nil {
					return nil, err
				}
				continue
			}

			arrDelim, ok := arrTok.(json.Delim)
			if !ok || arrDelim != '[' {
				return nil, fmt.Errorf("expected array delimiter '[' for resource_changes, got %s", tokenKind(arrTok))
			}

			if err := writeKeyPrefix("resource_changes"); err != nil {
				return nil, err
			}
			if err := bw.WriteByte('['); err != nil {
				return nil, err
			}

			elemIdx := 0
			for dec.More() {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				var rawRC rawResourceChange
				if err := dec.Decode(&rawRC); err != nil {
					return nil, fmt.Errorf("decode resource_change at index %d: %w", elemIdx, err)
				}

				scrubbedIndex, err := scrubResourceIndex(rawRC.Index, summary)
				if err != nil {
					return nil, fmt.Errorf("validate index for %q: %w", rawRC.Address, err)
				}

				scrubbedRC := scrubbedResourceChange{
					Address:         rawRC.Address,
					PreviousAddress: rawRC.PreviousAddress,
					ModuleAddress:   rawRC.ModuleAddress,
					Mode:            rawRC.Mode,
					Type:            rawRC.Type,
					Name:            rawRC.Name,
					Index:           scrubbedIndex,
					ProviderName:    rawRC.ProviderName,
					DeposedKey:      rawRC.DeposedKey,
					ActionReason:    rawRC.ActionReason,
				}
				if rawRC.Change != nil {
					scrubbedBefore, err := scrubStateValue(rawRC.Change.Before, rawRC.Change.BeforeSensitive, s.customRedactKeys, summary)
					if err != nil {
						return nil, fmt.Errorf("scrub change.before for %q: %w", rawRC.Address, err)
					}
					scrubbedAfter, err := scrubStateValue(rawRC.Change.After, rawRC.Change.AfterSensitive, s.customRedactKeys, summary)
					if err != nil {
						return nil, fmt.Errorf("scrub change.after for %q: %w", rawRC.Address, err)
					}
					scrubbedRC.Change = &scrubbedChange{
						Actions: rawRC.Change.Actions,
						Before:  scrubbedBefore,
						After:   scrubbedAfter,
					}
				}

				elemBytes, err := marshalJSONNoEscape(scrubbedRC, s.indent+s.indent, s.indent)
				if err != nil {
					return nil, fmt.Errorf("marshal scrubbed resource_change %q: %w", rawRC.Address, err)
				}

				if elemIdx > 0 {
					if err := bw.WriteByte(','); err != nil {
						return nil, err
					}
				}
				if s.indent != "" {
					if err := bw.WriteByte('\n'); err != nil {
						return nil, err
					}
					if _, err := bw.WriteString(s.indent); err != nil {
						return nil, err
					}
					if _, err := bw.WriteString(s.indent); err != nil {
						return nil, err
					}
				}
				if _, err := bw.Write(elemBytes); err != nil {
					return nil, err
				}

				elemIdx++
				summary.ResourceChangesCount++
			}

			closingArrTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("read closing resource_changes delimiter: %w", err)
			}
			if d, ok := closingArrTok.(json.Delim); !ok || d != ']' {
				return nil, fmt.Errorf("expected closing array delimiter ']', got %s", tokenKind(closingArrTok))
			}

			if elemIdx > 0 && s.indent != "" {
				if err := bw.WriteByte('\n'); err != nil {
					return nil, err
				}
				if _, err := bw.WriteString(s.indent); err != nil {
					return nil, err
				}
			}
			if err := bw.WriteByte(']'); err != nil {
				return nil, err
			}

		default:
			if err := skipValue(ctx, dec); err != nil {
				return nil, fmt.Errorf("skip top-level key %q: %w", key, err)
			}
			summary.SkippedTopLevelFields++
		}
	}

	closingObjTok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read closing object delimiter: %w", err)
	}
	if d, ok := closingObjTok.(json.Delim); !ok || d != '}' {
		return nil, fmt.Errorf("expected closing object delimiter '}', got %s", tokenKind(closingObjTok))
	}

	extraTok, err := dec.Token()
	if err == nil {
		return nil, fmt.Errorf("unexpected trailing token after JSON root object: %s", tokenKind(extraTok))
	}
	if err != io.EOF {
		return nil, fmt.Errorf("read trailing token: %w", err)
	}

	if !seenResourceChanges {
		if err := flushHeader(); err != nil {
			return nil, err
		}
		if err := writeKeyPrefix("resource_changes"); err != nil {
			return nil, err
		}
		if _, err := bw.WriteString("[]"); err != nil {
			return nil, err
		}
	}

	if s.indent != "" {
		if _, err := bw.WriteString("\n}\n"); err != nil {
			return nil, err
		}
	} else {
		if _, err := bw.WriteString("}\n"); err != nil {
			return nil, err
		}
	}

	if err := bw.Flush(); err != nil {
		return nil, fmt.Errorf("flush scrubbed output: %w", err)
	}

	summary.TotalRedactedLeaves = summary.RedactedByMaskCount + summary.RedactedByKeyCount + summary.RedactedByValueCount
	return summary, nil
}

// ScrubReaderToFile stream-scrubs JSON from r into outPath via an atomic 0600 temp file.
func (s *Scrubber) ScrubReaderToFile(ctx context.Context, r io.Reader, outPath string) (*model.ScrubSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("input reader cannot be nil")
	}
	if err := validateOutPath(outPath); err != nil {
		return nil, err
	}

	return s.writeStreamAtomic(ctx, r, outPath, nil)
}

// ScrubFile stream-scrubs an input plan JSON file at inPath and atomically writes the
// sanitized output to outPath (safely supporting in-place scrubbing when inPath == outPath).
func (s *Scrubber) ScrubFile(ctx context.Context, inPath, outPath string) (*model.ScrubSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(inPath) == "" {
		return nil, fmt.Errorf("input plan path cannot be empty")
	}
	fi, err := os.Stat(inPath)
	if err != nil {
		return nil, fmt.Errorf("stat plan file %s: %w", inPath, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file: %s", inPath)
	}
	if err := validateOutPath(outPath); err != nil {
		return nil, err
	}

	inFile, err := os.Open(inPath)
	if err != nil {
		return nil, fmt.Errorf("open plan file %s: %w", inPath, err)
	}

	return s.writeStreamAtomic(ctx, inFile, outPath, inFile)
}

func (s *Scrubber) writeStreamAtomic(ctx context.Context, r io.Reader, outPath string, inFile *os.File) (*model.ScrubSummary, error) {
	parentDir := filepath.Dir(outPath)
	tmpFile, err := os.CreateTemp(parentDir, ".tf-sim-scrub-*.tmp")
	if err != nil {
		if inFile != nil {
			_ = inFile.Close()
		}
		return nil, fmt.Errorf("create temp output file: %w", err)
	}
	tmpPath := tmpFile.Name()
	success := false

	defer func() {
		if inFile != nil {
			_ = inFile.Close()
		}
		if tmpFile != nil {
			_ = tmpFile.Close()
		}
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("set permissions on temp output file: %w", err)
	}

	summary, err := s.ScrubStream(ctx, r, tmpFile)
	if err != nil {
		return nil, err
	}

	if err := tmpFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync temp output file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		tmpFile = nil
		return nil, fmt.Errorf("close temp output file: %w", err)
	}
	tmpFile = nil

	if inFile != nil {
		if err := inFile.Close(); err != nil {
			inFile = nil
			return nil, fmt.Errorf("close input plan file: %w", err)
		}
		inFile = nil
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		return nil, fmt.Errorf("write output file %s: %w", outPath, err)
	}
	success = true

	return summary, nil
}

func validateOutPath(outPath string) error {
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	lfi, err := os.Lstat(outPath)
	if err == nil {
		if lfi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink output path: %s", outPath)
		}
		if lfi.IsDir() {
			return fmt.Errorf("output path is a directory, not a file: %s", outPath)
		}
		if !lfi.Mode().IsRegular() {
			return fmt.Errorf("output path is not a regular file: %s", outPath)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output path %s: %w", outPath, err)
	}

	parentDir := filepath.Dir(outPath)
	dirInfo, err := os.Stat(parentDir)
	if err != nil {
		return fmt.Errorf("stat output parent directory %s: %w", parentDir, err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("output parent path is not a directory: %s", parentDir)
	}
	return nil
}

func marshalJSONNoEscape(v any, prefix, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent(prefix, indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func skipValue(ctx context.Context, dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	_, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil
	}

	depth := 1
	tokens := 0
	for depth > 0 {
		tokens++
		if tokens&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > maxSkipDepth {
					return fmt.Errorf("maximum JSON skip nesting depth (%d) exceeded", maxSkipDepth)
				}
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func tokenKind(tok json.Token) string {
	switch t := tok.(type) {
	case nil:
		return "null"
	case json.Delim:
		return fmt.Sprintf("delimiter %q", string(t))
	case string:
		return "string"
	case json.Number, float64:
		return "number"
	case bool:
		return "bool"
	default:
		return "token"
	}
}

func scrubResourceIndex(idx any, summary *model.ScrubSummary) (any, error) {
	switch v := idx.(type) {
	case nil, json.Number:
		return v, nil
	case string:
		if v == RedactedPlaceholder {
			return RedactedPlaceholder, nil
		}
		if isSecretStringValue(v) {
			summary.RedactedByValueCount++
			return RedactedPlaceholder, nil
		}
		return v, nil
	default:
		return nil, fmt.Errorf("invalid resource_change index type %T", idx)
	}
}
