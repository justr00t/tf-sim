package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/justr00t/tf-sim/internal/report"
	"github.com/spf13/cobra"
)

// Build metadata injected at link time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// BuildInfo describes the compiled binary version, VCS commit, build timestamp,
// Go toolchain version, and target OS/architecture.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func normalizeVersion(v string) string {
	if len(v) >= 2 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

func currentBuildInfo() BuildInfo {
	v := strings.TrimSpace(version)
	c := strings.TrimSpace(commit)
	d := strings.TrimSpace(date)

	if v == "" {
		v = "dev"
	} else {
		v = normalizeVersion(v)
	}
	if c == "" {
		c = "none"
	}
	if d == "" {
		d = "unknown"
	}

	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = normalizeVersion(strings.TrimPrefix(strings.TrimSpace(bi.Main.Version), "v"))
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev := strings.TrimSpace(s.Value)
				if c == "none" && rev != "" {
					if len(rev) > 12 {
						rev = rev[:7]
					}
					c = rev
				}
			case "vcs.time":
				t := strings.TrimSpace(s.Value)
				if d == "unknown" && t != "" {
					d = t
				}
			}
		}
	}

	return BuildInfo{
		Version:   v,
		Commit:    c,
		Date:      d,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func newVersionCmd(stdout io.Writer) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print tf-sim build version, commit, and platform metadata",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := currentBuildInfo()
			norm := strings.ToLower(strings.TrimSpace(format))

			switch norm {
			case report.FormatTable:
				writeOutput(stdout, fmt.Sprintf(
					"tf-sim version %s (commit: %s, built: %s, go: %s, platform: %s)",
					info.Version, info.Commit, info.Date, info.GoVersion, info.Platform,
				))
				return nil

			case report.FormatJSON:
				data, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling build info to JSON: %w", err)
				}
				writeOutput(stdout, string(data))
				return nil

			default:
				return fmt.Errorf("unsupported output format %q: expected %q or %q", format, report.FormatTable, report.FormatJSON)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", report.FormatTable, "Output format (table|json)")

	return cmd
}
