package policies

import "embed"

// PackFS embeds the curated multi-cloud starter policy pack (AWS, Azure, GCP).
//
//go:embed aws/*.rego azure/*.rego gcp/*.rego
var PackFS embed.FS
