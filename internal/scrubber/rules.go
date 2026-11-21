package scrubber

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// RedactedPlaceholder is the replacement string written for redacted leaf values.
const RedactedPlaceholder = "[REDACTED]"

var keyNormalizer = strings.NewReplacer("-", "_", ".", "_")

var builtinExactSecretKeys = map[string]struct{}{
	"password":          {},
	"passwd":            {},
	"passphrase":        {},
	"secret":            {},
	"secret_key":        {},
	"secret_string":     {},
	"secret_binary":     {},
	"secret_value":      {},
	"client_secret":     {},
	"shared_secret":     {},
	"token":             {},
	"auth_token":        {},
	"access_token":      {},
	"refresh_token":     {},
	"session_token":     {},
	"api_token":         {},
	"bearer_token":      {},
	"private_key":       {},
	"private_key_pem":   {},
	"private_key_openssh": {},
	"private_key_pkcs8": {},
	"api_key":           {},
	"access_key":        {},
	"secret_access_key": {},
	"connection_string": {},
}

var builtinSecretKeySuffixes = []string{
	"_password",
	"_passwd",
	"_passphrase",
	"_secret",
	"_secret_key",
	"_token",
	"_private_key",
	"_api_key",
	"_access_key",
	"_connection_string",
}

var (
	rePEMPrivateKey      = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----`)
	reAWSAccessKeyID     = regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)
	reGitHubClassicToken = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b`)
	reGitHubFineToken    = regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`)
	reGitLabPAT          = regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}(?:[^0-9A-Za-z\-_]|$)`)
	reSlackToken         = regexp.MustCompile(`\bxox(?:b|p|a|r|s)-[0-9A-Za-z\-]{10,}(?:[^0-9A-Za-z\-_]|$)`)
	reGoogleAPIKey       = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}(?:[^0-9A-Za-z\-_]|$)`)
	reStripeKey          = regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b`)
	reOpenAIAnthropicKey = regexp.MustCompile(`\bsk-(?:proj-|ant-api\d{2}-)?[A-Za-z0-9\-_]{32,}(?:[^0-9A-Za-z\-_]|$)`)
	reJWT                = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	reCredentialedURI    = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]*:([^/\s@]+)@[^\s]+`)
	reConnStringSecret   = regexp.MustCompile(`(?i)(?:AccountKey|SharedAccessSignature|SharedAccessKey|Password|Pwd)\s*=\s*([^;\s]{6,})`)
	reBearerToken        = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*`)
	reBasicAuth          = regexp.MustCompile(`(?i)\bBasic\s+[A-Za-z0-9+/]{12,}={0,2}`)

	reUUID        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reAWSHexID    = regexp.MustCompile(`^[a-z]{2,10}-[0-9a-f]{8,17}$`)
	simpleRegexes = []*regexp.Regexp{
		rePEMPrivateKey,
		reAWSAccessKeyID,
		reGitHubClassicToken,
		reGitHubFineToken,
		reGitLabPAT,
		reSlackToken,
		reGoogleAPIKey,
		reStripeKey,
		reOpenAIAnthropicKey,
		reJWT,
		reBearerToken,
		reBasicAuth,
	}
)

func normalizeKey(key string) string {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return ""
	}
	replaced := keyNormalizer.Replace(trimmed)
	runes := []rune(replaced)
	var b strings.Builder
	b.Grow(len(replaced) + 4)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			hasNextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && hasNextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func isBuiltinSensitiveKey(key string) bool {
	norm := normalizeKey(key)
	if norm == "" {
		return false
	}
	if _, ok := builtinExactSecretKeys[norm]; ok {
		return true
	}
	for _, suffix := range builtinSecretKeySuffixes {
		if strings.HasSuffix(norm, suffix) {
			return true
		}
	}
	return false
}

func isKnownSecretPattern(s string) bool {
	for _, re := range simpleRegexes {
		if re.MatchString(s) {
			return true
		}
	}
	for _, m := range reCredentialedURI.FindAllStringSubmatch(s, -1) {
		if len(m) > 1 && m[1] != RedactedPlaceholder {
			return true
		}
	}
	for _, m := range reConnStringSecret.FindAllStringSubmatch(s, -1) {
		if len(m) > 1 && strings.Trim(m[1], "\"'") != RedactedPlaceholder {
			return true
		}
	}
	return false
}

func isHighEntropySecret(s string) bool {
	if len(s) < 32 || len(s) > 16384 || s == RedactedPlaceholder {
		return false
	}
	if hasWhitespace(s) || hasStructuralPrefixOrFormat(s) {
		return false
	}

	var hasUpper, hasLower, hasDigit bool
	slashCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '/':
			slashCount++
		case c == '+' || c == '=' || c == '_' || c == '-':
		default:
			return false
		}
	}
	if !hasUpper || !hasLower || !hasDigit || slashCount >= 3 {
		return false
	}
	return shannonEntropy(s) >= 4.3
}

func hasWhitespace(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			return true
		}
	}
	return false
}

func hasStructuralPrefixOrFormat(s string) bool {
	if strings.HasPrefix(s, "/") {
		return true
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "arn:") ||
		strings.HasPrefix(lower, "projects/") ||
		strings.HasPrefix(lower, "organizations/") ||
		strings.HasPrefix(lower, "folders/") ||
		strings.HasPrefix(lower, "billingaccounts/") ||
		strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") {
		return true
	}
	if reUUID.MatchString(s) || reAWSHexID.MatchString(s) {
		return true
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isSecretStringValue(s string) bool {
	if s == "" || s == RedactedPlaceholder {
		return false
	}
	if isKnownSecretPattern(s) {
		return true
	}
	return isHighEntropySecret(s)
}
