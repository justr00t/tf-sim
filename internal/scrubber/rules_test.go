package scrubber

import (
	"strings"
	"testing"
)

func TestRedactedPlaceholderConstant(t *testing.T) {
	if RedactedPlaceholder != "[REDACTED]" {
		t.Fatalf("expected RedactedPlaceholder to be %q, got %q", "[REDACTED]", RedactedPlaceholder)
	}
}

func TestIsBuiltinSensitiveKey(t *testing.T) {
	sensitiveKeys := []string{
		"password",
		"PASSWORD",
		"administrator_login_password",
		"master_password",
		"passwd",
		"user_passwd",
		"passphrase",
		"tls_passphrase",
		"secret",
		"client_secret",
		"shared_secret",
		"secret_key",
		"secret_string",
		"secret_binary",
		"secret_value",
		"token",
		"auth_token",
		"access_token",
		"refresh_token",
		"session_token",
		"api_token",
		"bearer_token",
		"private_key",
		"private_key_pem",
		"private_key_openssh",
		"private_key_pkcs8",
		"ssh_private_key",
		"api_key",
		"x-api-key",
		"x.api.key",
		"access_key",
		"primary_access_key",
		"secret_access_key",
		"connection_string",
		"primary_connection_string",
		"  Client-Secret  ",
		"adminPassword",
		"clientSecret",
		"apiKey",
		"accessToken",
		"privateKey",
		"connectionString",
		"awsAPIKey",
	}

	for _, k := range sensitiveKeys {
		if !isBuiltinSensitiveKey(k) {
			t.Errorf("expected isBuiltinSensitiveKey(%q) == true", k)
		}
	}

	nonSensitiveKeys := []string{
		"",
		"   ",
		"kms_key_id",
		"kmsKeyId",
		"kms_master_key_id",
		"enable_key_rotation",
		"enableKeyRotation",
		"bucket_key_enabled",
		"default_kms_key_name",
		"http_tokens",
		"httpTokens",
		"oauth_tokens",
		"shared_access_key_enabled",
		"secret_id",
		"minimum_password_length",
		"password_policy",
		"key_vault_id",
		"public_key",
	}

	for _, k := range nonSensitiveKeys {
		if isBuiltinSensitiveKey(k) {
			t.Errorf("expected isBuiltinSensitiveKey(%q) == false", k)
		}
	}
}

func TestIsSecretStringValue(t *testing.T) {
	secrets := []struct {
		name string
		val  string
	}{
		{"PEM_RSA", "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----"},
		{"PEM_EC", "-----BEGIN " + "EC PRIVATE KEY-----\nMHcCAQEEItest\n-----END EC PRIVATE KEY-----"},
		{"PEM_Generic", "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgtest\n-----END PRIVATE KEY-----"},
		{"AWS_AKIA", "AKIA" + "IOSFODNN7EXAMPLE"},
		{"AWS_ASIA", "ASIA" + "IOSFODNN7EXAMPLE"},
		{"AWS_SecretAccessKey", "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"GitHub_ghp", "ghp_" + "0123456789abcdef0123456789abcdef0123"},
		{"GitHub_PAT", "github_pat_" + "11AAAAAA00000000000000_0123456789abcdef0123456789abcdef"},
		{"GitLab_PAT", "glpat-" + "0123456789abcdef0123"},
		{"GitLab_TrailingHyphen", "glpat-" + "0123456789abcdef012-"},
		{"Slack_Bot", "xoxb-" + "0000000000-0000000000-abcdefghijklmnopqrstuvwx"},
		{"Slack_TrailingHyphen", "xoxb-" + "0000000000-"},
		{"Google_API", "AIza" + "SyDummyExampleKey0123456789abcdefghi"},
		{"Google_API_TrailingHyphen_InURL", "https://maps.googleapis.com/maps/api/js?key=" + "AIza" + "SyDummyExampleKey0123456789abcdefg-&callback=init"},
		{"Google_API_TrailingHyphen_EOS", "AIza" + "SyDummyExampleKey0123456789abcdefg-"},
		{"Stripe_Live", "sk_live_" + "0123456789abcdefghijklmnop"},
		{"OpenAI_Proj", "sk-proj-" + "0123456789abcdefghijklmnopqrstuvwxyz"},
		{"OpenAI_TrailingHyphen", "sk-proj-" + "0123456789abcdefghijklmnopqrstuvwx-"},
		{"JWT", "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"Credentialed_URI", "postgres://admin:" + "examplePass123@db.example.internal:5432/prod"},
		{"ConnStr_AccountKey", "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + "abcd12345678;"},
		{"ConnStr_ShortPassword", "Server=db;Database=app;Uid=sa;Password=" + "s3cr3t;"},
		{"ConnStr_RedactedPrefixBypass", "Server=db;Password=" + RedactedPlaceholder + "extraSecret;"},
		{"Bearer_Token", "Bearer " + "AbCdEf1234567890GhIjKlMnOpQrStUvWxYz"},
		{"Basic_Auth", "Authorization: Basic " + "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
		{"Large_HighEntropy_5000Bytes", strings.Repeat("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5-A6bC7dE8fG9hI0jK1lM2nO3p", 80)},
	}

	for _, tc := range secrets {
		t.Run("Secret_"+tc.name, func(t *testing.T) {
			if !isSecretStringValue(tc.val) {
				t.Errorf("expected isSecretStringValue to detect %s", tc.name)
			}
		})
	}

	safeValues := []struct {
		name string
		val  string
	}{
		{"Empty", ""},
		{"AlreadyRedacted", RedactedPlaceholder},
		{"PublicCertificate", "-----BEGIN CERTIFICATE-----\nMIIDtest\n-----END CERTIFICATE-----"},
		{"PublicKey", "-----BEGIN PUBLIC KEY-----\nMIIBIjANtest\n-----END PUBLIC KEY-----"},
		{"RedactedURI", "postgres://admin:[REDACTED]@db.example.internal:5432/prod"},
		{"RedactedConnStr", "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=[REDACTED];"},
		{"AWS_ARN", "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"},
		{"Azure_ID", "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"},
		{"GCP_Path", "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1"},
		{"HTTPS_URL", "https://example.com/v1/SomeLongPathWithMixedCase1234567890"},
		{"UUID", "12345678-1234-1234-1234-123456789012"},
		{"AWS_AMI", "ami-0123456789abcdef0"},
		{"Enum_Constant", "ALLOW_UNENCRYPTED_AND_ENCRYPTED"},
		{"IAM_Policy_JSON", `{"Version":"2012-10-17","Statement":[{"Action":["iam:ChangePassword","secretsmanager:GetSecretValue"],"Effect":"Allow","Resource":"*"}]}`},
		{"TooShortForEntropy", "Abc123Def456Ghi789"},
		{"RepeatedLowEntropy", strings.Repeat("Aa1", 15)},
	}

	for _, tc := range safeValues {
		t.Run("Safe_"+tc.name, func(t *testing.T) {
			if isSecretStringValue(tc.val) {
				t.Errorf("expected isSecretStringValue(%q) == false for %s", tc.val, tc.name)
			}
		})
	}
}
