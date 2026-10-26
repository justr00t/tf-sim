# Payments Service - AWS Storage Infrastructure
# Managed by Platform Engineering

resource "aws_s3_bucket" "compliant_audit_logs" {
  bucket = "company-audit-logs"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "arn:aws:kms:us-east-1:111122223333:key/123"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  versioning {
    enabled = true
  }
}

# Monthly financial reports bucket (currently missing server-side encryption)
resource "aws_s3_bucket" "unencrypted_reports" {
  # Retain bucket name for downstream billing export
  bucket = "company-unencrypted-reports"
}
