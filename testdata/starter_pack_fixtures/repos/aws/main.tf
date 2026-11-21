# Starter Policy Pack - AWS Non-Compliant Infrastructure Fixture
# Covers all 12 AWS starter policy rules (explicit non-compliant + missing attributes)

resource "aws_s3_bucket_public_access_block" "explicit_bad" {
  bucket                  = "bad-pab-bucket"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_public_access_block" "missing_attrs" {
  bucket = "missing-pab-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "explicit_bad" {
  bucket = "bad-sse-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "missing_attrs" {
  bucket = "missing-sse-bucket"
}

resource "aws_s3_bucket_versioning" "explicit_bad" {
  bucket = "bad-ver-bucket"

  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_versioning" "missing_attrs" {
  bucket = "missing-ver-bucket"
}

resource "aws_db_instance" "explicit_bad" {
  identifier                          = "bad-db"
  storage_encrypted                   = false
  publicly_accessible                 = true
  iam_database_authentication_enabled = false
}

resource "aws_db_instance" "missing_attrs" {
  identifier = "missing-db"
}

resource "aws_ebs_volume" "explicit_bad" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_ebs_volume" "missing_attrs" {
  availability_zone = "us-east-1a"
  size              = 20
}

resource "aws_instance" "explicit_bad" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  ebs_optimized = false
}

resource "aws_instance" "missing_attrs" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

resource "aws_kms_key" "explicit_bad" {
  description         = "bad key"
  enable_key_rotation = false
}

resource "aws_kms_key" "missing_attrs" {
  description = "missing rotation key"
}
