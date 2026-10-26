# Machine Learning Platform - GCP Cloud Storage Infrastructure
# Managed by MLOps Team

resource "google_storage_bucket" "secure_models" {
  name                        = "ml-models-secure"
  location                    = "US"
  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1"
  }
}

# Raw training dataset bucket (non-compliant ACL access setting)
resource "google_storage_bucket" "open_training_data" {
  name     = "ml-training-raw"
  location = "US"

  # Must enforce uniform bucket-level IAM access
  uniform_bucket_level_access = false
}
