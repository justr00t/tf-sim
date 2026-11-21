# Starter Policy Pack - GCP Non-Compliant Infrastructure Fixture
# Covers all 6 patchable GCP rules + 2 non-patchable Cloud SQL rules

resource "google_storage_bucket" "explicit_bad" {
  name                        = "bad-gcs-bucket"
  location                    = "US"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
}

resource "google_storage_bucket" "missing_attrs" {
  name     = "missing-gcs-bucket"
  location = "US"
}

# Non-patchable Cloud SQL resources (remediate must cleanly skip gcp-sql-ssl and gcp-sql-backup)
resource "google_sql_database_instance" "explicit_bad" {
  name             = "bad-cloudsql"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    }

    backup_configuration {
      enabled = false
    }
  }
}

resource "google_sql_database_instance" "missing_attrs" {
  name             = "missing-cloudsql"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
  }
}

resource "google_compute_instance" "explicit_bad" {
  name           = "bad-vm"
  machine_type   = "e2-medium"
  zone           = "us-central1-a"
  can_ip_forward = true

  shielded_instance_config {
    enable_secure_boot = false
  }
}

resource "google_compute_instance" "missing_attrs" {
  name         = "missing-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
}

resource "google_kms_crypto_key" "explicit_bad" {
  name            = "bad-crypto-key"
  key_ring        = "projects/demo/locations/global/keyRings/main"
  rotation_period = ""
}

resource "google_kms_crypto_key" "missing_attrs" {
  name     = "missing-crypto-key"
  key_ring = "projects/demo/locations/global/keyRings/main"
}

resource "google_compute_firewall" "explicit_bad" {
  name    = "bad-firewall"
  network = "default"

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "missing_attrs" {
  name    = "missing-firewall"
  network = "default"
}
