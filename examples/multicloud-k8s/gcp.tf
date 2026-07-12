# Intentionally insecure GCP fixtures for Attestral rule coverage.

resource "google_compute_firewall" "open" {
  name          = "allow-all"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
}

resource "google_sql_database_instance" "db" {
  name             = "acme-pg"
  database_version = "POSTGRES_15"

  settings {
    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false
    }
  }
}

resource "google_storage_bucket" "data" {
  name                        = "acme-data"
  uniform_bucket_level_access = false
}

resource "google_container_cluster" "gke" {
  name              = "acme-gke"
  enable_legacy_abac = true
}
