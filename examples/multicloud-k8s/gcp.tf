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

resource "google_container_cluster" "gke_hardening" {
  name                  = "acme-gke-2"
  enable_shielded_nodes = false

  private_cluster_config {
    enable_private_nodes = false
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }
}

resource "google_compute_instance" "vm" {
  name           = "acme-vm"
  machine_type   = "e2-medium"
  can_ip_forward = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }

  service_account {
    email  = "default-compute@acme.iam.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = false
    enable_vtpm                 = false
    enable_integrity_monitoring = false
  }
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_kms_crypto_key" "key" {
  name     = "acme-key"
  key_ring = "acme-ring"
}
