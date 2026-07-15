# Intentionally insecure AWS fixtures for the core-pack checks ATL-008..ATL-018.
# Every resource below is deliberately misconfigured to trigger exactly its
# rule(s), and hardened on every other attribute so no neighbouring core or
# aws-pack rule co-fires. Do not use as a template for real infrastructure.

# ATL-008 (no IAM database auth) + ATL-009 (single-AZ): one Aurora cluster.
# Encrypted with backups retained, so ATL-006/ATL-007 stay quiet.
resource "aws_rds_cluster" "billing" {
  cluster_identifier                  = "billing"
  storage_encrypted                   = true
  backup_retention_period             = 7
  iam_database_authentication_enabled = false
  multi_az                            = false
}

# ATL-010: instance storage explicitly unencrypted. The explicit `false` keeps
# ATL-005 (attr_missing) quiet; the hardened flags keep ATL-004/048/049 quiet.
resource "aws_db_instance" "app" {
  identifier                 = "app"
  storage_encrypted          = false
  publicly_accessible        = false
  auto_minor_version_upgrade = true
  deletion_protection        = true
}

# ATL-011: unencrypted EBS volume.
resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

# ATL-012: instance with a public IP. metadata_options is omitted entirely so
# ATL-033 (IMDSv2 optional) stays quiet.
resource "aws_instance" "bastion" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

# ATL-013: KMS key with rotation switched off.
resource "aws_kms_key" "data" {
  description         = "data encryption key"
  enable_key_rotation = false
}

# ATL-014: SNS topic with no KMS key (kms_master_key_id absent).
resource "aws_sns_topic" "alerts" {
  name = "alerts"
}

# ATL-015: SQS queue with no KMS key (kms_master_key_id absent).
resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}

# ATL-016: authenticated-read ACL - readable by ANY AWS account, not just this
# one. ATL-001 matches the public-read values only, so ATL-016 fires alone.
resource "aws_s3_bucket" "handoff" {
  bucket = "acme-handoff"
  acl    = "authenticated-read"
}

# ATL-017: unencrypted Neptune cluster.
resource "aws_neptune_cluster" "graph" {
  cluster_identifier = "graph"
  storage_encrypted  = false
}

# ATL-018: publicly accessible Redshift cluster. Encrypted, so ATL-042 (pack)
# stays quiet.
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier  = "warehouse"
  node_type           = "dc2.large"
  encrypted           = true
  publicly_accessible = true
}
