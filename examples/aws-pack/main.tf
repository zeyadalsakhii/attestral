# Intentionally insecure AWS fixtures for the aws_pack.yaml rule set
# (ATL-027..ATL-054). Every resource below is deliberately misconfigured to
# trigger exactly one (or a small, disjoint set of) pack rule(s). Do not use
# as a template for real infrastructure.

# --- S3 -------------------------------------------------------------------

# ATL-027: versioning suspended.
resource "aws_s3_bucket_versioning" "reports" {
  bucket = "acme-reports"
  versioning_configuration {
    status = "Suspended"
  }
}

# ATL-029: MFA delete disabled (versioning otherwise enabled).
resource "aws_s3_bucket_versioning" "archive" {
  bucket = "acme-archive"
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Disabled"
  }
}

# ATL-028: account/bucket S3 Block Public Access switched off.
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = "acme-reports"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# --- IAM ------------------------------------------------------------------

# ATL-030 (length < 14) + ATL-031 (no reuse prevention declared).
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length = 8
  require_symbols         = false
  require_numbers         = true
}

# --- Networking / EC2 -----------------------------------------------------

# ATL-032: the VPC default security group is left permitting traffic.
resource "aws_default_security_group" "default" {
  vpc_id = "vpc-0acme"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ATL-033: instance metadata service still answers IMDSv1 (http_tokens optional).
resource "aws_instance" "app" {
  ami           = "ami-0acme"
  instance_type = "t3.small"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

# ATL-034: account-level EBS encryption-by-default turned off.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = false
}

# --- Lambda ---------------------------------------------------------------

# ATL-035: end-of-life runtime.
resource "aws_lambda_function" "worker" {
  function_name = "acme-worker"
  runtime       = "python3.7"
  handler       = "main.handler"
  role          = "arn:aws:iam::111122223333:role/acme-worker"
}

# ATL-036: public function URL with no authorization.
resource "aws_lambda_function_url" "worker" {
  function_name      = "acme-worker"
  authorization_type = "NONE"
}

# --- DynamoDB -------------------------------------------------------------

# ATL-037: deletion protection off.
resource "aws_dynamodb_table" "sessions" {
  name                        = "acme-sessions"
  hash_key                    = "id"
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = false
}

# --- CloudFront -----------------------------------------------------------

# ATL-038 (viewer protocol allow-all) + ATL-039 (minimum TLS TLSv1).
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true

  default_cache_behavior {
    target_origin_id       = "acme-origin"
    viewer_protocol_policy = "allow-all"
  }

  viewer_certificate {
    minimum_protocol_version = "TLSv1"
  }
}

# --- API Gateway ----------------------------------------------------------

# ATL-040: custom domain negotiates TLS 1.0.
resource "aws_api_gateway_domain_name" "api" {
  domain_name     = "api.acme.example"
  security_policy = "TLS_1_0"
}

# --- ELBv2 ----------------------------------------------------------------

# ATL-041: deletion protection off on the load balancer.
resource "aws_lb" "web" {
  name                       = "acme-web"
  load_balancer_type         = "application"
  enable_deletion_protection = false
}

# --- Redshift -------------------------------------------------------------

# ATL-042: data warehouse not encrypted at rest.
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier = "acme-warehouse"
  node_type          = "ra3.xlplus"
  encrypted          = false
}

# --- OpenSearch -----------------------------------------------------------

# ATL-043: search domain does not enforce HTTPS.
resource "aws_opensearch_domain" "search" {
  domain_name = "acme-search"

  domain_endpoint_options {
    enforce_https = false
  }
}

# --- DocumentDB -----------------------------------------------------------

# ATL-044: cluster storage not encrypted.
resource "aws_docdb_cluster" "docs" {
  cluster_identifier = "acme-docs"
  storage_encrypted  = false
}

# --- EKS ------------------------------------------------------------------

# ATL-045: no control-plane log types enabled.
resource "aws_eks_cluster" "platform" {
  name     = "acme-platform"
  role_arn = "arn:aws:iam::111122223333:role/acme-eks"

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

# --- SageMaker ------------------------------------------------------------

# ATL-046 (direct internet access) + ATL-047 (root access).
resource "aws_sagemaker_notebook_instance" "research" {
  name                   = "acme-research"
  instance_type          = "ml.t3.medium"
  role_arn               = "arn:aws:iam::111122223333:role/acme-sm"
  direct_internet_access = "Enabled"
  root_access            = "Enabled"
}

# --- RDS instance ---------------------------------------------------------

# ATL-048 (auto minor upgrade off) + ATL-049 (deletion protection off).
# storage_encrypted is set so the core encryption rules stay quiet.
resource "aws_db_instance" "orders" {
  identifier                 = "acme-orders"
  engine                     = "postgres"
  instance_class             = "db.t3.medium"
  storage_encrypted          = true
  auto_minor_version_upgrade = false
  deletion_protection        = false
}

# --- MSK ------------------------------------------------------------------

# ATL-050: broker traffic permits plaintext.
resource "aws_msk_cluster" "events" {
  cluster_name           = "acme-events"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = 3

  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT"
    }
  }
}

# --- Kinesis --------------------------------------------------------------

# ATL-051: stream stored without server-side encryption.
resource "aws_kinesis_stream" "ingest" {
  name             = "acme-ingest"
  shard_count      = 2
  encryption_type  = "NONE"
}

# --- ElastiCache ----------------------------------------------------------

# ATL-052 (at-rest) + ATL-053 (in-transit) encryption disabled.
resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "acme-cache"
  description                = "acme cache"
  at_rest_encryption_enabled = false
  transit_encryption_enabled = false
}

# --- CloudTrail -----------------------------------------------------------

# ATL-054: trail logs are not encrypted with a KMS CMK.
resource "aws_cloudtrail" "audit" {
  name                       = "acme-audit"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
