# Intentionally insecure AWS fixtures for the v0.6 rule additions.

resource "aws_cloudtrail" "main" {
  name                          = "acme-trail"
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}

resource "aws_ecr_repository" "app" {
  name                 = "acme/app"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_eks_cluster" "cluster" {
  name = "acme-eks"

  vpc_config {
    endpoint_public_access = true
  }
}

resource "aws_lb_listener" "web" {
  protocol = "HTTP"
  port     = 80
}

resource "aws_efs_file_system" "shared" {
  creation_token = "acme-efs"
  encrypted      = false
}

resource "aws_cloudwatch_log_group" "app" {
  name = "/acme/app"
}
