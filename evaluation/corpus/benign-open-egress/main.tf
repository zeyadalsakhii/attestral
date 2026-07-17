# A well-configured service security group using Terraform's near-universal
# default-outbound idiom: tight, scoped ingress plus a world-open egress.
# The 0.0.0.0/0 on egress must never read as "open to the world" - a HIGH
# here is the false positive that gets a scanner muted on its first real run.

resource "aws_security_group" "service" {
  name        = "payments-service"
  description = "443 from the VPC only; standard default outbound"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.service.id
}
