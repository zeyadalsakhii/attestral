# AWS service-coverage expansion (ATL-055..ATL-067)

Thirteen CIS-AWS / AWS FSBP checks extending the pack to more services: a public
Lambda function URL, RDS without IAM auth, Redshift not forcing VPC-routed
traffic, ElastiCache without at-rest or in-transit encryption, an unencrypted
DocumentDB cluster, SageMaker notebooks with internet or root access, an ALB
without deletion protection or invalid-header dropping, an unencrypted Kinesis
stream, an unauthenticated API Gateway method, and a CloudFront distribution
with no WAF.

```bash
attestral scan examples/aws-pack-ext
```

Each resource is misconfigured on exactly the one attribute its rule targets and
hardened elsewhere, so it fires its own new rule; the fixture also legitimately
raises other existing AWS pack findings on the same resources (real, not noise).
See `tests/test_aws_pack_ext.py`.
