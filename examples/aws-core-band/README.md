# AWS core-band fixture (ATL-008..ATL-018)

Eleven of the original core-pack AWS checks - RDS IAM auth and availability,
storage encryption across RDS/EBS/Neptune, KMS rotation, SNS/SQS encryption,
the `authenticated-read` S3 ACL, public EC2 IPs, and public Redshift - one
deliberately misconfigured resource per rule.

```bash
attestral scan examples/aws-core-band
```

```
10 components · 11 findings · 1 critical · 4 high · 5 medium · 1 low
```

| Rule | Severity | The planted misconfiguration |
|---|---|---|
| ATL-018 | critical | Redshift cluster is publicly accessible |
| ATL-010 | high | RDS instance storage unencrypted |
| ATL-011 | high | EBS volume unencrypted |
| ATL-016 | high | S3 ACL `authenticated-read` (any AWS account can read) |
| ATL-017 | high | Neptune cluster storage unencrypted |
| ATL-008 | medium | RDS cluster without IAM database authentication |
| ATL-012 | medium | EC2 instance with a public IP |
| ATL-013 | medium | KMS key rotation off |
| ATL-014 | medium | SNS topic without KMS encryption |
| ATL-015 | medium | SQS queue without KMS encryption |
| ATL-009 | low | RDS cluster single-AZ |

Every resource is hardened on its *other* attributes (explicit encryption,
retention, deletion protection, no IMDSv1) so exactly this band fires and
nothing else - `tests/test_aws_core_band.py` asserts the set is equal, not just
a superset, so any drift into a neighbouring rule fails the suite.
