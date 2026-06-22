package compliance.s3

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_s3_bucket_server_side_encryption_configuration"

    rc.change.after.rule.apply_server_side_encryption_by_default.sse_algorithm != "aws:kms"

    msg := "GAP-01: S3 buckets storing PHI must use customer-managed KMS encryption"
}