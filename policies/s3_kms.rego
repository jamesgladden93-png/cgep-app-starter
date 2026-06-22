# METADATA
# title: GAP-01 — S3 PHI buckets must use customer-managed KMS encryption
# description: Enforces SC.L2-3.13.11 (FIPS-validated cryptography). Fails any plan
#   where the S3 uploads bucket SSE configuration deviates from aws:kms.
# custom:
#   framework: cmmc-l2
#   controls:
#     - "SC.L2-3.13.10"
#   severity: high
#   gap: GAP-01
package compliance.s3

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_s3_bucket_server_side_encryption_configuration"

    rc.change.after.rule.apply_server_side_encryption_by_default.sse_algorithm != "aws:kms"

    msg := "GAP-01: S3 buckets storing PHI must use customer-managed KMS encryption"
}