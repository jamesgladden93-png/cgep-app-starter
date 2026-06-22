package compliance.s3

import rego.v1

# METADATA
# title: GAP-04 — S3 bucket versioning must be enabled
# description: Enforces MP.L2-3.8.9 (media protection / backup). Fails any plan
#   where the S3 uploads bucket versioning configuration is absent or disabled.
# custom:
#   framework: cmmc-l2
#   controls:
#     - "MP.L2-3.8.9"
#   severity: medium
#   gap: GAP-04
deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_s3_bucket_versioning"

    rc.change.after.versioning_configuration.status != "Enabled"

    msg := "GAP-04: S3 bucket versioning must be enabled"
}