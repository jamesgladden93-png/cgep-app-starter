package compliance.s3

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_s3_bucket_versioning"

    rc.change.after.versioning_configuration.status != "Enabled"

    msg := "GAP-04: S3 bucket versioning must be enabled"
}