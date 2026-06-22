package compliance.s3

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_s3_bucket_policy"

    not contains(lower(json.marshal(rc.change.after.policy)), "aws:securetransport")

    msg := "GAP-03: S3 buckets must deny non-TLS requests"
}