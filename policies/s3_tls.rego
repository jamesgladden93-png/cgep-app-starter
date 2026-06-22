package compliance.s3

import rego.v1

# METADATA
# title: GAP-03 — S3 buckets must deny non-TLS requests
# description: Enforces SC.L2-3.13.8 (encryption in transit). Fails any plan where
#   the S3 uploads bucket policy omits an aws:SecureTransport=false deny statement.
# custom:
#   framework: nist-800-53-rev5
#   controls:
#     - "SC-8"
#   severity: high
#   gap: GAP-03
deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_s3_bucket_policy"

    not contains(lower(json.marshal(rc.change.after.policy)), "aws:securetransport")

    msg := "GAP-03: S3 buckets must deny non-TLS requests"
}