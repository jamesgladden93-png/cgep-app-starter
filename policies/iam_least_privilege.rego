# METADATA
# title: GAP-07 — Lambda IAM role must not use wildcard S3 or DynamoDB permissions
# description: Enforces AC.L2-3.1.5 (least privilege). Fails any plan where an
#   aws_iam_role_policy contains s3:* or dynamodb:* wildcard action grants.
# custom:
#   framework: cmmc-l2
#   controls:
#     - "AC.L2-3.1.5"
#   severity: high
#   gap: GAP-07
package compliance.iam

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_iam_role_policy"

    contains(lower(rc.change.after.policy), "\"action\":\"s3:*\"")

    msg := "GAP-07: Wildcard S3 permissions are prohibited"
}

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_iam_role_policy"

    contains(lower(rc.change.after.policy), "\"action\":\"dynamodb:*\"")

    msg := "GAP-07: Wildcard DynamoDB permissions are prohibited"
}