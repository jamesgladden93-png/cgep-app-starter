package compliance.iam

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_iam_role_policy"

    contains(lower(json.marshal(rc.change.after.policy)), "\"action\":\"s3:*\"")

    msg := "GAP-07: Wildcard S3 permissions are prohibited"
}

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_iam_role_policy"

    contains(lower(json.marshal(rc.change.after.policy)), "\"action\":\"dynamodb:*\"")

    msg := "GAP-07: Wildcard DynamoDB permissions are prohibited"
}