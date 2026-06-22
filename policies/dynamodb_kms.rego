package compliance.dynamodb

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_dynamodb_table"

    not rc.change.after.server_side_encryption[0].enabled

    msg := "GAP-02: DynamoDB tables must have server-side encryption enabled"
}