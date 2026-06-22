# METADATA
# title: GAP-02 — DynamoDB tables must use customer-managed KMS encryption
# description: Enforces SC.L2-3.13.11 (FIPS-validated cryptography). Fails any plan
#   where the DynamoDB intake table does not have server-side encryption enabled.
# custom:
#   framework: cmmc-l2
#   controls:
#     - "SC.L2-3.13.10"
#   severity: high
#   gap: GAP-02
package compliance.dynamodb

import rego.v1

deny contains msg if {
    rc := input.resource_changes[_]

    rc.type == "aws_dynamodb_table"

    not rc.change.after.server_side_encryption[0].enabled

    msg := "GAP-02: DynamoDB tables must have server-side encryption enabled"
}