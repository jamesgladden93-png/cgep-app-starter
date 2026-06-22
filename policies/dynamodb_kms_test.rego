package compliance.dynamodb_test

import rego.v1
import data.compliance.dynamodb

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

mock_dynamodb(sse_enabled) := {"resource_changes": [{
	"type": "aws_dynamodb_table",
	"change": {"after": {"server_side_encryption": [{"enabled": sse_enabled}]}},
}]}

# ---------------------------------------------------------------------------
# GAP-02: DynamoDB KMS encryption
# ---------------------------------------------------------------------------

test_dynamodb_sse_enabled_passes if {
	count(dynamodb.deny) == 0 with input as mock_dynamodb(true)
}

test_dynamodb_sse_disabled_fails if {
	msgs := dynamodb.deny with input as mock_dynamodb(false)
	count(msgs) == 1
	some m in msgs
	contains(m, "GAP-02")
}

test_no_dynamodb_resource_passes if {
	count(dynamodb.deny) == 0 with input as {"resource_changes": [{"type": "aws_vpc", "change": {"after": {}}}]}
}
