package compliance.iam_test

import rego.v1
import data.compliance.iam

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

mock_iam_policy(action) := {"resource_changes": [{
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%q,"Resource":"*"}]}`, [action])}},
}]}

scoped_policy := {"resource_changes": [{
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::bucket/*"}]}`}},
}]}

# ---------------------------------------------------------------------------
# GAP-07: IAM least privilege
# ---------------------------------------------------------------------------

test_scoped_s3_passes if {
	count(iam.deny) == 0 with input as scoped_policy
}

test_wildcard_s3_fails if {
	msgs := iam.deny with input as mock_iam_policy("s3:*")
	count(msgs) == 1
	some m in msgs
	contains(m, "GAP-07")
}

test_wildcard_dynamodb_fails if {
	msgs := iam.deny with input as mock_iam_policy("dynamodb:*")
	count(msgs) == 1
	some m in msgs
	contains(m, "GAP-07")
}
