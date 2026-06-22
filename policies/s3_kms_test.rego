package compliance.s3_test

import rego.v1
import data.compliance.s3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

mock_s3_sse(algorithm) := {"resource_changes": [{
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": algorithm}}}},
}]}

# ---------------------------------------------------------------------------
# GAP-01: S3 KMS encryption
# ---------------------------------------------------------------------------

test_s3_kms_pass if {
	count(s3.deny) == 0 with input as mock_s3_sse("aws:kms")
}

test_s3_sse_s3_fails if {
	msgs := s3.deny with input as mock_s3_sse("AES256")
	count(msgs) == 1
	some m in msgs
	contains(m, "GAP-01")
}

test_no_s3_sse_resource_passes if {
	count(s3.deny) == 0 with input as {"resource_changes": [{"type": "aws_vpc", "change": {"after": {}}}]}
}
