package compliance.s3_tls_test

import rego.v1
import data.compliance.s3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

mock_bucket_policy(policy_json) := {"resource_changes": [{
	"type": "aws_s3_bucket_policy",
	"change": {"after": {"policy": policy_json}},
}]}

tls_deny_policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::bucket/*","arn:aws:s3:::bucket"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`

no_tls_policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`

# ---------------------------------------------------------------------------
# GAP-03: S3 TLS enforcement
# ---------------------------------------------------------------------------

test_tls_deny_present_passes if {
	count(s3.deny) == 0 with input as mock_bucket_policy(tls_deny_policy)
}

test_no_tls_deny_fails if {
	msgs := s3.deny with input as mock_bucket_policy(no_tls_policy)
	count(msgs) == 1
	some m in msgs
	contains(m, "GAP-03")
}
