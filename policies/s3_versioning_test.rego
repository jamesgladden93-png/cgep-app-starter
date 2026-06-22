package compliance.s3_versioning_test

import rego.v1
import data.compliance.s3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

mock_versioning(status) := {"resource_changes": [{
	"type": "aws_s3_bucket_versioning",
	"change": {"after": {"versioning_configuration": {"status": status}}},
}]}

# ---------------------------------------------------------------------------
# GAP-04: S3 versioning
# ---------------------------------------------------------------------------

test_versioning_enabled_passes if {
	count(s3.deny) == 0 with input as mock_versioning("Enabled")
}

test_versioning_suspended_fails if {
	msgs := s3.deny with input as mock_versioning("Suspended")
	count(msgs) == 1
	some m in msgs
	contains(m, "GAP-04")
}

test_versioning_disabled_fails if {
	msgs := s3.deny with input as mock_versioning("Disabled")
	count(msgs) == 1
}
