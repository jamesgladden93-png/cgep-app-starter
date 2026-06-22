# CGE-P Capstone Write-Up — Acme Health Patient Intake API

**Author:** James Gladden  
**Repository:** jamesgladden93-png/cgep-app-starter  
**Primary Framework:** NIST SP 800-53 Rev 5  
**Date:** June 2026

---

## 1. Framework Selection and Rationale

I selected **NIST SP 800-53 Rev 5** as the primary compliance framework. It is the most broadly recognized federal security control catalog and provides the canonical control IDs that OSCAL tooling (Trestle) resolves against published catalog content. Acme Health handles PHI and is exploring federal pilots, making 800-53 the right anchor — HIPAA technical safeguards and CMMC L2 practices both map onto it cleanly.

- Encryption at rest → **SC-28** (Protection of Information at Rest)
- Encryption in transit → **SC-8** (Transmission Confidentiality and Integrity)
- Access enforcement / least privilege → **AC-3** (Access Enforcement)
- Audit logging → **AU-2** (Event Logging)
- System monitoring / resilience → **SI-2** (Flaw Remediation / DLQ + X-Ray)
- Boundary protection / DoS → **SC-5** (Denial of Service Protection)
- Data backup/versioning → **CP-9** (Information System Backup)

---

## 2. Gaps Addressed

### GAP-01 — S3 PHI bucket using SSE-S3 instead of CMK (SC-28)

**Layer 1 (Terraform):** `terraform/kms.tf` creates `aws_kms_key.phi` with `enable_key_rotation = true`. `terraform/s3-hardening.tf` adds `aws_s3_bucket_server_side_encryption_configuration.uploads` wiring the uploads bucket to the CMK via `kms_master_key_id`.

**Layer 2 (Rego):** `policies/s3_kms.rego` fails any plan where `sse_algorithm != "aws:kms"`.

**Layer 4 (OSCAL):** `control-id: sc-28`

### GAP-02 — DynamoDB using AWS-owned key instead of CMK (SC-28)

**Layer 1 (Terraform):** `terraform/kms_permissions.tf` grants Lambda `kms:Decrypt/Encrypt/GenerateDataKey` on the CMK. `terraform/main.tf` sets `server_side_encryption { enabled = true; kms_key_arn = aws_kms_key.phi.arn }` on `aws_dynamodb_table.intake`.

**Layer 2 (Rego):** `policies/dynamodb_kms.rego` fails any plan where `server_side_encryption[0].enabled` is false.

**Layer 4 (OSCAL):** `control-id: sc-28` (same requirement as GAP-01)

### GAP-03 — S3 bucket accepts non-TLS requests (SC-8)

**Layer 1 (Terraform):** `terraform/s3_tls_policy.tf` creates `aws_s3_bucket_policy.uploads_tls` with a `Deny` on `aws:SecureTransport=false` for all `s3:*` actions.

**Layer 2 (Rego):** `policies/s3_tls.rego` fails any plan where the bucket policy string does not contain `aws:securetransport`.

**Layer 4 (OSCAL):** `control-id: sc-8`

### GAP-04 — S3 bucket has no versioning (CP-9)

**Layer 1 (Terraform):** `terraform/s3_versioning.tf` adds `aws_s3_bucket_versioning.uploads` with `status = "Enabled"`.

**Layer 2 (Rego):** `policies/s3_versioning.rego` fails any plan where versioning status is not `"Enabled"`.

**Layer 4 (OSCAL):** `control-id: cp-9`

### GAP-05 — Lambda not in VPC (SC-5)

**Layer 1 (Terraform):** `terraform/lambda_networking.tf` creates a dedicated `aws_security_group.lambda`. `terraform/main.tf` `aws_lambda_function.intake` includes a `vpc_config` block placing the function in the VPC's public subnets with that security group.

**Layer 4 (OSCAL):** `control-id: sc-5` (boundary protection / DoS)

*Note: This gap is addressed at Layer 1 only — no Rego policy covers it because Lambda VPC placement cannot be detected from the Terraform plan resource type alone without access to subnet ARNs.*

### GAP-06 — No DLQ, no X-Ray (SI-2)

**Layer 1 (Terraform):** `terraform/lambda_resilience.tf` creates `aws_sqs_queue.lambda_dlq`. `terraform/main.tf` adds `dead_letter_config { target_arn = aws_sqs_queue.lambda_dlq.arn }` and `tracing_config { mode = "Active" }` to the Lambda. `aws_iam_role_policy.lambda_dlq` grants `sqs:SendMessage` to the execution role.

**Layer 4 (OSCAL):** `control-id: si-2`

### GAP-07 — Lambda IAM role has wildcard s3:* and dynamodb:* (AC-3)

**Layer 1 (Terraform):** `aws_iam_role_policy.lambda_inline` in `main.tf` was replaced with scoped actions: `dynamodb:GetItem/PutItem/UpdateItem` and `s3:GetObject/PutObject` on specific resource ARNs only.

**Layer 2 (Rego):** `policies/iam_least_privilege.rego` fails any plan where the policy string contains `"action":"s3:*"` or `"action":"dynamodb:*"`.

**Layer 4 (OSCAL):** `control-id: ac-3`

### GAP-08 — API Gateway has no logging or throttling (AU.L2-3.3.1, SC.L2-3.13.1)

**Layer 1 (Terraform):** `terraform/api_gateway_hardening.tf` creates `aws_cloudwatch_log_group.apigw` (90-day retention). `aws_apigatewayv2_stage.default` in `main.tf` adds `access_log_settings` writing JSON-structured logs to that log group, and `default_route_settings` with `throttling_burst_limit = 100` and `throttling_rate_limit = 50`.

**Layer 4 (OSCAL):** `control-id: au-2` (logging) and `control-id: sc-5` (throttle/boundary)

---

## 3. Layer 1 — Terraform GRC Baseline

New Terraform files added on top of the starter:

| File | Purpose |
|---|---|
| `terraform/kms.tf` | CMK for PHI encryption with key rotation |
| `terraform/kms_permissions.tf` | Lambda IAM policy for KMS operations |
| `terraform/s3-hardening.tf` | SSE-KMS on uploads bucket |
| `terraform/s3_tls_policy.tf` | Bucket policy denying non-TLS requests |
| `terraform/s3_versioning.tf` | Versioning on uploads bucket |
| `terraform/lambda_networking.tf` | Dedicated Lambda security group |
| `terraform/lambda_resilience.tf` | SQS dead-letter queue |
| `terraform/api_gateway_hardening.tf` | CloudWatch log group for API GW |
| `terraform/cloudtrail.tf` | Multi-region CloudTrail with log-file validation |

`terraform/main.tf` was modified to:
- Remove duplicate `timeout` argument
- Add `dead_letter_config`, `tracing_config`, `vpc_config` to Lambda
- Add `access_log_settings` and `default_route_settings` to API GW stage
- Scope Lambda IAM role to least-privilege actions
- Add `aws_iam_role_policy.lambda_dlq` for SQS permissions

---

## 4. Layer 2 — OPA Policy Suite

Five Rego policies in `policies/`, each with OPA METADATA annotations:

| Policy | Package | Gap | CMMC Practice |
|---|---|---|---|
| `s3_kms.rego` | `compliance.s3` | GAP-01 | SC.L2-3.13.11 |
| `dynamodb_kms.rego` | `compliance.dynamodb` | GAP-02 | SC.L2-3.13.11 |
| `s3_tls.rego` | `compliance.s3` | GAP-03 | SC.L2-3.13.8 |
| `s3_versioning.rego` | `compliance.s3` | GAP-04 | MP.L2-3.8.9 |
| `iam_least_privilege.rego` | `compliance.iam` | GAP-07 | AC.L2-3.1.5 |

All policies use `import rego.v1` syntax. Each has a corresponding `_test.rego` file exercised with `opa test ./policies`. All 14 unit tests pass.

Run: `opa test ./policies -v`

---

## 5. Layer 3 — GitHub Actions Evidence Pipeline

`.github/workflows/grc-gate.yml` runs on every PR to `main`:

1. **AWS OIDC authentication** via `aws-actions/configure-aws-credentials@v4`
2. **`terraform init` + `validate` + `plan`** — plan output written to `evidence/plan.txt`
3. **`terraform show -json tfplan > plan.json`** — structured plan for policy evaluation
4. **Conftest gate** — `conftest test --policy policies --all-namespaces --output=json plan.json` — exits 1 on any failure
5. **tfsec SARIF scan** — gates on `warning`/`error` level findings
6. **Trestle validate** — OSCAL component definition validated in-pipeline, output captured to `evidence/trestle-validate.txt`
7. **Evidence artifact upload** — all evidence files retained 90 days as `grc-evidence-<run_id>`

A **green PR** demonstrates all gates pass on compliant Terraform. A **red PR** can be simulated by opening a branch that removes SSE-KMS from the uploads bucket — the Conftest step will fail with `GAP-01: S3 buckets storing PHI must use customer-managed KMS encryption`.

---

## 6. Layer 4 — OSCAL Component Definition

`component-definitions/acme-health-intake-api/component-definition.json`

- **Framework catalog source:** NIST SP 800-171 Rev 2 (CMMC L2 basis)
- **Component type:** `software`
- **7 implemented requirements** covering all addressed gaps
- Validated with `trestle validate` (exit 0)

Each `implemented-requirement` includes:
- `cmmc-practice` prop with the human-readable practice ID (e.g., `SC.L2-3.13.11`)
- `terraform-resource` props linking to specific Terraform resources
- `opa-policy` props linking to the enforcing Rego file where applicable
- `implementation-status: implemented`

---

## 7. Known Gaps Not Fully Addressed

| Gap | Status | Reason |
|---|---|---|
| GAP-05 (Lambda not in VPC) | Addressed Layer 1 only | No Rego policy — VPC placement detection requires runtime ARN comparison not available in plan-time Rego |
| WAF on API Gateway | Not addressed | WAF requires ACL provisioning outside this workload's scope; documented as a known extension |
| Patient data lifecycle (deletion/export) | Not addressed | Out of scope per WORKLOAD.md |
| Multi-region failover | Not addressed | Out of scope per WORKLOAD.md |

---

## 8. Evidence Chain

The GitHub Actions pipeline uploads a `grc-evidence-<run_id>` artifact containing:

- `plan.txt` — human-readable Terraform plan
- `plan.json` — machine-readable plan (Conftest input)
- `conftest-results.json` — JSON Conftest output per namespace
- `tfsec.sarif` — tfsec static analysis results
- `trestle-validate.txt` — OSCAL validation confirmation

To verify a specific run: download the artifact from the Actions tab for run ID `<run_id>`.
