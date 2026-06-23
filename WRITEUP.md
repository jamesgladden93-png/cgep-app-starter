# CGE-P Capstone Write-Up — Acme Health Patient Intake API

**Author:** James Gladden  
**Repository:** jamesgladden93-png/cgep-app-starter  
**Primary Framework:** CMMC Level 2 (NIST SP 800-171 Rev 2)  
**Date:** June 2026

---

## 1. Framework Selection and Rationale

I selected **CMMC Level 2** as the primary compliance framework. Acme Health handles PHI and is exploring federal health-IT pilots, making CMMC L2 the most defensible choice. CMMC L2 inherits the 110 practices of NIST SP 800-171 Rev 2 and maps cleanly onto every named gap in this workload.

- Encryption at rest → **SC.L2-3.13.10** (Employment of Cryptographic Mechanisms)
- Encryption in transit → **SC.L2-3.13.8** (Implement Subnetworks)
- Access enforcement / least privilege → **AC.L2-3.1.5** (Least Privilege)
- Audit logging → **AU.L2-3.3.1** (Create and Retain Audit Logs)
- System monitoring / resilience → **SI.L2-3.14.6** (Monitor Organizational Systems)
- Boundary protection → **SC.L2-3.13.1** (Boundary Protection)
- Data backup/versioning → **MP.L2-3.8.9** (Protect CUI During Transport)

---

## 2. Control-to-Code Traceability Matrix

| CMMC Practice | NIST 800-171 | Gap | Terraform Resource | Rego Policy | OSCAL control-id |
|---|---|---|---|---|---|
| SC.L2-3.13.10 | 3.13.10 | GAP-01 | `aws_kms_key.phi`, `aws_s3_bucket_server_side_encryption_configuration.uploads` | `policies/s3_kms.rego` | `sc-3.13.10` |
| SC.L2-3.13.10 | 3.13.10 | GAP-02 | `aws_dynamodb_table.intake` (server_side_encryption) | `policies/dynamodb_kms.rego` | `sc-3.13.10` |
| SC.L2-3.13.8 | 3.13.8 | GAP-03 | `aws_s3_bucket_policy.uploads_tls`, `aws_s3_bucket_policy.evidence_vault_tls` | `policies/s3_tls.rego` | `sc-3.13.8` |
| MP.L2-3.8.9 | 3.8.9 | GAP-04 | `aws_s3_bucket_versioning.uploads`, `aws_s3_bucket_versioning.evidence_vault` | `policies/s3_versioning.rego` | `mp-3.8.9` |
| AC.L2-3.1.5 | 3.1.5 | GAP-07 | `aws_iam_role_policy.lambda_inline` (scoped actions) | `policies/iam_least_privilege.rego` | `ac-3.1.5` |
| AU.L2-3.3.1 | 3.3.1 | — | `aws_cloudtrail.main`, `aws_cloudwatch_log_group.cloudtrail`, `aws_cloudwatch_metric_alarm.root_login` | — | `au-3.3.1` |
| SI.L2-3.14.6 | 3.14.6 | — | `aws_cloudwatch_metric_alarm.lambda_errors`, `aws_cloudwatch_event_rule.s3_policy_change`, `aws_cloudwatch_event_rule.iam_policy_change` | — | `si-3.14.6` |

Full OSCAL implementation: `component-definitions/acme-health-intake-api/component-definition.json`

---

## 3. Gaps Addressed


### GAP-01 — S3 PHI bucket using SSE-S3 instead of CMK (SC.L2-3.13.10)

**Layer 1 (Terraform):** `terraform/kms.tf` creates `aws_kms_key.phi` with `enable_key_rotation = true`. `terraform/s3-hardening.tf` adds `aws_s3_bucket_server_side_encryption_configuration.uploads` wiring the uploads bucket to the CMK via `kms_master_key_id`.

**Layer 2 (Rego):** `policies/s3_kms.rego` fails any plan where `sse_algorithm != "aws:kms"`.

**Layer 4 (OSCAL):** `control-id: sc-3.13.10`

### GAP-02 — DynamoDB using AWS-owned key instead of CMK (SC.L2-3.13.10)

**Layer 1 (Terraform):** `terraform/kms_permissions.tf` grants Lambda `kms:Decrypt/Encrypt/GenerateDataKey` on the CMK. `terraform/main.tf` sets `server_side_encryption { enabled = true; kms_key_arn = aws_kms_key.phi.arn }` on `aws_dynamodb_table.intake`.

**Layer 2 (Rego):** `policies/dynamodb_kms.rego` fails any plan where `server_side_encryption[0].enabled` is false.

**Layer 4 (OSCAL):** `control-id: sc-3.13.10` (same requirement as GAP-01)

### GAP-03 — S3 bucket accepts non-TLS requests (SC.L2-3.13.8)

**Layer 1 (Terraform):** `terraform/s3_tls_policy.tf` creates `aws_s3_bucket_policy.uploads_tls` with a `Deny` on `aws:SecureTransport=false` for all `s3:*` actions.

**Layer 2 (Rego):** `policies/s3_tls.rego` fails any plan where the bucket policy string does not contain `aws:securetransport`.

**Layer 4 (OSCAL):** `control-id: sc-3.13.8`

### GAP-04 — S3 bucket has no versioning (MP.L2-3.8.9)

**Layer 1 (Terraform):** `terraform/s3_versioning.tf` adds `aws_s3_bucket_versioning.uploads` with `status = "Enabled"`.

**Layer 2 (Rego):** `policies/s3_versioning.rego` fails any plan where versioning status is not `"Enabled"`.

**Layer 4 (OSCAL):** `control-id: mp-3.8.9`

### GAP-05 — Lambda not in VPC (SC.L2-3.13.1)

**Layer 1 (Terraform):** `terraform/lambda_networking.tf` creates a dedicated `aws_security_group.lambda`. `terraform/main.tf` `aws_lambda_function.intake` includes a `vpc_config` block placing the function in the VPC's public subnets with that security group.

**Layer 4 (OSCAL):** `control-id: sc-3.13.1`

*Note: This gap is addressed at Layer 1 only — no Rego policy covers it because Lambda VPC placement cannot be detected from the Terraform plan resource type alone without access to subnet ARNs.*

### GAP-06 — No DLQ, no X-Ray (SI.L2-3.14.6)

**Layer 1 (Terraform):** `terraform/lambda_resilience.tf` creates `aws_sqs_queue.lambda_dlq`. `terraform/main.tf` adds `dead_letter_config { target_arn = aws_sqs_queue.lambda_dlq.arn }` and `tracing_config { mode = "Active" }` to the Lambda. `aws_iam_role_policy.lambda_dlq` grants `sqs:SendMessage` to the execution role.

**Layer 4 (OSCAL):** `control-id: si-3.14.6`

### GAP-07 — Lambda IAM role has wildcard s3:* and dynamodb:* (AC.L2-3.1.5)

**Layer 1 (Terraform):** `aws_iam_role_policy.lambda_inline` in `main.tf` was replaced with scoped actions: `dynamodb:GetItem/PutItem/UpdateItem` and `s3:GetObject/PutObject` on specific resource ARNs only.

**Layer 2 (Rego):** `policies/iam_least_privilege.rego` fails any plan where the policy string contains `"action":"s3:*"` or `"action":"dynamodb:*"`.

**Layer 4 (OSCAL):** `control-id: ac-3.1.5`

### GAP-08 — API Gateway has no logging or throttling (AU.L2-3.3.1, SC.L2-3.13.1)

**Layer 1 (Terraform):** `terraform/api_gateway_hardening.tf` creates `aws_cloudwatch_log_group.apigw` (90-day retention). `aws_apigatewayv2_stage.default` in `main.tf` adds `access_log_settings` writing JSON-structured logs to that log group, and `default_route_settings` with `throttling_burst_limit = 100` and `throttling_rate_limit = 50`.

**Layer 4 (OSCAL):** `control-id: au-3.3.1` (logging) and `control-id: sc-3.13.1` (boundary/throttle)

---

## 4. Layer 1 — Terraform GRC Baseline

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
| `terraform/cloudtrail.tf` | Multi-region CloudTrail with CW Logs delivery |
| `terraform/monitoring.tf` | CloudWatch alarms + EventBridge drift detection rules |

`terraform/main.tf` was modified to:
- Remove duplicate `timeout` argument
- Add `dead_letter_config`, `tracing_config`, `vpc_config` to Lambda
- Add `access_log_settings` and `default_route_settings` to API GW stage
- Scope Lambda IAM role to least-privilege actions
- Add `aws_iam_role_policy.lambda_dlq` for SQS permissions

---

## 5. Layer 2 — OPA Policy Suite

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

## 6. Layer 3 — GitHub Actions Evidence Pipeline

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

## 7. Layer 4 — OSCAL Component Definition

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

## 8. Monitoring & Detection Layer

`terraform/monitoring.tf` implements real-time detection on top of the CloudTrail audit log stream:

### CloudTrail → CloudWatch Logs delivery
CloudTrail now delivers to `/aws/cloudtrail/<name>-<suffix>` via a dedicated IAM role (`cloudtrail-cw`). This enables metric filters to run against the live event stream rather than querying S3.

### CloudWatch Metric Filters + Alarms

| Alarm | Filter pattern | CMMC practice |
|---|---|---|
| `root-login-alarm` | `$.userIdentity.type = "Root"` | AU.L2-3.3.1 |
| `kms-deletion-alarm` | `ScheduleKeyDeletion` or `DisableKey` on kms.amazonaws.com | SC.L2-3.13.10 |
| `lambda-errors-alarm` | Lambda `Errors` metric > 5 over 2 periods | SI.L2-3.14.6 |

All alarms publish to `aws_sns_topic.alerts` (KMS-encrypted with the same CMK).

### EventBridge Drift Detection Rules

| Rule | Events watched | CMMC practice |
|---|---|---|
| `s3-policy-change` | `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl` | AC.L2-3.1.5 |
| `iam-policy-change` | `PutRolePolicy`, `AttachRolePolicy`, `DetachRolePolicy`, `CreatePolicyVersion` | AC.L2-3.1.5 |

Both rules route to the same SNS topic, providing near-real-time notification of IAM/S3 drift that could bypass the Rego policy gate.

### What was not done
AWS Config rules were not added — they require a Config recorder which costs ~$2/month continuously. EventBridge + CloudWatch covers the same drift surface for this sandbox workload at near-zero cost.

---

## 9. Known Gaps Not Fully Addressed

| Gap | Status | Reason |
|---|---|---|
| GAP-05 (Lambda not in VPC) | Addressed Layer 1 only | No Rego policy — VPC placement detection requires runtime ARN comparison not available in plan-time Rego |
| WAF on API Gateway | Not addressed | WAF requires ACL provisioning outside this workload's scope; documented as a known extension |
| Patient data lifecycle (deletion/export) | Not addressed | Out of scope per WORKLOAD.md |
| Multi-region failover | Not addressed | Out of scope per WORKLOAD.md |

---

## 10. Evidence Chain

The GitHub Actions pipeline uploads a `grc-evidence-<run_id>` artifact containing:

- `plan.txt` — human-readable Terraform plan
- `plan.json` — machine-readable plan (Conftest input)
- `conftest-results.json` — JSON Conftest output per namespace
- `tfsec.sarif` — tfsec static analysis results
- `trestle-validate.txt` — OSCAL validation confirmation

To verify a specific run: download the artifact from the Actions tab for run ID `<run_id>`.
