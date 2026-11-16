# Requirements Specification: FrankenGuard IAM Exorcism Engine

## 1. Overview
FrankenGuard autonomously audits over-privileged AWS IAM policies defined in Terraform (`.tf`) files against actual runtime CloudTrail telemetry and applies deterministic least-privilege patches via Abstract Syntax Tree (AST) manipulation.

## 2. Functional Requirements
- **FR-01 (Telemetry Ingestion):** Ingest AWS CloudTrail JSON logs and extract unique `(principal_arn, event_source, event_name, target_resource_arn)` tuples.
- **FR-02 (Static Policy Parsing):** Parse Terraform `aws_iam_role_policy` and `aws_iam_policy` blocks to detect wildcard actions (`*`, `s3:*`, `dynamodb:*`) and wildcard resources (`*`).
- **FR-03 (Blast-Radius Correlation):** Compare declared permissions against observed runtime calls to compute unused permissions and privilege-escalation vectors (`iam:PassRole`).
- **FR-04 (Deterministic AST Surgery):** Apply JSON patch directives to `.tf` files via Tree-sitter HCL parsing without altering comments, indentation, or unrelated Terraform resources.
- **FR-05 (Local Sandbox Validation):** Verify patched policies against a containerized LocalStack AWS environment.
