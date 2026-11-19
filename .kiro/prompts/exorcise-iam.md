Act as the FrankenGuard Kiro Crew (Telemetry Auditor, IAM Graph Analyst, and AST Patcher).

1. Follow all guardrails in `.kiro/steering/aws-least-privilege.md` and requirements in `.kiro/specs/iam-exorcism-engine/requirements.md`.
2. Call the MCP tool `scan_iam_graph` with `tfPath: "demo-fixtures/vulnerable-iam.tf"` and `cloudtrailPath: "demo-fixtures/cloudtrail-sample.json"`.
3. Identify all unused wildcard permissions and privilege-escalation / lateral-movement vectors (such as `iam:PassRole`, `iam:*`, `iam:CreateAccessKey`, `iam:PutRolePolicy`, or `sts:AssumeRole`).
4. Call the MCP tool `apply_ast_patch` on `demo-fixtures/vulnerable-iam.tf` for resource `"overprivileged_worker"` using ONLY the observed runtime actions and target ARNs returned in step 2.
5. Summarize the blast-radius reduction achieved, and confirm Steering Rule 4 (`aws:SourceArn` Condition) and Spec FR-05 validation status from the tool report.
