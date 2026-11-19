# AWS IAM & Terraform Security Steering Guardrails

## Core Rules
1. **Zero Wildcard Policy:** Never allow `"*"` in IAM `Action` or `Resource` attributes unless explicitly scoped to a read-only metadata namespace.
2. **Deterministic AST Modification:** Never rewrite entire `.tf` files using raw LLM string generation. Always output structured JSON patch directives (`resource_name`, `removed_actions`, `allowed_actions`, `target_arn`) executed by the Tree-sitter HCL AST patcher.
3. **Runtime Telemetry Verification:** Every proposed IAM policy patch must cross-reference actual observed API calls from AWS CloudTrail logs before removing or scoping permissions.
4. **Condition Enforcement:** Require `aws:SourceArn` or `aws:PrincipalAccount` condition blocks on cross-service assume-role trust policies.

## Rule 5: Quick-Trigger Alias
- When the user says `"Exorcise active IAM fixture"` or invokes `/exorcise-iam`, automatically execute the complete 5-step audit and AST patch workflow defined in `.kiro/prompts/exorcise-iam.md` against `demo-fixtures/vulnerable-iam.tf` and `demo-fixtures/cloudtrail-sample.json` for resource `"overprivileged_worker"`.
