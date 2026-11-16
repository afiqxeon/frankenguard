# FrankenGuard 🧟‍♂️🛡️

**Autonomous AWS IAM & Terraform Exorcism Engine** built for **Kiroween 2026** (*Frankenstein* Category & *Best Kiro Crew App*).

FrankenGuard stitches together live **AWS CloudTrail** runtime telemetry, static **Terraform IAM** permission graphs, and deterministic **Tree-sitter HCL AST** surgery—orchestrated by **Kiro Crew**, **Kiro Steering**, **Kiro Specs**, and a custom **Model Context Protocol (MCP)** server.

## Architecture
- **`.kiro/specs/`**: Spec-driven requirements and system design for deterministic IAM remediation.
- **`.kiro/steering/`**: Security guardrails banning wildcard (`*`) permissions and forbidding raw LLM text replacement on `.tf` files.
- **`.kiro/hooks/`**: Automated file-save triggers validating Terraform compliance.
- **`mcp-server/`**: Custom MCP server exposing `scan_iam_graph` and `apply_ast_patch`.
- **`core-engine/`**: CloudTrail telemetry ingestor, permission blast-radius analyzer, and Tree-sitter AST patcher.
- **`demo-fixtures/`**: Vulnerable Terraform IAM policy and CloudTrail runtime trace for reproducible local testing.

## Quick Start (LocalStack Sandbox)
```bash
docker compose up -d
