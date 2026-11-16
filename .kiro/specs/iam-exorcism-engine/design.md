# Architecture Design: FrankenGuard

## System Components
1. **Kiro Crew Multi-Agent Layer:**
   - `Telemetry Auditor`: Extracts observed runtime actions via MCP tool `scan_iam_graph`.
   - `IAM Graph Analyst`: Evaluates policy blast radius under `.kiro/steering/aws-least-privilege.md` constraints.
   - `AST Patcher Agent`: Emits structured JSON patch directives to MCP tool `apply_ast_patch`.
2. **Custom MCP Server (`mcp-server/`):**
   - Exposes `scan_iam_graph` and `apply_ast_patch` over stdio/SSE transport.
3. **Deterministic Core Engine (`core-engine/`):**
   - Tree-sitter HCL/JSON AST rewriter guaranteeing zero syntax hallucinations.
4. **LocalStack AWS Sandbox (`docker-compose.yml`):**
   - Self-contained IAM, S3, and CloudTrail simulation environment.
