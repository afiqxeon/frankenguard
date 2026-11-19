# 🧟‍♂️ FrankenGuard — Autonomous AWS IAM Exorcism Engine

> **Kiroween 2026 Hackathon Submission (Category: Frankenstein & Best Kiro Crew App)**  
> Stitching **AWS CloudTrail runtime telemetry**, **Kiro Multi-Agent Spec/Steering guardrails**, and **Tree-sitter HCL2 Abstract Syntax Tree (AST) surgery** into a deterministic least-privilege remediation engine.

[![Docker Compose](https://img.shields.io/badge/Docker_Compose-Zero_Host_Deps-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Kiro Steering](https://img.shields.io/badge/Kiro_Steering-Rules_1--5-8B5CF6)](.kiro/steering/aws-least-privilege.md)
[![MCP Protocol](https://img.shields.io/badge/MCP_Server-TCP_:4444-10B981)](.kiro/settings/mcp.json)
[![Tree-sitter AST](https://img.shields.io/badge/AST_Surgery-Deterministic_C++-orange)](core-engine/ast-patcher/patcher.ts)
[![UI Status](https://img.shields.io/badge/Web_UI-localhost:3000-06B6D4)](#step-1-start-the-dockerized-engine--anatomy-ui)

---

## 🎯 The Problem

Modern cloud infrastructures frequently suffer from **"Zombie Wildcard IAM Policies"** (`s3:*`, `dynamodb:*`, `iam:PassRole` on `Resource = "*"`). Asking a raw LLM to rewrite Terraform files directly via text generation introduces hallucination risks, broken HCL syntax, and unintended privilege drops.

## ⚡ How FrankenGuard Solves It

FrankenGuard eliminates non-deterministic file edits by separating **reasoning** from **code mutation**—turning dangerous wildcard policies into production-safe least-privilege code:

1. **Telemetry Auditor & Graph Analyst (`scan_iam_graph` MCP Tool):** Correlates declared Terraform permissions against actual AWS CloudTrail API call logs across single-service and multi-service workloads to isolate unused wildcards and privilege-escalation vectors.
2. **Kiro Steering & Spec Guardrails (`.kiro/steering/` & `.kiro/specs/`):** Enforces deterministic security policies (Rules 1–5)—requiring zero wildcards, severing escalation vectors (`iam:PassRole`, `iam:*`, `iam:CreateAccessKey`, `iam:PutRolePolicy`, `sts:AssumeRole`), injecting `Condition` (`ArnLike: aws:SourceArn`), and validating changes against Spec `FR-05`.
3. **Surgical HCL2 AST Patcher (`apply_ast_patch` MCP Tool):** Uses C++ `tree-sitter` and `@tree-sitter-grammars/tree-sitter-hcl` to locate the exact `policy = jsonencode(...)` AST node and replace it in-place with idiomatic Terraform HCL2—leaving surrounding blocks, comments, and formatting untouched.
4. **Monster Anatomy View (`http://localhost:3000`):** A responsive, self-contained visual dashboard featuring live 1.2s auto-sync polling, real-time MCP server connectivity telemetry (`MCP Server: Connected`), **5 selectable AWS production attack scenarios**, dynamic SVG blast-radius topology graphs (`96/100` → `8/100`, `-92%`), one-click prompt copy, and side-by-side surgical AST diffs.

---

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                         Kiro IDE / Kiro Crew                            │
│  • .kiro/steering/aws-least-privilege.md (Rules 1–5 Guardrails)         │
│  • .kiro/specs/iam-exorcism-engine/ (FR-01 to FR-05 Verification)       │
│  • .kiro/settings/mcp.json (Cross-platform TCP 4444 + Docker fallback)  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ JSON-RPC over MCP
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  Docker Compose Runtime (Zero Host Deps)                │
│                                                                         │
│  ┌─────────────────────────────────┐  ┌──────────────────────────────┐  │
│  │      frankenguard-engine        │  │       frankenguard-ui        │  │
│  │  • MCP Server (TCP :4444 bridge)│  │  • Monster Anatomy View UI   │  │
│  │  • Tree-sitter HCL2 AST Patcher │  │  • 5 AWS Production Presets  │  │
│  │  • CloudTrail Telemetry Scanner │  │  • Live 1.2s Sync & MCP Ping │  │
│  └────────────────┬────────────────┘  └──────────────┬───────────────┘  │
└───────────────────┼──────────────────────────────────┼──────────────────┘
                    └────────────────┬─────────────────┘
                                     ▼
                    demo-fixtures/vulnerable-iam.tf
```

---

## 🧪 Included Real-World AWS Attack Scenarios (`SCENARIO (5):` Selector)

Switch effortlessly between 5 curated production workloads directly from the top control bar in [http://localhost:3000](http://localhost:3000):

| Scenario Preset                          | Over-Privileged Baseline                           | Exorcised Scoped Policy                                                |  Blast Radius Reduction   |
| :--------------------------------------- | :------------------------------------------------- | :--------------------------------------------------------------------- | :-----------------------: |
| **Data Lake Invoice Worker** _(Default)_ | `s3:*`, `dynamodb:*`, `iam:PassRole`               | `s3:GetObject` on `prod-invoices-archive/*`                            | **96/100 → 8/100 (-92%)** |
| **GitHub Actions CI/CD Bot**             | `ec2:*`, `iam:*`, `sts:AssumeRole`                 | `ec2:DescribeInstances` & `ec2:RebootInstances` on target instance ARN | **98/100 → 8/100 (-92%)** |
| **Stripe Payment Webhook**               | `secretsmanager:*`, `kms:*`, `iam:CreateAccessKey` | `secretsmanager:GetSecretValue` & CMK `kms:Decrypt`                    | **94/100 → 8/100 (-91%)** |
| **GenAI Bedrock Summarizer**             | `bedrock:*`, `s3:*`, `iam:PutRolePolicy`           | `bedrock:InvokeModelWithResponseStream` & `s3:GetObject`               | **95/100 → 8/100 (-92%)** |
| **Order Fulfillment Queue Consumer**     | `sqs:*`, `sns:*`, `sts:AssumeRole`                 | Multi-action `sqs:ReceiveMessage` & `sqs:DeleteMessage`                | **92/100 → 8/100 (-91%)** |

---

## 🚀 Quick Start (Judge Evaluation Guide)

### Step 1: Start the Dockerized Engine & Anatomy UI

No Node.js, Bun, or C++ build tools are required on your host machine—everything runs inside Docker:

```bash
git clone https://github.com/afiqxeon/frankenguard.git
cd frankenguard
docker compose up -d --build
```

- **Monster Anatomy View UI**: Open [http://localhost:3000](http://localhost:3000) in your browser (starts in `VULNERABLE` state with Blast Radius Score `96/100` and live `MCP Server: Connected` telemetry in the footer).
- **MCP AST Server**: Listens persistently on `127.0.0.1:4444` (with automatic `docker exec` fallback configured in `.kiro/settings/mcp.json`).

---

### Step 2: Open in Kiro IDE / Kiro Crew

Open the `frankenguard` directory in Kiro IDE or Kiro Crew. Kiro automatically loads:

- [`.kiro/settings/mcp.json`](.kiro/settings/mcp.json) (`frankenguard-mcp` with `scan_iam_graph` and `apply_ast_patch`)
- [`.kiro/steering/aws-least-privilege.md`](.kiro/steering/aws-least-privilege.md) (Security Guardrails Rules 1–5)
- [`.kiro/specs/iam-exorcism-engine/`](.kiro/specs/iam-exorcism-engine/) (Requirements & Verification)

---

### Step 3: Trigger the Exorcism (3 Execution Paths)

Choose whichever execution path you prefer:

- **Option A (1-Click UI Copy):** Click **📋 Copy Kiro Prompt** in the guidance banner on [http://localhost:3000](http://localhost:3000) and paste it into Kiro Crew / Kiro IDE.
- **Option B (Kiro Slash Command / Quick Alias):** Type `/exorcise-iam` or `Exorcise active IAM fixture` directly in Kiro.
- **Option C (Standalone UI Mode):** Click **⚡ Execute AST Exorcism** next to the scenario selector in [http://localhost:3000](http://localhost:3000) to run the Tree-sitter AST patcher directly.

#### Universal Kiro Orchestration Prompt:

```markdown
Act as the FrankenGuard Kiro Crew (Telemetry Auditor, IAM Graph Analyst, and AST Patcher).

1. Follow all guardrails in `.kiro/steering/aws-least-privilege.md` and requirements in `.kiro/specs/iam-exorcism-engine/requirements.md`.
2. Call the MCP tool `scan_iam_graph` with `tfPath: "demo-fixtures/vulnerable-iam.tf"` and `cloudtrailPath: "demo-fixtures/cloudtrail-sample.json"`.
3. Identify all unused wildcard permissions and privilege-escalation / lateral-movement vectors (such as `iam:PassRole`, `iam:*`, `iam:CreateAccessKey`, `iam:PutRolePolicy`, or `sts:AssumeRole`).
4. Call the MCP tool `apply_ast_patch` on `demo-fixtures/vulnerable-iam.tf` for resource `"overprivileged_worker"` using ONLY the observed runtime actions and target ARNs returned in step 2.
5. Summarize the blast-radius reduction achieved, and confirm Steering Rule 4 (`aws:SourceArn` Condition) and Spec FR-05 validation status from the tool report.
```

---

### Step 4: Observe Real-Time Remediation & Test Other Scenarios

1. Watch [http://localhost:3000](http://localhost:3000) automatically flash green and drop the Blast Radius Score from **96/100 to 8/100 (-92%)** via live polling—showing severed edges for unused permissions alongside a side-by-side HCL2 AST diff.
2. Once remediated, click **↺ Reset Fixture** in the top bar or switch **SCENARIO (5):** to audit and patch any of the other 4 AWS production architectures.

---

## 📁 Repository Structure

```text
├── .kiro/
│   ├── steering/aws-least-privilege.md   # Rules 1–5: Zero-wildcard & AST-only mutation guardrails
│   ├── specs/iam-exorcism-engine/        # Formal Requirements (FR-01 to FR-05) and System Design
│   ├── prompts/exorcise-iam.md           # Universal Kiro Crew orchestration workflow
│   └── settings/mcp.json                 # MCP tool definition (TCP 4444 + Docker fallback)
├── core-engine/
│   ├── ast-patcher/patcher.ts            # Tree-sitter HCL2 AST surgery engine (C++ native parser)
│   ├── scenarios.ts                      # 5 real-world AWS production attack scenarios & telemetry
│   └── node-shims.d.ts                   # Ambient TypeScript shims for Node runtime
├── demo-fixtures/
│   ├── vulnerable-iam.tf                 # Active Terraform IAM policy fixture
│   └── cloudtrail-sample.json            # Active AWS CloudTrail runtime telemetry trace
├── mcp-server/src/index.ts               # MCP Server exposing scan_iam_graph and apply_ast_patch
├── web-ui/
│   ├── index.html                        # Monster Anatomy View UI (responsive, self-contained, dynamic SVG)
│   ├── server.ts                         # Node.js backend server with live MCP ping probe
│   └── logo.png                          # Official transparent FrankenGuard mascot emblem
├── docker-compose.yml                    # Multi-container orchestration (engine + web-ui)
└── Dockerfile                            # Optimized container build with Tree-sitter C++ compilation
```

---

## 🛡️ Guardrails & Spec Compliance Matrix

| Rule / Requirement  | Description                    | Enforcement Mechanism                                                    |
| :------------------ | :----------------------------- | :----------------------------------------------------------------------- |
| **Steering Rule 1** | Zero Wildcard Policy (`*`)     | Verified by `scan_iam_graph` & rejected by AST patcher                   |
| **Steering Rule 2** | Deterministic AST Mutation     | Tree-sitter C++ AST parser modifies only `policy = jsonencode(...)` node |
| **Steering Rule 3** | Runtime Telemetry Verification | Cross-referenced against CloudTrail JSON event tuples                    |
| **Steering Rule 4** | Condition Block Injection      | Enforces `ArnLike: aws:SourceArn` on all scoped policies                 |
| **Steering Rule 5** | Quick-Trigger Alias            | Mapped to `/exorcise-iam` slash command & 1-click UI copy                |
| **FR-01 – FR-05**   | Formal Specification           | Tested & validated across all 5 production attack scenarios              |

---

## 👥 Authors & Hackathon Credits

**Taufiqurrohman** ([@afiqxeon](https://github.com/afiqxeon))  
_Full-Stack Developer & AI Automation Engineer_

Built with ❤️ for **Kiroween 2026 Hackathon**  
_Category: Frankenstein • Best Kiro Crew App_
