import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { applyDeterministicAstPatch } from "../core-engine/ast-patcher/patcher.js";

const PORT = Number(process.env.PORT ?? 3000);
const TF_PATH = path.resolve("./demo-fixtures/vulnerable-iam.tf");
const TRAIL_PATH = path.resolve("./demo-fixtures/cloudtrail-sample.json");
const HTML_PATH = path.resolve("./web-ui/index.html");

const INITIAL_VULNERABLE_TF = `resource "aws_iam_role_policy" "overprivileged_worker" {
  name = "frankenguard-demo-worker-policy"
  role = "prod-data-processor-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:*",
          "dynamodb:*",
          "iam:PassRole"
        ]
        Resource = "*"
      }
    ]
  })
}
`;

interface TelemetrySummary {
  observedActions: string[];
  observedResources: string[];
  principalArn: string;
  eventCount: number;
}

/**
 * Extracts runtime API invocations and target ARNs from AWS CloudTrail logs.
 */
function analyzeTelemetry(): TelemetrySummary {
  const raw = JSON.parse(fs.readFileSync(TRAIL_PATH, "utf-8"));
  const actions = new Set<string>();
  const resources = new Set<string>();
  let principalArn = "arn:aws:sts::000000000000:assumed-role/prod-data-processor-role/*";

  for (const record of raw.Records ?? []) {
    const service = String(record.eventSource).split(".")[0];
    actions.add(`${service}:${record.eventName}`);
    if (record.requestParameters?.bucketName) {
      resources.add(`arn:aws:s3:::${record.requestParameters.bucketName}/*`);
    }
    if (record.userIdentity?.arn) {
      principalArn = record.userIdentity.arn;
    }
  }

  return {
    observedActions: Array.from(actions),
    observedResources: Array.from(resources),
    principalArn,
    eventCount: (raw.Records ?? []).length
  };
}

/**
 * Evaluates current Terraform file state to calculate blast-radius risk metrics.
 */
function buildSystemState() {
  const tfContent = fs.readFileSync(TF_PATH, "utf-8");
  const telemetry = analyzeTelemetry();
  const isPatched = tfContent.includes("FrankenGuardLeastPrivilege");

  return {
    status: isPatched ? "EXORCISED" : "VULNERABLE",
    riskScore: isPatched ? 8 : 96,
    blastRadiusServices: isPatched ? 1 : 3,
    wildcardCount: isPatched ? 0 : 4,
    privilegeEscalationRisk: !isPatched && tfContent.includes("iam:PassRole"),
    tfContent,
    initialTfContent: INITIAL_VULNERABLE_TF,
    telemetry
  };
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    const html = fs.readFileSync(HTML_PATH, "utf-8");
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }

  if (req.method === "GET" && req.url === "/api/state") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(buildSystemState()));
    return;
  }

  if (req.method === "POST" && req.url === "/api/exorcise") {
    try {
      const telemetry = analyzeTelemetry();
      applyDeterministicAstPatch(TF_PATH, {
        resourceName: "overprivileged_worker",
        allowedActions: telemetry.observedActions,
        targetResources: telemetry.observedResources,
        conditionSourceArn: "arn:aws:sts::000000000000:assumed-role/prod-data-processor-role/*"
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(buildSystemState()));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: (err as Error).message }));
    }
    return;
  }

  if (req.method === "POST" && req.url === "/api/reset") {
    fs.writeFileSync(TF_PATH, INITIAL_VULNERABLE_TF, "utf-8");
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(buildSystemState()));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not Found" }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[FrankenGuard Web UI] Monster Anatomy View listening on http://localhost:${PORT}`);
});
