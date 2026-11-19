import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { applyDeterministicAstPatch } from "../core-engine/ast-patcher/patcher.js";
import {
  DEMO_SCENARIOS,
  activateScenarioFixtures,
  parseCloudTrailTelemetry
} from "../core-engine/scenarios.js";

const PORT = Number(process.env.PORT ?? 3000);
const TF_PATH = path.resolve("./demo-fixtures/vulnerable-iam.tf");
const TRAIL_PATH = path.resolve("./demo-fixtures/cloudtrail-sample.json");
const HTML_PATH = path.resolve("./web-ui/index.html");

let activeScenarioId = "s3-worker";
let isMcpConnected = true;

/**
 * Probes whether the FrankenGuard MCP Engine (port 4444) is active and accepting connections.
 */
async function probeMcpServer(): Promise<boolean> {
  const host =
    process.env.MCP_HOST ||
    (fs.existsSync("/.dockerenv") ? "frankenguard-engine" : "127.0.0.1");
  const port = Number(process.env.MCP_PORT || 4444);

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const done = (status: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(status);
    };

    socket.setTimeout(400);
    socket.on("connect", () => done(true));
    socket.on("timeout", () => done(false));
    socket.on("error", () => {
      if (host !== "127.0.0.1") {
        const fallback = new net.Socket();
        fallback.setTimeout(300);
        fallback.on("connect", () => {
          fallback.destroy();
          done(true);
        });
        fallback.on("error", () => {
          fallback.destroy();
          done(false);
        });
        fallback.connect(port, "127.0.0.1");
      } else {
        done(false);
      }
    });
    socket.connect(port, host);
  });
}

setInterval(async () => {
  isMcpConnected = await probeMcpServer();
}, 2500);
probeMcpServer().then((res) => {
  isMcpConnected = res;
});

/**
 * Extracts declared IAM actions from the initial vulnerable Terraform HCL string.
 */
function extractDeclaredActions(hcl: string): string[] {
  const match = hcl.match(/Action\s*=\s*\[([\s\S]*?)\]/);
  if (!match) return [];
  return Array.from(match[1].matchAll(/"([^"]+)"/g)).map((m) => m[1]);
}

/**
 * Evaluates current Terraform file state, active scenario metadata, and dynamic graph edges.
 */
function buildSystemState() {
  const scenario = DEMO_SCENARIOS[activeScenarioId] ?? DEMO_SCENARIOS["s3-worker"];
  const tfContent = fs.readFileSync(TF_PATH, "utf-8");
  const telemetry = parseCloudTrailTelemetry(TRAIL_PATH);
  const isPatched = tfContent.includes("FrankenGuardLeastPrivilege");

  const declaredActions = extractDeclaredActions(scenario.vulnerableTf);
  const escalationActions = ["iam:PassRole", "iam:*", "iam:CreateAccessKey", "iam:PutRolePolicy", "sts:AssumeRole"];
  const hasEscalation =
    !isPatched && declaredActions.some((act) => escalationActions.includes(act));
  const wildcardCount = isPatched
    ? 0
    : declaredActions.filter((a) => a.includes("*")).length + 1;

  // Build dynamic topology nodes for the Monster Anatomy SVG graph
  const graphNodes = declaredActions.map((action) => {
    const servicePrefix = action.split(":")[0];
    const matchedList = telemetry.observedActions.filter((obs) =>
      obs.startsWith(`${servicePrefix}:`)
    );
    const matchedObserved = matchedList.length > 0 ? matchedList.join(", ") : null;
    const isEscalationNode = escalationActions.includes(action);

    return {
      declaredAction: action,
      observedAction: matchedObserved ?? null,
      targetResource:
        telemetry.observedResources.find((r) => r.includes(`:${servicePrefix}:`)) ??
        telemetry.observedResources[0] ??
        "*",
      scopedSourceArn: telemetry.scopedSourceArn,
      isUsed: Boolean(matchedObserved),
      isEscalation: isEscalationNode
    };
  });

  return {
    activeScenarioId: scenario.id,
    scenarios: Object.values(DEMO_SCENARIOS).map((s) => ({ id: s.id, label: s.label })),
    roleName: scenario.roleName,
    resourceName: scenario.resourceName,
    status: isPatched ? "EXORCISED" : "VULNERABLE",
    riskScore: isPatched ? 8 : scenario.initialRiskScore,
    blastRadiusReduction: Math.round(
      ((scenario.initialRiskScore - 8) / scenario.initialRiskScore) * 100
    ),
    wildcardCount,
    privilegeEscalationRisk: hasEscalation,
    tfContent,
    initialTfContent: scenario.vulnerableTf,
    telemetry,
    graphNodes,
    mcpConnected: isMcpConnected
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

  if (
    req.method === "GET" &&
    req.url &&
    (req.url === "/logo.png" ||
      req.url === "/logo.webp" ||
      req.url === "/favicon.ico" ||
      req.url === "/tailwind.css")
  ) {
    const filename = req.url === "/favicon.ico" ? "logo.png" : req.url.slice(1);
    const filePath = path.resolve("./web-ui", filename);
    if (fs.existsSync(filePath)) {
      const ext = path.extname(filePath).toLowerCase();
      const mime =
        ext === ".webp"
          ? "image/webp"
          : ext === ".css"
            ? "text/css"
            : "image/png";
      res.writeHead(200, { "Content-Type": mime });
      res.end(fs.readFileSync(filePath, null));
      return;
    }
  }

  if (req.method === "GET" && req.url === "/api/state") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(buildSystemState()));
    return;
  }

  if (req.method === "POST" && req.url === "/api/scenario") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      try {
        const parsed = JSON.parse(body || "{}");
        const nextId = String(parsed.scenarioId || "s3-worker");
        if (DEMO_SCENARIOS[nextId]) {
          activeScenarioId = nextId;
          activateScenarioFixtures(activeScenarioId, TF_PATH, TRAIL_PATH);
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(buildSystemState()));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: (err as Error).message }));
      }
    });
    return;
  }

  if (req.method === "POST" && req.url === "/api/exorcise") {
    try {
      const scenario = DEMO_SCENARIOS[activeScenarioId] ?? DEMO_SCENARIOS["s3-worker"];
      const telemetry = parseCloudTrailTelemetry(TRAIL_PATH);
      applyDeterministicAstPatch(TF_PATH, {
        resourceName: scenario.resourceName,
        allowedActions: telemetry.observedActions,
        targetResources: telemetry.observedResources,
        conditionSourceArn: telemetry.scopedSourceArn
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
    activateScenarioFixtures(activeScenarioId, TF_PATH, TRAIL_PATH);
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
