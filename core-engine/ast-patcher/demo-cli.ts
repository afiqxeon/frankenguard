import fs from "node:fs";
import { applyDeterministicAstPatch } from "./patcher.js";

const tfPath = "./demo-fixtures/vulnerable-iam.tf";
const trailPath = "./demo-fixtures/cloudtrail-sample.json";

console.log("🧟‍♂️ [FrankenGuard] Ingesting CloudTrail runtime telemetry...");
const trailRaw = JSON.parse(fs.readFileSync(trailPath, "utf-8"));

const observedActions = new Set<string>();
const observedArns = new Set<string>();

for (const record of trailRaw.Records ?? []) {
  const service = String(record.eventSource).split(".")[0];
  observedActions.add(`${service}:${record.eventName}`);
  if (record.requestParameters?.bucketName) {
    observedArns.add(`arn:aws:s3:::${record.requestParameters.bucketName}/*`);
  }
}

console.log("🔍 [FrankenGuard] Observed Runtime Actions:", Array.from(observedActions));
console.log("🎯 [FrankenGuard] Observed Target ARNs:", Array.from(observedArns));
console.log("⚡ [FrankenGuard] Executing deterministic Tree-sitter HCL AST surgery...");

applyDeterministicAstPatch(tfPath, {
  resourceName: "overprivileged_worker",
  allowedActions: Array.from(observedActions),
  targetResources: Array.from(observedArns),
  conditionSourceArn: "arn:aws:sts::000000000000:assumed-role/prod-data-processor-role/*"
});

console.log("✅ [FrankenGuard] Exorcism complete! Run `git diff demo-fixtures/vulnerable-iam.tf` to inspect the AST patch.");
