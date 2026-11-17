import fs from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { applyDeterministicAstPatch } from "../../core-engine/ast-patcher/patcher.js";

const server = new Server(
  { name: "frankenguard-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_iam_graph",
      description: "Correlate Terraform IAM policy wildcards with actual AWS CloudTrail telemetry logs.",
      inputSchema: {
        type: "object",
        properties: {
          tfPath: { type: "string" },
          cloudtrailPath: { type: "string" }
        },
        required: ["tfPath", "cloudtrailPath"]
      }
    },
    {
      name: "apply_ast_patch",
      description: "Deterministically patch Terraform IAM policies via Tree-sitter HCL AST.",
      inputSchema: {
        type: "object",
        properties: {
          tfPath: { type: "string" },
          resourceName: { type: "string" },
          allowedActions: { type: "array", items: { type: "string" } },
          targetResources: { type: "array", items: { type: "string" } }
        },
        required: ["tfPath", "resourceName", "allowedActions", "targetResources"]
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "scan_iam_graph") {
    const tfContent = fs.readFileSync(String(args?.tfPath), "utf-8");
    const trailRaw = JSON.parse(fs.readFileSync(String(args?.cloudtrailPath), "utf-8"));

    const observedActions = new Set<string>();
    const observedArns = new Set<string>();

    for (const record of trailRaw.Records ?? []) {
      const service = String(record.eventSource).split(".")[0];
      observedActions.add(`${service}:${record.eventName}`);
      if (record.requestParameters?.bucketName) {
        observedArns.add(`arn:aws:s3:::${record.requestParameters.bucketName}/*`);
      }
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              hasWildcardAction: tfContent.includes(":*") || tfContent.includes(`"*"`),
              observedActions: Array.from(observedActions),
              observedResources: Array.from(observedArns)
            },
            null,
            2
          )
        }
      ]
    };
  }

  if (name === "apply_ast_patch") {
    const patched = applyDeterministicAstPatch(String(args?.tfPath), {
      resourceName: String(args?.resourceName),
      allowedActions: (args?.allowedActions as string[]) ?? [],
      targetResources: (args?.targetResources as string[]) ?? []
    });

    return {
      content: [
        {
          type: "text",
          text: `AST Patch successfully applied to ${args?.tfPath}:\n\n${patched}`
        }
      ]
    };
  }

  throw new Error(`Unknown tool: ${name}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);
