import fs from "node:fs";
import Parser from "tree-sitter";
import HCL from "@tree-sitter-grammars/tree-sitter-hcl";

export interface PatchDirective {
  resourceName: string;
  allowedActions: string[];
  targetResources: string[];
  conditionSourceArn?: string;
}

/**
 * Formats an array or single string into idiomatic Terraform HCL2 syntax.
 */
function formatHclList(items: string[], indent: string): string {
  if (items.length === 1) {
    return `"${items[0]}"`;
  }
  const body = items.map((item) => `${indent}  "${item}",`).join("\n");
  return `[\n${body}\n${indent}]`;
}

/**
 * Parses a Terraform HCL file into a concrete syntax tree and deterministically
 * replaces only the `policy = jsonencode(...)` expression of the target IAM resource
 * using idiomatic HCL2 map assignment (`=`) while preserving surrounding blocks.
 */
export function applyDeterministicAstPatch(tfFilePath: string, directive: PatchDirective): string {
  const sourceCode = fs.readFileSync(tfFilePath, "utf-8");
  const parser = new Parser();
  parser.setLanguage(HCL as unknown as Parser.Language);

  const tree = parser.parse(sourceCode);
  let targetStartByte = -1;
  let targetEndByte = -1;

  function traverse(node: Parser.SyntaxNode): void {
    if (node.type === "block") {
      const headerText = node.text.split("{")[0];
      if (
        headerText.includes(`"aws_iam_role_policy"`) &&
        headerText.includes(`"${directive.resourceName}"`)
      ) {
        // Locate the `policy = jsonencode(...)` attribute node inside the target resource body
        for (const child of node.namedChildren) {
          if (child.type === "body") {
            for (const item of child.namedChildren) {
              if (item.type === "attribute" && item.text.trim().startsWith("policy")) {
                const expr = item.namedChildren[1];
                if (expr) {
                  targetStartByte = expr.startIndex;
                  targetEndByte = expr.endIndex;
                }
              }
            }
          }
        }
      }
    }
    for (const child of node.namedChildren) {
      traverse(child);
    }
  }

  traverse(tree.rootNode);

  if (targetStartByte === -1 || targetEndByte === -1) {
    throw new Error(`Target resource aws_iam_role_policy.${directive.resourceName} not found in HCL AST.`);
  }

  const enforcedSourceArn =
    directive.conditionSourceArn ??
    "arn:aws:sts::987654321098:assumed-role/prod-data-processor-role/*";

  const actionsHcl = directive.allowedActions.map((a) => `          "${a}"`).join(",\n");
  const resourceHcl = formatHclList(directive.targetResources, "        ");

  // Generate idiomatic HCL2 expression matching baseline formatting and Steering Rule #4
  const replacement = `jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FrankenGuardLeastPrivilege"
        Effect   = "Allow"
        Action   = [
${actionsHcl}
        ]
        Resource = ${resourceHcl}
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "${enforcedSourceArn}"
          }
        }
      }
    ]
  })`;

  const patchedCode =
    sourceCode.slice(0, targetStartByte) + replacement + sourceCode.slice(targetEndByte);

  fs.writeFileSync(tfFilePath, patchedCode, "utf-8");
  return patchedCode;
}
