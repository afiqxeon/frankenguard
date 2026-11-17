import fs from "node:fs";
import Parser from "tree-sitter";
import HCL from "@tree-sitter-grammars/tree-sitter-hcl";

export interface PatchDirective {
  resourceName: string;
  allowedActions: string[];
  targetResources: string[];
  conditionSourceArn?: string;
}

export function applyDeterministicAstPatch(
  tfFilePath: string,
  directive: PatchDirective,
): string {
  const sourceCode = fs.readFileSync(tfFilePath, "utf-8");
  const parser = new Parser();
  parser.setLanguage(HCL as unknown as Parser.Language);

  const tree = parser.parse(sourceCode);
  let targetStartByte = -1;
  let targetEndByte = -1;

  function traverse(node: Parser.SyntaxNode) {
    if (node.type === "block") {
      const headerText = node.text.split("{")[0];
      if (
        headerText.includes(`"aws_iam_role_policy"`) &&
        headerText.includes(`"${directive.resourceName}"`)
      ) {
        // Find the policy = jsonencode(...) attribute inside this resource block.
        for (const child of node.namedChildren) {
          if (child.type === "body") {
            for (const item of child.namedChildren) {
              if (
                item.type === "attribute" &&
                item.text.trim().startsWith("policy")
              ) {
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
    throw new Error(
      `Resource aws_iam_role_policy.${directive.resourceName} tidak ditemukan dalam AST.`,
    );
  }

  const leastPrivilegePolicy: Record<string, unknown> = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "FrankenGuardLeastPrivilege",
        Effect: "Allow",
        Action: directive.allowedActions,
        Resource: directive.targetResources,
        ...(directive.conditionSourceArn
          ? {
              Condition: {
                ArnLike: {
                  "aws:SourceArn": directive.conditionSourceArn,
                },
              },
            }
          : {}),
      },
    ],
  };

  const formattedJson = JSON.stringify(leastPrivilegePolicy, null, 4)
    .split("\n")
    .map((line, idx) => (idx === 0 ? line : `  ${line}`))
    .join("\n");

  const replacement = `jsonencode(${formattedJson})`;
  const patchedCode =
    sourceCode.slice(0, targetStartByte) +
    replacement +
    sourceCode.slice(targetEndByte);

  fs.writeFileSync(tfFilePath, patchedCode, "utf-8");
  return patchedCode;
}
