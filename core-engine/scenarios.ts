import fs from "node:fs";
import path from "node:path";

export interface DemoScenario {
  id: string;
  label: string;
  roleName: string;
  resourceName: string;
  initialRiskScore: number;
  vulnerableTf: string;
  cloudtrailJson: Record<string, unknown>;
}

export interface AnalyzedTelemetry {
  observedActions: string[];
  observedResources: string[];
  principalArn: string;
  scopedSourceArn: string;
  eventCount: number;
}

export const DEMO_SCENARIOS: Record<string, DemoScenario> = {
  "s3-worker": {
    id: "s3-worker",
    label: "Data Lake Invoice Worker (S3 + PassRole Escalation)",
    roleName: "prod-data-processor-role",
    resourceName: "overprivileged_worker",
    initialRiskScore: 96,
    vulnerableTf: `resource "aws_iam_role_policy" "overprivileged_worker" {
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
`,
    cloudtrailJson: {
      Records: [
        {
          eventTime: "2026-11-15T10:15:00Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/prod-data-processor-role/worker-1"
          },
          eventSource: "s3.amazonaws.com",
          eventName: "GetObject",
          requestParameters: {
            bucketName: "prod-invoices-archive",
            key: "2026/inv-001.pdf"
          }
        }
      ]
    }
  },
  "cicd-deployer": {
    id: "cicd-deployer",
    label: "GitHub Actions CI/CD Bot (EC2 + Full IAM Takeover)",
    roleName: "github-actions-deployer-role",
    resourceName: "overprivileged_worker",
    initialRiskScore: 98,
    vulnerableTf: `resource "aws_iam_role_policy" "overprivileged_worker" {
  name = "frankenguard-cicd-deployer-policy"
  role = "github-actions-deployer-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ec2:*",
          "iam:*",
          "sts:AssumeRole"
        ]
        Resource = "*"
      }
    ]
  })
}
`,
    cloudtrailJson: {
      Records: [
        {
          eventTime: "2026-11-16T08:42:10Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/github-actions-deployer-role/gha-runner-42"
          },
          eventSource: "ec2.amazonaws.com",
          eventName: "DescribeInstances",
          requestParameters: {
            instanceId: "i-09a8b7c6d5e4f3210"
          }
        },
        {
          eventTime: "2026-11-16T08:42:14Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/github-actions-deployer-role/gha-runner-42"
          },
          eventSource: "ec2.amazonaws.com",
          eventName: "RebootInstances",
          requestParameters: {
            instanceId: "i-09a8b7c6d5e4f3210"
          }
        }
      ]
    }
  },
  "payment-webhook": {
    id: "payment-webhook",
    label: "Stripe Payment Webhook (Secrets + KMS Key Hijack)",
    roleName: "stripe-webhook-lambda-role",
    resourceName: "overprivileged_worker",
    initialRiskScore: 94,
    vulnerableTf: `resource "aws_iam_role_policy" "overprivileged_worker" {
  name = "frankenguard-payment-webhook-policy"
  role = "stripe-webhook-lambda-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "secretsmanager:*",
          "kms:*",
          "iam:CreateAccessKey"
        ]
        Resource = "*"
      }
    ]
  })
}
`,
    cloudtrailJson: {
      Records: [
        {
          eventTime: "2026-11-17T03:19:55Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/stripe-webhook-lambda-role/webhook-fn"
          },
          eventSource: "secretsmanager.amazonaws.com",
          eventName: "GetSecretValue",
          requestParameters: {
            secretId: "arn:aws:secretsmanager:us-east-1:987654321098:secret:prod/stripe/api-key-Xy9Z"
          }
        },
        {
          eventTime: "2026-11-17T03:19:55Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/stripe-webhook-lambda-role/webhook-fn"
          },
          eventSource: "kms.amazonaws.com",
          eventName: "Decrypt",
          requestParameters: {
            keyId: "arn:aws:kms:us-east-1:987654321098:key/1234abcd-12ab-34cd-56ef-1234567890ab"
          }
        }
      ]
    }
  },
  "bedrock-inference": {
    id: "bedrock-inference",
    label: "GenAI Bedrock Summarizer (LLM Cost & Policy Injection)",
    roleName: "genai-summarizer-service-role",
    resourceName: "overprivileged_worker",
    initialRiskScore: 95,
    vulnerableTf: `resource "aws_iam_role_policy" "overprivileged_worker" {
  name = "frankenguard-bedrock-inference-policy"
  role = "genai-summarizer-service-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "bedrock:*",
          "s3:*",
          "iam:PutRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })
}
`,
    cloudtrailJson: {
      Records: [
        {
          eventTime: "2026-11-17T11:05:20Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/genai-summarizer-service-role/ecs-task-88a"
          },
          eventSource: "s3.amazonaws.com",
          eventName: "GetObject",
          requestParameters: {
            bucketName: "prod-executive-briefs",
            key: "q4-2026-report.pdf"
          }
        },
        {
          eventTime: "2026-11-17T11:05:22Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/genai-summarizer-service-role/ecs-task-88a"
          },
          eventSource: "bedrock.amazonaws.com",
          eventName: "InvokeModelWithResponseStream",
          requestParameters: {
            modelId: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0"
          }
        }
      ]
    }
  },
  "sqs-order-consumer": {
    id: "sqs-order-consumer",
    label: "Order Fulfillment Queue Consumer (Multi-Action SQS)",
    roleName: "order-fulfillment-consumer-role",
    resourceName: "overprivileged_worker",
    initialRiskScore: 92,
    vulnerableTf: `resource "aws_iam_role_policy" "overprivileged_worker" {
  name = "frankenguard-order-consumer-policy"
  role = "order-fulfillment-consumer-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "sqs:*",
          "sns:*",
          "sts:AssumeRole"
        ]
        Resource = "*"
      }
    ]
  })
}
`,
    cloudtrailJson: {
      Records: [
        {
          eventTime: "2026-11-17T14:10:01Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/order-fulfillment-consumer-role/pod-consumer-03"
          },
          eventSource: "sqs.amazonaws.com",
          eventName: "ReceiveMessage",
          requestParameters: {
            queueUrl: "https://sqs.us-east-1.amazonaws.com/987654321098/prod-order-fulfillment-queue"
          }
        },
        {
          eventTime: "2026-11-17T14:10:03Z",
          userIdentity: {
            arn: "arn:aws:sts::987654321098:assumed-role/order-fulfillment-consumer-role/pod-consumer-03"
          },
          eventSource: "sqs.amazonaws.com",
          eventName: "DeleteMessage",
          requestParameters: {
            queueUrl: "https://sqs.us-east-1.amazonaws.com/987654321098/prod-order-fulfillment-queue"
          }
        }
      ]
    }
  }
};

/**
 * Extracts runtime API actions, target resource ARNs, and principal identity
 * across multiple AWS services from CloudTrail telemetry records.
 */
export function parseCloudTrailTelemetry(trailPath: string): AnalyzedTelemetry {
  const raw = JSON.parse(fs.readFileSync(trailPath, "utf-8"));
  const actions = new Set<string>();
  const resources = new Set<string>();
  let principalArn = "arn:aws:sts::987654321098:assumed-role/prod-data-processor-role/worker-1";

  for (const record of raw.Records ?? []) {
    const service = String(record.eventSource).split(".")[0];
    actions.add(`${service}:${record.eventName}`);

    const params = record.requestParameters ?? {};
    if (params.bucketName) {
      resources.add(`arn:aws:s3:::${params.bucketName}/*`);
    } else if (params.instanceId) {
      resources.add(`arn:aws:ec2:us-east-1:987654321098:instance/${params.instanceId}`);
    } else if (params.secretId) {
      resources.add(String(params.secretId));
    } else if (params.keyId) {
      resources.add(String(params.keyId));
    } else if (params.modelId) {
      resources.add(String(params.modelId));
    } else if (params.queueUrl) {
      const queueName = String(params.queueUrl).split("/").pop();
      resources.add(`arn:aws:sqs:us-east-1:987654321098:${queueName}`);
    }

    if (record.userIdentity?.arn) {
      principalArn = String(record.userIdentity.arn);
    }
  }

  const scopedSourceArn = principalArn.includes(":assumed-role/")
    ? principalArn.replace(/\/[^/]+$/, "/*")
    : principalArn;

  return {
    observedActions: Array.from(actions),
    observedResources: Array.from(resources),
    principalArn,
    scopedSourceArn,
    eventCount: (raw.Records ?? []).length
  };
}

/**
 * Writes the selected scenario's Terraform policy and CloudTrail log into active demo fixtures.
 */
export function activateScenarioFixtures(
  scenarioId: string,
  tfPath: string,
  trailPath: string
): DemoScenario {
  const scenario = DEMO_SCENARIOS[scenarioId] ?? DEMO_SCENARIOS["s3-worker"];
  fs.mkdirSync(path.dirname(tfPath), { recursive: true });
  fs.writeFileSync(tfPath, scenario.vulnerableTf, "utf-8");
  fs.writeFileSync(trailPath, JSON.stringify(scenario.cloudtrailJson, null, 2) + "\n", "utf-8");
  return scenario;
}
