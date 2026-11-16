resource "aws_iam_role_policy" "overprivileged_worker" {
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
