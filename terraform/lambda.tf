# Creates a Lambda function to retrieve Okta audit logs and store them in OpenSearch.

# Create the Lambda execution role
resource "aws_iam_role" "lambda_ingest" {
  name = "lambda_ingest_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach policies to the role
resource "aws_iam_role_policy" "lambda_ingest_policy" {
  name = "lambda_ingest_policy"
  role = aws_iam_role.lambda_ingest.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = "*"
      }
    ]
  })
}
