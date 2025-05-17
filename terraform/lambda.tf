# Creates a Lambda function to retrieve Okta audit logs and store them in OpenSearch.

locals {
  build_dir = "${path.module}/../build"
  dist_dir  = "${path.module}/../dist"
}

# Download Python dependencies and copy to build directory
resource "null_resource" "build_lambda" {
  # Run when source changes
  triggers = {
    source_hash = filesha256("${path.module}/../src/oktalogger/main.py")
  }

  # Code from https://docs.astral.sh/uv/guides/integration/aws-lambda/#deploying-a-docker-image
  provisioner "local-exec" {
    working_dir = path.module
    command     = <<EOT
        rm -rf ${local.build_dir}
        mkdir -p ${local.build_dir}
        uv pip install \
        --no-installer-metadata \
        --no-compile-bytecode \
        --python-platform x86_64-manylinux2014 \
        --python 3.13 \
        --target ${local.build_dir} \
        -r uv.lock
        cp -r ${var.lambda_src_dir}/* ${local.build_dir}/
    EOT
  }
}


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
          "es:ESHttp*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Allow the Lambda function to write logs to CloudWatch
resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.lambda_ingest.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Zip up the source code
data "archive_file" "lambda_payload" {
  type       = "zip"
  source_dir = local.build_dir

  output_path = "${local.dist_dir}/payload.zip"
  depends_on  = [null_resource.build_lambda]
}

# Deploy the Lambda function
resource "aws_lambda_function" "okta_ingest_lambda" {
  filename         = data.archive_file.lambda_payload.output_path
  source_code_hash = data.archive_file.lambda_payload.output_base64sha256
  function_name    = "okta_audit_logs_ingest"
  role             = aws_iam_role.lambda_ingest.arn
  handler          = "main.lambda_handler"
  runtime          = "python3.13"
  timeout          = 300
  layers           = ["arn:aws:lambda:us-east-1:177933569100:layer:AWS-Parameters-and-Secrets-Lambda-Extension:17"]
  # Environment variables for the Lambda function
  environment {
    variables = {
      OKTA_HOST       = var.okta_host
      OPENSEARCH_HOST = aws_opensearch_domain.siem_poc.endpoint
      OS_REGION       = data.aws_region.current.name
      INDEX_NAME      = var.index_name
    }
  }
}

# Create a CloudWatch log group for the Lambda function
resource "aws_cloudwatch_log_group" "okta_ingest_logs" {
  name              = "/aws/lambda/${aws_lambda_function.okta_ingest_lambda.function_name}"
  retention_in_days = 14

  # Ensure the log group is created before the Lambda function
  depends_on = [aws_lambda_function.okta_ingest_lambda]
}

# Schedule the Lambda function to run every x minutes
resource "aws_cloudwatch_event_rule" "okta_poll_schedule" {
  name                = "okta-poll-schedule"
  description         = "Trigger Okta audit log ingestion every ${var.okta_polling_interval} minutes"
  schedule_expression = "rate(${var.okta_polling_interval})"
}

# Target the Lambda function
resource "aws_cloudwatch_event_target" "okta_lambda" {
  rule      = aws_cloudwatch_event_rule.okta_poll_schedule.name
  target_id = "OktaIngestLambda"
  arn       = aws_lambda_function.okta_ingest_lambda.arn
}

# Allow EventBridge to invoke the Lambda function
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.okta_ingest_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.okta_poll_schedule.arn
}