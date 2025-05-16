# Creates a Lambda function to retrieve Okta audit logs and store them in OpenSearch.

locals {
  build_dir = "${path.module}/../build"
  dist_dir = "${path.module}/../dist"
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
        uv lock
        uv export --frozen --no-dev --no-editable -o requirements.txt
        uv pip install \
        --no-installer-metadata \
        --no-compile-bytecode \
        --python-platform x86_64-manylinux2014 \
        --python 3.13 \
        --target ${local.build_dir} \
        -r requirements.txt
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
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = "*"
      }
    ]
  })
}

# Zip up the source code
data "archive_file" "lambda_payload" {
  type       = "zip"
  source_dir = local.build_dir

  output_path = "${local.dist_dir}/payload.zip"
  depends_on  = [null_resource.build_lambda]
}

# Deploy the Lambda function
resource "aws_lambda_function" "lambda_payload_dir" {
  filename         = data.archive_file.lambda_payload.output_path
  source_code_hash = data.archive_file.lambda_payload.output_base64sha256
  function_name    = "okta_audit_logs_ingest"
  role             = aws_iam_role.lambda_ingest.arn
  handler          = "main.lambda_handler"
  runtime          = "python3.13"
  environment {
    variables = {
      OKTA_HOST       = var.okta_host
      OPENSEARCH_HOST = aws_opensearch_domain.siem_poc.endpoint
      OS_REGION       = data.aws_region.current.name
      INDEX_NAME      = var.index_name
    }
  }
}
