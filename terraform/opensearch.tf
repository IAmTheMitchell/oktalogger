# Terraform configuration to create an OpenSearch domain with user/pass authentication and IP whitelisting.

# Create the OpenSearch domain with user/pass authentication and IP whitelisting
resource "aws_opensearch_domain" "siem_poc" {
  domain_name    = "siem-poc"
  engine_version = "OpenSearch_2.19"

  cluster_config {
    instance_type          = "t3.small.search"
    instance_count         = 2
    zone_awareness_enabled = true
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 10
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = var.os_admin_username
      master_user_password = var.os_admin_password
    }
  }

  node_to_node_encryption {
    enabled = true
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}

# Policies to control access to the OpenSearch domain.
data "aws_iam_policy_document" "opensearch_access" {
  statement {
    sid     = "AllowLambdaIngest"
    effect  = "Allow"
    actions = ["es:*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_ingest.arn]
    }
    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_opensearch_domain.siem_poc.domain_name}/*"]
  }

  statement {
    sid     = "AllowMasterUserFromIP"
    effect  = "Allow"
    actions = ["es:ESHttp*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_opensearch_domain.siem_poc.domain_name}/*"]
    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = [var.allowed_ip_cidr]
    }
  }
}

# Attach the access policy to the OpenSearch domain. Managing this separately can save large amounts of time when making updates.
resource "aws_opensearch_domain_policy" "siem_poc_policy" {
  domain_name     = aws_opensearch_domain.siem_poc.domain_name
  access_policies = data.aws_iam_policy_document.opensearch_access.json

  depends_on = [aws_opensearch_domain.siem_poc]
}

# OS role for the Lambda writer
resource "opensearch_role" "lambda_writer" {
  # This name lives only inside the cluster
  role_name   = "lambda_writer"
  description = "Write Okta audit logs from Lambda"

  cluster_permissions = [
    "cluster_composite_ops",
  ]

  index_permissions {
    index_patterns = [var.index_name]
    allowed_actions = [
      "crud",
    ]
  }

  depends_on = [aws_opensearch_domain.siem_poc]
}

# Map the Lambda’s IAM role to the OS security role
resource "opensearch_roles_mapping" "lambda_writer" {
  role_name   = opensearch_role.lambda_writer.role_name
  description = "Give lambda_ingest_role the lambda_writer privileges"

  backend_roles = [
    aws_iam_role.lambda_ingest.arn
  ]

  depends_on = [opensearch_role.lambda_writer]
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}