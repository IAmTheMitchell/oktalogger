provider "aws" {
  region = "us-east-1"
}

# Create an IAM policy document for the OpenSearch domain access policy
# This policy allows the OpenSearchAdmin role to perform all actions on the domain
data "aws_iam_policy_document" "access_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/OpenSearchAdmin"]
    }

    actions   = ["es:*"]
    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/siem-poc/*"]
  }
}

# Create an IAM role for OpenSearch with a trust relationship to the specified IAM user
resource "aws_iam_role" "opensearch_admin" {
  name = "OpenSearchAdmin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${var.iam_user_name}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Allow user to assume the OpenSearchAdmin role
resource "aws_iam_user_policy" "assume_opensearch_admin" {
  name = "AssumeOpenSearchAdmin"
  user = var.iam_user_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/OpenSearchAdmin"
      }
    ]
  })
}

# Attach the OpenSearchAdmin policy to the OpenSearchAdmin role
resource "aws_iam_role_policy" "opensearch_admin_policy" {
  name = "OpenSearchAdminPolicy"
  role = aws_iam_role.opensearch_admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "es:*"
        Resource = "*"
      }
    ]
  })
}

# Create the OpenSearch domain
resource "aws_opensearch_domain" "siem_poc" {
  domain_name           = "siem-poc"
  engine_version        = "OpenSearch_2.19"

  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 1
    zone_awareness_enabled = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 10
  }


  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/OpenSearchAdmin"
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

  tags = {
    Environment = "rchallenge2"
  }
}

# Attach the access policy to the OpenSearch domain
resource "aws_opensearch_domain_policy" "siem_poc_policy" {
  domain_name     = aws_opensearch_domain.siem_poc.domain_name
  access_policies = data.aws_iam_policy_document.access_policy.json

  depends_on = [aws_iam_role.opensearch_admin]
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

variable "iam_user_name" {
  description = "The name of the IAM user to assume the OpenSearchAdmin role"
  type        = string
  default     = "mitchell"
}