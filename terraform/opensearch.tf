provider "aws" {
  region = "us-east-1"
}

locals {
  access_policies = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # Allow lambda to write to OpenSearch
      # {
      #   Sid       = "AllowLambdaIngest"
      #   Effect    = "Allow"
      #   Principal = { AWS = aws_iam_role.lambda_ingest.arn }
      #   Action    = "es:ESHttp*"  # TODO: Restrict to specific actions
      #   Resource  = "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_opensearch_domain.logs.domain_name}/*"
      # },

      # Allow master user to login from approved IP
      {
        Sid       = "AllowMasterUserFromIP"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "es:ESHttp*"
        Resource  = "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_opensearch_domain.siem_poc.domain_name}/*"
        Condition = {
          IpAddress = { "aws:SourceIp" = [var.allowed_ip_cidr] }
        }
      }
    ]
  })
}

resource "aws_opensearch_domain" "siem_poc" {
  domain_name    = "siem-poc"
  engine_version = "OpenSearch_2.19"

  cluster_config {
    instance_type          = "t3.small.search"
    instance_count         = 1
    zone_awareness_enabled = false
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
      master_user_name     = "osadmin"
      master_user_password = var.admin_password
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

# Attach the access policy to the OpenSearch domain separately
resource "aws_opensearch_domain_policy" "siem_poc_policy" {
  domain_name     = aws_opensearch_domain.siem_poc.domain_name
  access_policies = local.access_policies
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

variable "admin_password" {
  type        = string
  description = "Master user password"
  sensitive   = true
}

variable "allowed_ip_cidr" {
  type        = string
  description = "IP CIDR range to allow access. Static/VPN IP recommended."
}