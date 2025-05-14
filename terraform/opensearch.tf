provider "aws" {
  region = "us-east-1"
}

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

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "es:*"
        Resource = "arn:aws:es:${var.region}:${data.aws_caller_identity.current.account_id}:domain/siem-poc/*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip
          }
        }
      }
    ]
  })

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
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
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  tags = {
    Environment = "rchallenge2"
  }
}

data "aws_caller_identity" "current" {}

variable "admin_password" {
  type        = string
  description = "Master user password"
  sensitive   = true
}

variable "allowed_ip" {
    type        = string
    description = "Your public IP to allow access. VPN IP recommended."
}

variable "region" {
  default = "us-east-1"
}