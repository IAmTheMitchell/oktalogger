# Configures necessary providers for Terraform operations.

terraform {
  required_providers {
    opensearch = {
      source = "opensearch-project/opensearch"
      version = "2.3.1"
    }
  }
}

provider "opensearch" {
  url = "https://${aws_opensearch_domain.siem_poc.endpoint}"
  healthcheck = false
  username = var.os_admin_username
  password = var.os_admin_password
  version_ping_timeout = 120
  sign_aws_requests = false  # Necessary when using username/password
}

provider "aws" {
  region = "us-east-1"
}