# Variables for configuring Lambda, Okta, and OpenSearch.

variable "okta_host" {
  type        = string
  description = "Okta domain (e.g., https://dev-123456.okta.com)"
}

variable "okta_api_token" {
  type        = string
  description = "API token for Okta"
  sensitive   = true
}

variable "os_admin_username" {
  type        = string
  description = "Master user name for OpenSearch"
  default     = "osadmin"
}

variable "os_admin_password" {
  type        = string
  description = "Master user password for OpenSearch"
  sensitive   = true
}

variable "allowed_ip_cidr" {
  type        = string
  description = "IP CIDR range to allow access to OpenSearch. Static/VPN IP recommended."
}

variable "lambda_src_dir" {
  type        = string
  description = "Directory containing the Lambda function source code"
  default     = "../src/oktalogger"
}

variable "okta_polling_interval" {
  type        = string
  description = "Polling interval for Okta audit logs (e.g., '5 minutes')"
  default     = "2 minutes"
}
