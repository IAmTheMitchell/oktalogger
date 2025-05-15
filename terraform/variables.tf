# Variables for configuring Lambda, Okta, and OpenSearch.

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