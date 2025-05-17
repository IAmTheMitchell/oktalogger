# Manages secrets stored in AWS Secrets Manager.

# Create the secrets
resource "aws_secretsmanager_secret" "os_admin_credentials" {
  name = "os_admin_credentials"
  recovery_window_in_days = var.secret_recovery_window
}

resource "aws_secretsmanager_secret" "okta_api_token" {
  name = "okta_api_token"
  recovery_window_in_days = var.secret_recovery_window
}

# Store OS Admin credentials
resource "aws_secretsmanager_secret_version" "os_admin_credentials" {
  secret_id = aws_secretsmanager_secret.os_admin_credentials.id
  secret_string = jsonencode({
    username = var.os_admin_username
    password = var.os_admin_password
  })
}

# Store Okta API token
resource "aws_secretsmanager_secret_version" "okta_api_token" {
  secret_id     = aws_secretsmanager_secret.okta_api_token.id
  secret_string = var.okta_api_token
}

