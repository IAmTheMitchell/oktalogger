# Configures OpenSearch index and security detections.

# Set up OpenSearch index
resource "opensearch_index" "log_index" {
  name = var.index_name

  depends_on = [aws_opensearch_domain.siem_poc]

  lifecycle {
    ignore_changes = [mappings]
  }
}

variable "index_name" {
  description = "The name of the OpenSearch index to create"
  type        = string
  default     = "okta-logs"
}
