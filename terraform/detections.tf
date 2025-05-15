# Configures OpenSearch index and security detections.

# Set up OpenSearch index
resource "opensearch_index" "log_index" {
  name               = var.index_name
}

variable "index_name" {
  description = "The name of the OpenSearch index to create"
  type        = string
  default     = "okta-logs"
}
