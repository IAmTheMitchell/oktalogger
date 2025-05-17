# Configures OpenSearch index and security detections.

# Set up OpenSearch index
resource "opensearch_index" "log_index" {
  name          = var.index_name
  force_destroy = true

  depends_on = [aws_opensearch_domain_policy.siem_poc_policy]

  # Wait for the OpenSearch domain to become available
  provisioner "local-exec" {
    command = <<EOT
      echo "Waiting for OpenSearch domain to become available..."
      for i in {1..30}; do
        curl -s -o /dev/null -w "%%{http_code}" -u "${var.os_admin_username}:${var.os_admin_password}" "https://${aws_opensearch_domain.siem_poc.endpoint}/_cluster/health" | grep -q "200" && break
        sleep 10
      done
    EOT
  }

  lifecycle {
    ignore_changes = [mappings]
  }
}

variable "index_name" {
  description = "The name of the OpenSearch index to create"
  type        = string
  default     = "okta-logs"
}


# Monitor for logged in user attempting to access Okta Admin Console
resource "opensearch_monitor" "okta_admin_console_monitor" {
  body = <<EOF
{
  "name": "Okta - Unauthorized Admin Console Access Attempt",
  "type": "monitor",
  "enabled": true,
  "schedule": {
    "period": {
      "interval": 1,
      "unit": "MINUTES"
    }
  },
  "inputs": [{
    "search": {
      "indices": ["${opensearch_index.log_index.name}"],
      "query": {
        "size": 0,
        "query": {
          "bool": {
            "filter": [
              { "term": { "eventType.keyword": "app.generic.unauth_app_access_attempt" }},
              { "term": { "target.displayName.keyword": "Okta Admin Console" }}
            ]
          }
        }
      }
    }
  }],
  "triggers": [
    {
      "name": "Unauthorized Admin Access Attempt Alert", 
      "severity": "1",
      "condition": {
        "script": {
          "source": "ctx.results[0].hits.total.value > 0",
          "lang": "painless"
        }
      }
    }
  ]
}
EOF
}

# Monitor for user added to "Admins" group
resource "opensearch_monitor" "okta_admin_group_monitor" {
  body = <<EOF
{
  "name": "Okta - User Added to Admin Group",
  "type": "monitor",
  "enabled": true,
  "schedule": {
    "period": {
      "interval": 1,
      "unit": "MINUTES"
    }
  },
  "inputs": [{
    "search": {
      "indices": ["${opensearch_index.log_index.name}"],
      "query": {
        "size": 0,
        "query": {
          "bool": {
            "filter": [
              { "term": { "eventType.keyword": "group.user_membership.add" }},
              { "term": { "target.displayName.keyword": "Admins" }}
            ]
          }
        }
      }
    }
  }],
  "triggers": [{
    "name": "Admins Group Alert",
    "severity": "1",
    "condition": {
      "script": {
        "source": "ctx.results[0].hits.total.value > 0",
        "lang": "painless"
      }
    },
    "actions": []
  }]
}
EOF
}