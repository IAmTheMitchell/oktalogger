# Okta Logger

The goal of this project is to poll Okta for audit logs and index the logs in AWS OpenSearch. The project contains Python code for a Lambda function to facilitate forwarding the logs and Terraform code to automate the infrastructure setup. 

## Set Up
1. Follow [the Okta documentation](https://developer.okta.com/docs/guides/create-an-api-token/main/) to create an Okta API token.

1. [Download and install](https://docs.astral.sh/uv/getting-started/installation/) uv to manage Python. 

1. Change to the `terraform` directory and run `terraform init` to download Terraform dependencies. (See [Hashicorp docs](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) for information on installing Terraform.)

1. Run `terraform plan` to see the resources that will be created in AWS. Enter the variable values as prompted. (See [Hashicorp docs](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/aws-build) for connecting your local environment to AWS if necessary.)

1. If everything checks out in the plan output, run `terraform apply`. Deployment may take 20+ minutes. (Note: If deployment fails with 403 HTTP forbidden error for OpenSearch resource creation, ensure that the OpenSearch cluster is fully deployed and healthy in the AWS console, then run Terraform again.)

1. Navigate to the Lambda service in the AWS console. A new Lambda function should have been created for ingesting Okta logs. The monitor page should display invocations on a set schedule. By default, the Lambda runs every 5 minutes. This can be modified via the `okta_polling_interval` Terraform variable. Optionally, the Lambda can be manually invoked from the Test tab.

1. Navigate to the OpenSearch service in the AWS console. Clicking the link under `OpenSearch Dashboards URL (IPv4)` will take you to the OpenSearch console. Log in with the master credentials. (Default user is osadmin + the password you set.) If you have auth issues, make sure you are accessing the console from the IP you set in Terraform.

1. Optional - Run `terraform destroy` to delete all resources created by this project. **IMPORTANT** - It is the responsibility of the user to ensure that all resources were deleted. Orphaned or improperly deleted resources may result in charges to the user's 
AWS account.

## Security Detections

Terraform will configure two example security detections. Security alerts will be available in the OpenSearch dashboard under the "Alerts" page.

![An example of triggered alerts in the OpenSearch Dashboard](/docs/alerts.png)

### Okta - Unauthorized Admin Console Access Attempt

This monitor searches for Okta logs indicating that an authenticated Okta user has attempted to access the Okta admin console and been denied. 

Recommendation: Investigate recent user activity. This may be indicative of an insider threat or compromised user account attempting to elevate privileges. 

### Okta - User Added to Admin Group

This monitor searches for Okta logs indicating that a user was added to the "Admins" group. This example can be easily tweaked to monitor any desired groups. Ideally, the monitored group should be highly sensitive, and memberships should rarely change to avoid generating excess false positives.

Recommendation: Attempt to correlate the group modification with evidence of planned activity (such as a verified change request). If none found, investigate recent activity for both users. This may be indicative of insider threat, misconfiguration, and/or privilege escalation. 

### Adding Additional Security Detections

`terraform/detections.tf` can be modified to include additional security detections. Detections are created using the `opensearch_monitor` resource and are built in JSON format. 

## Architecture

![A Mermaid diagram of the project architecture.](/docs/architecture.png)

### Overview
The Lambda function begins by retrieving the Okta API token from AWS Secrets Manager. An IAM role is utilized to allow for passwordless authentication to Secrets Manager. The function then queries OpenSearch for the last indexed Okta audit log. Next, the function polls logs from the Okta API, using the time of the last indexed log as the starting period for the poll. Finally, the new audit logs are sent to OpenSearch and indexed.

### Components

#### Terraform
Terraform is used to manage all services and infrastructure for this project. This allows for automated deployment, drift correction, and tear-down.

#### AWS Lambda
Lambda provides compute to run the Python script that polls and indexes the Okta logs. Thanks to the serverless architecture of Lambda, maintenance is minimal and no specific infrastucture has to be provisioned. AWS handles infrastructure scaling, maintenance, and updates. 

#### AWS Secrets Manager
Secrets, such as the OpenSearch credentials and Okta API token, are stored in the AWS Secrets Manager. Credentials can be rotated and updated with Terraform, and the Lambda function will automatically retrieve the latest credentials.

#### AWS Parameters and Secrets Lambda Extension
The AWS Parameters and Secrets Lambda Extension was used instead of the typical boto3 client method because it supports caching. This allows for faster secrets retrieval and lower costs by reducing the number of calls to AWS Secrets Manager.

[Official AWS Documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html)

#### AWS OpenSearch
OpenSearch is used as the SIEM platform to index, search, and alert on the Okta audit logs.

## Troubleshooting

### Lambda Logging and Errors
Terraform will automatically configure a CloudWatch log group for the Lambda function. In the AWS console, navigate to the CloudWatch service, then Logs -> Log groups. The corresponding log streams will contain logs from Lambda invocations in the past 14 days. This can be helpful for troubleshooting errors.

### Running Code Locally
`src/main.py` is designed to run both in AWS Lambda and locally on a dev machine. When running locally, set the following environment variables in your terminal:
```
export OKTA_HOST=your_value_here
export OKTA_API_TOKEN=your_value_here
export OPENSEARCH_HOST=your_value_here
export AWS_REGION=your_value_here
export INDEX_NAME=your_value_here
export OPENSEARCH_USERNAME=your_value_here
export OPENSEARCH_PASSWORD=your_value_here
```

### OpenSearch Failures
Running OpenSearch with minimal resources can lead to strange issues. Be sure to follow best practices and recommendations when provisioning an OpenSearch cluster for production. `opensearch.tf` can be modified to change cluster attributes.

If OpenSearch becomes unresponsive (unfortunately common when under-provisioned), Terraform may fail with errors due to being unable to update the state of internal OpenSearch resources. The solution is to either fix OpenSearch manually, remove the state of the broken Terraform resources manually (`terraform state rm resource_here`), or destroy all infrastructure with `terraform destroy -refresh=false`.

Again, if using OpenSearch for more than a proof of concept, be sure to follow best practices when provisioning. 

## Future Enhancements

### Migrate from User/Pass Auth
It is highly recommended to disable user/pass authentication for OpenSearch if using this in production. User/pass is BASIC auth and does not implement MFA. This makes it susceptible to brute force or simple login if an attacker has obtained leaked credentials. (Limiting the console to an IP range is used as a mitigating control for this PoC.) SAML, AWS Cognito, or another more robust auth solution should be used in production.

### Send Logs in Bulk
It would be better to send the logs to OpenSearch in bulk. Theoretically this is possible with the below code:

```Python
    # String to hold the formatted logs
    bulk_string = ""

    # Index the logs
    for log in data:
        # Add index wrapper to the log
        wrapped_log = {"index": log}

        # Convert the log to a JSON string
        json_string = json.dumps(wrapped_log)

        # Add log to string for bulk indexing
        bulk_string += json_string

    client.bulk(bulk_string)
```

However, OpenSearch returns a 400 error – Perhaps the bulk operation does not support nested objects. Further investigation is required. 

### Page Through Okta Logs

By default, Okta returns a maximum of 100 logs per API call. If there are more than 100 logs to be processed, it will take multiple function invocations to collect all the logs. A better solution would be to page through all the available logs and process in a single invocation. 

### Fix Unnecessary Terraform Refresh of Detections

Terraform replaces the OpenSearch detections each run due to processing that happens around the detections/monitors after creation. Lifecycle rules could be instituted to correct this behavior. 

### Add CI/CD and Tests
CI/CD to deploy the code and run automated tests would improve efficiency and reduce the risk of human error.