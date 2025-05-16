# Okta Logger

The goal of this project is to poll Okta for audit logs and send them to a SIEM. The project contains Python code for a Lambda function to facilitate forwarding the logs and Terraform code to automate the infrastructure setup. 

## Set Up
1. Follow [the Okta documentation](https://developer.okta.com/docs/guides/create-an-api-token/main/) to create an Okta API token.

2. Change to the `terraform` directory and run `terraform init` to download Terraform dependencies. (See [Hashicorp docs](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) for information on installing Terraform.)

3. Run `terraform plan` to see the resources that will be created in AWS. Enter the variable values as prompted. (See [Hashicorp docs](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/aws-build) for connecting your local environment to AWS if necessary.)

4. If everything looks good, run `terraform apply`. Deployment may take 20+ minutes. (Note: If deployment fails with 403 HTTP forbidden error for OpenSearch resource creation, check that OpenSearch is fully deployed in the AWS console, then run Terraform again.)

5. Check the AWS console. Navigate to the OpenSearch service. Clicking the link under OpenSearch Dashboards URL (IPv4) will take you to the OpenSearch console. Log in with the master credentials. (Default user is osadmin + the password you set.) If you have auth issues, make sure you are accessing the console from the IP you set in Terraform.

## Design

### AWS Parameters and Secrets Lambda Extension
The AWS Parameters and Secrets Lambda Extension was used instead of the typical boto3 client method because it supports caching. This allows for faster retrieval and lower costs by reducing the amount of calls to AWS Secrets Manager.

[Official AWS Documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html)

## Common Issues

### OpenSearch Failures
Running OpenSearch with minimal resources can lead to strange issues. Be sure to follow best practices and recommendations when provisioning an OpenSearch cluster for production. `opensearch.tf` can be modified to change cluster attributes.

## Future Enhancements

### Migrate from User/Pass Auth
It is highly recommended to disable user/pass authentication for OpenSearch if using this in production. User/pass is BASIC auth and does not implement MFA. This makes it susceptible to brute force or simple login if an attacker has obtained leaked credentials. (Limiting the console to an IP range is used as a mitigating control for this PoC.) SAML, AWS Cognito, or another more robust auth solution should be used in Production.

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

However, OpenSearch returns a 400 error. Apparently the bulk operation does not support nested objects. 