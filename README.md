# Coding Challenge 2

The goal of this project is to poll Okta for audit logs and send them to a SIEM. The project contains Python code for a Lambda function to facilitate forwarding the logs and Terraform code to automate the infrastructure setup. 

## Set Up
1. Follow [the Okta documentation](https://developer.okta.com/docs/guides/create-an-api-token/main/) to create an Okta API token.

2. Change to the `terraform` directory and run `terraform init` to download Terraform dependencies. (See [Hashicorp docs](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) for information on installing Terraform.)

3. Run `terraform plan` to see the resources that will be created in AWS. Enter the variable values as prompted. (See [Hashicorp docs](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/aws-build) for connecting your local environment to AWS if necessary.)

