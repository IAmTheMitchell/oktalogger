import json
import logging
import os
from urllib.parse import urlparse

import boto3
import requests
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection

OKTA_HOST = os.environ.get("OKTA_HOST")
OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST")
OS_REGION = os.environ.get("OS_REGION")
INDEX_NAME = os.environ.get("INDEX_NAME")

# Determine if running in AWS Lambda
IS_LAMBDA = os.environ.get("AWS_EXECUTION_ENV") is not None

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG if not IS_LAMBDA else logging.INFO)
logger.info("Starting Okta Logger")
logger.info(f"Running in {'AWS Lambda' if IS_LAMBDA else 'local environment'}")

# If running locally
if not IS_LAMBDA:
    # Log to the console
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Get credentials from environment variables
    OPENSEARCH_USERNAME = os.environ.get("OPENSEARCH_USERNAME")
    OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD")
    OKTA_API_TOKEN = os.environ.get("OKTA_API_TOKEN")


def get_aws_secret(secret_name):
    """Retrieve a secret from AWS Secrets Manager using Lambda Extension."""

    # Get the secrets extension HTTP port from environment variable
    secrets_extension_http_port = os.environ.get(
        "AWS_SECRETS_EXTENSION_HTTP_PORT", "2773"
    )

    # Set up headers for the request
    headers = {"X-Aws-Parameters-Secrets-Token": os.environ.get("AWS_SESSION_TOKEN")}

    secrets_extension_endpoint = (
        "http://localhost:"
        + secrets_extension_http_port
        + "/secretsmanager/get?secretId="
        + secret_name
    )

    r = requests.get(secrets_extension_endpoint, headers=headers)

    secret = json.loads(r.text)[
        "SecretString"
    ]  # load the Secrets Manager response into a Python dictionary, access the secret

    return secret


def validate_opensearch_host(host):
    """Validate the OpenSearch host URL"""
    if not host:
        logger.error("OpenSearch host is not set. Exiting.")
        raise ValueError("OpenSearch host is not set.")
    validated_host = host
    if not host.startswith(("http://", "https://")):
        validated_host = "https://" + host
    validated_host = urlparse(validated_host).hostname

    return validated_host


def get_last_run(opensearch_client):
    """Retrieve time of last indexed log in OpenSearch"""
    results = opensearch_client.search(
        index=INDEX_NAME, body={"size": 1, "sort": [{"published": {"order": "desc"}}]}
    )
    hits = results["hits"]["hits"]
    return hits[0]["_source"]["published"] if hits else "1970-01-01T00:00:00Z"


def get_okta_logs(baseurl, api_key, start_time):
    """Retrieve audit logs from Okta"""
    okta_endpoint = baseurl + "/api/v1/logs"
    headers = {"Authorization": f"SSWS {api_key}"}
    params = {
        "since": start_time,
    }
    response = requests.get(okta_endpoint, headers=headers, params=params)

    data = response.json()

    # Check for errors in Okta response
    if isinstance(data, dict) and "errorCode" in data:
        raise Exception(f"Error retrieving logs from Okta: {data['errorSummary']}")

    logger.info(f"Retrieved {len(data)} logs from Okta")
    return data


def index_logs(os_client, data):
    for log in data:
        # Index each log entry
        response = os_client.index(index=INDEX_NAME, body=log)
        if response["result"] == "created":
            logger.info(f"Log indexed: {response['_id']}")
        else:
            logger.error(f"Failed to index log: {log['uuid']}")


def main():
    """Main function to retrieve Okta logs and index them into OpenSearch"""
    # If running in AWS Lambda, get secrets from AWS Secrets Manager
    if IS_LAMBDA:
        logger.info(
            "Running in AWS Lambda, retrieving secrets from AWS Secrets Manager"
        )
        okta_api_token = get_aws_secret("okta_api_token")
    else:
        okta_api_token = OKTA_API_TOKEN

    # Set up connection to OpenSearch. Varies based on environment.
    logger.info("Setting up connection to OpenSearch host: %s", OPENSEARCH_HOST)

    # Validate OpenSearch host
    opensearch_host = validate_opensearch_host(OPENSEARCH_HOST)

    if IS_LAMBDA:
        service = "es"
        credentials = boto3.Session().get_credentials()
        auth = AWSV4SignerAuth(credentials, OS_REGION, service)

        os_client = OpenSearch(
            hosts=[{"host": opensearch_host, "port": 443}],
            http_auth=auth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            pool_maxsize=20,
        )
    else:
        auth = (OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD)

        os_client = OpenSearch(
            hosts=[{"host": opensearch_host, "port": 443}],
            http_auth=auth,
            http_compress=True,
            use_ssl=True,
            verify_certs=True,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )

    # Get the last indexed log time
    last_run = get_last_run(os_client)
    logger.info(f"Last indexed log time: {last_run}")

    # Get logs from Okta
    data = get_okta_logs(OKTA_HOST, okta_api_token, last_run)

    # Check if there are any logs to index
    if len(data) == 0:
        logger.warning("No new logs retrieved from Okta. Stopping execution.")
        return

    # Index the logs
    index_logs(os_client, data)

    logger.info(f"Indexed {len(data)} logs into OpenSearch index {INDEX_NAME}")


def lambda_handler(event, context):
    """AWS Lambda handler function"""
    main()


if __name__ == "__main__":
    main()
