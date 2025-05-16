import logging
import os
from urllib.parse import urlparse

import boto3
import requests
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection

OKTA_HOST = os.environ.get("OKTA_HOST")
OKTA_API_TOKEN = os.environ.get("OKTA_API_TOKEN")
OPENSEARCH_HOST = urlparse(os.environ.get("OPENSEARCH_HOST")).hostname
OPENSEARCH_USERNAME = os.environ.get("OPENSEARCH_USERNAME")
OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD")
OS_REGION = os.environ.get("OS_REGION")
INDEX_NAME = os.environ.get("INDEX_NAME")

# Determine if running in AWS Lambda
is_lambda = os.environ.get("AWS_EXECUTION_ENV") is not None

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG if not is_lambda else logging.INFO)

# If running locally, log to the console
if not is_lambda:
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def get_okta_logs(baseurl=None, api_key=None):
    """Retrieve audit logs from Okta"""
    okta_endpoint = baseurl + "/api/v1/logs"

    headers = {"Authorization": f"SSWS {api_key}"}

    response = requests.get(okta_endpoint, headers=headers)

    data = response.json()
    return data


def main():
    # Get logs from Okta
    data = get_okta_logs(OKTA_HOST, OKTA_API_TOKEN)
    if len(data) == 0:
        logger.warning("No new logs retrieved from Okta. Stopping execution.")
        return
    logger.info(f"Retrieved {len(data)} logs from Okta")

    # Set up connection to OpenSearch. Varies based on environment.
    if is_lambda:
        service = "es"
        credentials = boto3.Session().get_credentials()
        auth = AWSV4SignerAuth(credentials, OS_REGION, service)

        os_client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": 443}],
            http_auth=auth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            pool_maxsize=20,
        )
    else:
        auth = (OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD)

        os_client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": 443}],
            http_auth=auth,
            http_compress=True,
            use_ssl=True,
            verify_certs=True,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )

    # Check that index exists
    if not os_client.indices.exists(INDEX_NAME):
        # Create index if it doesn't exist
        os_client.indices.create(index=INDEX_NAME)
        logger.warning(f"Index {INDEX_NAME} created")

    # Index the logs
    # Limit the number of logs to 10 for this example
    data = data[:10]  # TODO: Remove this line to index all logs
    for log in data:
        # Index each log entry
        response = os_client.index(index=INDEX_NAME, body=log)
        if response["result"] == "created":
            logger.info(f"Log indexed: {response['_id']}")
        else:
            logger.error(f"Failed to index log: {log['uuid']}")

    logger.info(f"Indexed {len(data)} logs into OpenSearch index {INDEX_NAME}")


def lambda_handler(event, context):
    """AWS Lambda handler function"""
    main()


if __name__ == "__main__":
    main()
