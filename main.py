import logging
import os
from urllib.parse import urlparse

import requests
from opensearchpy import OpenSearch

okta_baseurl = os.environ.get("OKTA_BASE_URL")
okta_api_key = os.environ.get("OKTA_API_KEY")
opensearch_host = urlparse(os.environ.get("OPENSEARCH_HOST")).hostname
opensearch_username = os.environ.get("OPENSEARCH_USERNAME")
opensearch_password = os.environ.get("OPENSEARCH_PASSWORD")
aws_region = os.environ.get("AWS_REGION")
index_name = os.environ.get("INDEX_NAME")

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
    data = get_okta_logs(okta_baseurl, okta_api_key)
    logger.info(f"Retrieved {len(data)} logs from Okta")

    # Set up connection to OpenSearch
    auth = (opensearch_username, opensearch_password)

    os_client = OpenSearch(
        hosts=[{"host": opensearch_host, "port": 443}],
        http_auth=auth,
        http_compress=True,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )

    # Check that index exists
    if not os_client.indices.exists(index_name):
        # Create index if it doesn't exist
        os_client.indices.create(index=index_name)
        logger.warning(f"Index {index_name} created")

    # Index the logs
    # Limit the number of logs to 10 for this example
    data = data[:10]  # TODO: Remove this line to index all logs
    for log in data:
        # Index each log entry
        response = os_client.index(index=index_name, body=log)
        if response["result"] == "created":
            logger.info(f"Log indexed: {response['_id']}")
        else:
            logger.error(f"Failed to index log: {log['uuid']}")

    logger.info(f"Indexed {len(data)} logs into OpenSearch index {index_name}")


if __name__ == "__main__":
    main()
