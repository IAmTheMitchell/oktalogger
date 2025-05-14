import os

import boto3
import requests
from opensearchpy import AWSV4SignerAuth, OpenSearch

okta_baseurl = os.environ.get("OKTA_BASE_URL")
okta_api_key = os.environ.get("OKTA_API_KEY")
opensearch_host = os.environ.get("OPENSEARCH_HOST")
aws_region = os.environ.get("AWS_REGION")


def get_okta_logs(baseurl=None, api_key=None):
    okta_endpoint = baseurl + "/api/v1/logs"

    headers = {"Authorization": f"SSWS {api_key}"}

    response = requests.get(okta_endpoint, headers=headers)

    data = response.json()
    return data


def main():
    # Get logs from Okta
    data = get_okta_logs(okta_baseurl, okta_api_key)
    print(data)

    # Set up connection to OpenSearch
    service = "es"
    credentials = boto3.Session().get_credentials()
    auth = AWSV4SignerAuth(credentials, aws_region, service)

    client = OpenSearch(
        hosts=[{"host": opensearch_host, "port": 443}],
        http_auth=auth,
        http_compress=True,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=True,
        ssl_show_warn=False,
    )

    # Check that index exists
    index_name = "okta-logs"
    if not client.indices.exists(index_name):
        # Create index if it doesn't exist
        client.indices.create(index=index_name)
        print(f"Index {index_name} created.")

    # Index the logs
    for log in data:
        pass


if __name__ == "__main__":
    main()
