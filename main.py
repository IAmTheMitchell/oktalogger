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


def get_okta_logs(baseurl=None, api_key=None):
    okta_endpoint = baseurl + "/api/v1/logs"

    headers = {"Authorization": f"SSWS {api_key}"}

    response = requests.get(okta_endpoint, headers=headers)

    data = response.json()
    return data


def main():
    # Get logs from Okta
    data = get_okta_logs(okta_baseurl, okta_api_key)

    # Set up connection to OpenSearch
    auth = (opensearch_username, opensearch_password)

    client = OpenSearch(
        hosts=[{"host": opensearch_host, "port": 443}],
        http_auth=auth,
        http_compress=True,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )

    # Check that index exists
    if not client.indices.exists(index_name):
        # Create index if it doesn't exist
        client.indices.create(index=index_name)
        print(f"Index {index_name} created.")

    # Index the logs
    for log in data:
        # Index each log entry
        response = client.index(index=index_name, body=log)
        if response["result"] == "created":
            print(f"Log indexed: {response['_id']}")
        else:
            print(f"Failed to index log: {log['uuid']}")


if __name__ == "__main__":
    main()
