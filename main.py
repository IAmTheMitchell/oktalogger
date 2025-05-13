import os

import requests


def main():
    baseurl = "https://dev-50024099-admin.okta.com"
    endpoint = baseurl + "/api/v1/logs"

    api_key = os.environ.get("OKTA_API_KEY")

    headers = {"Authorization": f"SSWS {api_key}"}

    response = requests.get(endpoint, headers=headers)

    data = response.json()
    print(data)


if __name__ == "__main__":
    main()
