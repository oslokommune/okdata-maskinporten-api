import os

import requests

OKDATA_PERMISSION_API_URL = os.environ["OKDATA_PERMISSION_API_URL"]


def create_okdata_permissions(
    resource_name: str,
    owner_principal_id: str,
    auth_header: dict,
):
    service_account_prefix = "service-account-"
    if owner_principal_id.startswith(service_account_prefix):
        user_id = owner_principal_id[len(service_account_prefix) :]
        user_type = "client"
    else:
        user_type = "user"
        user_id = owner_principal_id
    create_permissions_body = {
        "owner": {"user_id": user_id, "user_type": user_type},
        "resource_name": resource_name,
    }

    create_permissions_response = requests.post(
        f"{OKDATA_PERMISSION_API_URL}/permissions",
        json=create_permissions_body,
        headers=auth_header,
    )
    create_permissions_response.raise_for_status()
