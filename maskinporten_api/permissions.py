import os

import requests

OKDATA_PERMISSION_API_URL = os.environ["OKDATA_PERMISSION_API_URL"]


def create_okdata_permissions(resource_name, team_name, auth_header):
    create_permissions_body = {
        "owner": {"user_id": team_name, "user_type": "team"},
        "resource_name": resource_name,
    }

    create_permissions_response = requests.post(
        f"{OKDATA_PERMISSION_API_URL}/permissions",
        json=create_permissions_body,
        headers=auth_header,
    )
    create_permissions_response.raise_for_status()

    return create_permissions_response


def get_user_permissions(bearer_token):
    res = requests.get(
        f"{OKDATA_PERMISSION_API_URL}/my_permissions",
        headers={"Authorization": f"Bearer {bearer_token}"},
        params={"resource_type": "maskinporten:client"},
    )
    res.raise_for_status()
    return res.json()


def get_user_team(team_id, bearer_token, has_role=None):
    params = {}

    if has_role:
        params["has_role"] = has_role

    res = requests.get(
        f"{OKDATA_PERMISSION_API_URL}/teams",
        headers={"Authorization": f"Bearer {bearer_token}"},
        params=params,
    )
    res.raise_for_status()
    for team in res.json():
        if team["id"] == team_id:
            return team
    return None
