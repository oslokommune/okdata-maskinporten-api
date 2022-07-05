import os
from urllib.parse import quote

import requests


def create_okdata_permissions(resource_name, team_name, auth_header):
    create_permissions_body = {
        "owner": {"user_id": team_name, "user_type": "team"},
        "resource_name": resource_name,
    }

    create_permissions_response = requests.post(
        f"{os.environ['OKDATA_PERMISSION_API_URL']}/permissions",
        json=create_permissions_body,
        headers=auth_header,
    )
    create_permissions_response.raise_for_status()

    return create_permissions_response


def delete_okdata_permissions(resource_name, auth_header):
    res = requests.delete(
        f"{os.environ['OKDATA_PERMISSION_API_URL']}/permissions/{resource_name}",
        headers=auth_header,
    )
    res.raise_for_status()
    return res


def get_resource_permissions(resource_name, auth_header):
    res = requests.get(
        f"{os.environ['OKDATA_PERMISSION_API_URL']}/permissions/{resource_name}",
        headers=auth_header,
    )
    res.raise_for_status()
    return res.json()


def get_user_permissions(bearer_token):
    res = requests.get(
        f"{os.environ['OKDATA_PERMISSION_API_URL']}/my_permissions",
        headers={"Authorization": f"Bearer {bearer_token}"},
        params={"resource_type": "maskinporten:client"},
    )
    res.raise_for_status()
    return res.json()


# TODO: Use `okdata-sdk-python` team client for the two functions
# below. Requires a better way of calling the SDK as an already authenticated
# user (by using the access token, not requiring re-auth using
# username/password).
def get_user_team(team_id, bearer_token, has_role=None):
    params = {}

    if has_role:
        params["has_role"] = has_role

    res = requests.get(
        f"{os.environ['OKDATA_PERMISSION_API_URL']}/teams/{team_id}",
        headers={"Authorization": f"Bearer {bearer_token}"},
        params=params,
    )
    res.raise_for_status()
    return res.json()


def get_team_by_name(team_name, auth_header):
    """Return details for a team by name."""
    url = "{}/teams/name/{}".format(
        os.environ["OKDATA_PERMISSION_API_URL"], quote(team_name)
    )
    res = requests.get(url, headers=auth_header)
    res.raise_for_status()
    return res.json()
