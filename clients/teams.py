import os

import requests


class TeamsClient:
    @staticmethod
    def has_member(access_token: str, team_id: str, user_id: str):
        r = requests.get(
            url=f"{os.environ['TEAMS_API_URL']}/teams/{team_id}/members/{user_id}",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        return r.status_code == 200

    @staticmethod
    def has_role(access_token: str, team_id: str, role: str):
        r = requests.get(
            url=f"{os.environ['TEAMS_API_URL']}/teams/{team_id}/roles",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        return role in r.json()