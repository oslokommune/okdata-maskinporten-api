"""Report of the currently active Maskinporten clients in both test and prod.

Currently reported issues are:

- Clients without permissions.
- Clients without team owners.
- Teams without email address.
"""

import logging
import os
from dataclasses import dataclass
from itertools import chain

import requests
from aws_xray_sdk.core import patch_all, xray_recorder
from okdata.aws.logging import logging_wrapper
from requests.exceptions import HTTPError

from maskinporten_api.maskinporten_client import (
    MaskinportenClient,
    UnsupportedEnvironmentError,
)
from maskinporten_api.permissions import get_resource_permissions, get_team_by_name
from models import MaskinportenEnvironment
from resources.authorizer import ServiceClient, keycloak_client

patch_all()

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))

MASKINPORTEN_ENVS = [e.value for e in MaskinportenEnvironment]

# Maskinporten admin client IDs. These are not administered by us.
ADMIN_CLIENTS = [
    os.environ["MASKINPORTEN_ADMIN_CLIENT_ID_TEST"],
    os.environ["MASKINPORTEN_ADMIN_CLIENT_ID_PROD"],
]


@dataclass
class Team:
    emails: list
    clients: list


class ClientWarning(Exception):
    client: dict
    warning: str


def _client_teams(client, env):
    """Return a list of the teams with permissions on `client`.

    Raise `ClientWarning` if there's any issue with the client that we should
    be made aware of.
    """
    service_client = ServiceClient(keycloak_client())

    client_id = client["client_id"]
    client_name = client["client_name"]

    try:
        permissions = get_resource_permissions(
            f"maskinporten:client:{env}-{client_id}",
            service_client.authorization_header,
        )
    except HTTPError as e:
        if e.response.status_code == 404:
            # Special case: skip our admin clients, as these aren't
            # administered by us.
            if client_id in ADMIN_CLIENTS:
                return []

            raise ClientWarning(
                f"Klient {client_id} ({client_name}) har ingen permissions."
            )
        raise

    team_names = set(chain(*[p["teams"] for p in permissions]))

    if not team_names:
        raise ClientWarning(
            f"Klient {client_id} ({client_name}) har ingen team.",
        )

    return [
        get_team_by_name(tn, service_client.authorization_header) for tn in team_names
    ]


def _format_warnings(title, warnings):
    """Return a string with `title` and `warnings` formatted for a report."""

    if not warnings:
        return ""

    return "{}:\n{}\n{}".format(
        title,
        "-" * 80,
        "\n".join(
            [f"- {w}" for w in warnings],
        ),
    )


def _send_email(to_email, from_email, from_name, subject, html_body):
    res = requests.post(
        os.environ["EMAIL_API_URL"],
        json={
            "mottakerepost": [to_email],
            "avsenderepost": from_email,
            "avsendernavn": from_name,
            "emne": subject,
            "meldingskropp": html_body,
        },
        headers={"apikey": os.environ["EMAIL_API_KEY"]},
    )
    res.raise_for_status()
    return res


@logging_wrapper
@xray_recorder.capture("client_report")
def client_report(event, context):
    """Send a report of currently active Maskinporten client and their owners.

    TODO: Send reports to the client owners as well.
    """
    report_parts = []

    for env in MASKINPORTEN_ENVS:
        client_warnings = []
        teams = {}

        try:
            maskinporten_client = MaskinportenClient(env)
        except UnsupportedEnvironmentError:
            logging.warning(
                f"Skipping unsupported Maskinporten environment {env}",
            )
            continue

        clients = maskinporten_client.get_clients().json()
        active_clients = [c for c in clients if c["active"]]

        for client in active_clients:
            try:
                for team in _client_teams(client, env):
                    team_entry = teams.setdefault(
                        team["name"],
                        Team(team["attributes"].get("email"), []),
                    )
                    team_entry.clients.append(client)
            except ClientWarning as w:
                client_warnings.append(w)

        report_parts.extend(
            [
                _format_warnings(f"Klientadvarsler [{env}]", client_warnings),
                _format_warnings(
                    f"Teamadvarsler [{env}]",
                    [
                        f"Team {t} har ingen epostadresse."
                        for t in sorted(
                            [n for n, t in teams.items() if not t.emails],
                        )
                    ],
                ),
            ]
        )

    if report := "\n\n".join(filter(None, report_parts)):
        _send_email(
            "dataplattform@oslo.kommune.no",
            "dataplattform@oslo.kommune.no",
            "Datapatruljen",
            "Maskinporten klientrapport",
            report.replace("\n", "<br />"),
        )
    else:
        logger.info("Nothing to report!")
