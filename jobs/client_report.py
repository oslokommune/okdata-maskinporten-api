"""Sending of reports about currently active Maskinporten clients."""

import logging
import os
from dataclasses import dataclass
from itertools import chain

import requests
from aws_xray_sdk.core import patch_all, xray_recorder
from okdata.aws.logging import logging_wrapper
from okdata.aws.ssm import get_secret
from requests.exceptions import HTTPError

from maskinporten_api.auto_rotate import has_auto_rotate_enabled
from maskinporten_api.maskinporten_client import (
    MaskinportenClient,
    UnsupportedEnvironmentError,
)
from maskinporten_api.permissions import (
    client_resource_name,
    get_resource_permissions,
    get_team_by_name,
)
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


@dataclass
class ClientWarning(Exception):
    client_id: str
    client_name: str


class ClientMissingPermissionsWarning(ClientWarning):
    def __str__(self):
        return f"Klient {self.client_id} ({self.client_name}) har ingen permissions."


class ClientMissingTeamWarning(ClientWarning):
    def __str__(self):
        return f"Klient {self.client_id} ({self.client_name}) har ingen team."


@dataclass
class TeamMissingEmailWarning(Exception):
    team_name: str

    def __str__(self):
        return f"Team {self.team_name} har ingen epostadresse."

    def __eq__(self, other):
        return self.team_name == other.team_name

    def __hash__(self):
        return hash(self.team_name)


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
            client_resource_name(env, client_id),
            service_client.authorization_header,
        )
    except HTTPError as e:
        if e.response.status_code == 404:
            # Special case: skip our admin clients, as these aren't
            # administered by us.
            if client_id in ADMIN_CLIENTS:
                return []

            raise ClientMissingPermissionsWarning(client_id, client_name)
        raise

    team_names = set(chain(*[p["teams"] for p in permissions]))

    if not team_names:
        raise ClientMissingTeamWarning(client_id, client_name)

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
            sorted([f"- {w}" for w in warnings]),
        ),
    )


def _format_client(client):
    scopes = client["scopes"]
    auto_rotate = has_auto_rotate_enabled(client["client_id"], client["env"])

    return "\n".join(
        [
            f"Navn: {client['client_name']}",
            f"Beskrivelse: {client['description']}",
            f"Opprettet: {client['created'][:10]}",
            (
                f"Scope: {scopes[0] if scopes else 'ingen'}"
                if len(scopes) <= 1
                else "\n".join(["Scopes:", *[f"- {scope}" for scope in scopes]])
            ),
            f"Maskinporten-miljø: {client['env']}",
            f"Automatisk nøkkelrotering: {'Ja' if auto_rotate else 'Nei'}",
        ]
    )


def _send_email(to_emails, body):
    res = requests.post(
        os.environ["EMAIL_API_URL"],
        json={
            "mottakerepost": to_emails,
            "avsenderepost": "dataplattform@oslo.kommune.no",
            "avsendernavn": "Dataspeilet",
            "emne": "Maskinporten klientrapport",
            "meldingskropp": body.replace("\n", "<br />"),
        },
        headers={"apikey": get_secret("/dataplatform/shared/email-api-key")},
    )
    res.raise_for_status()
    return res


def _active_clients(env):
    """Return a list of active Maskinporten clients in `env`."""
    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError:
        logging.warning(
            f"Skipping unsupported Maskinporten environment {env}",
        )
        return []

    clients = maskinporten_client.get_clients().json()
    return [c for c in clients if c["active"]]


@logging_wrapper
@xray_recorder.capture("send_client_report_internal")
def send_client_report_internal(event, context):
    """Send a report to us about two kinds of errors:

    1. Maskinporten clients without any permissions or team owners.

    2. Teams without any contact email address.
    """
    report_parts = []
    team_warnings = set()

    for env in MASKINPORTEN_ENVS:
        client_warnings = []

        for client in _active_clients(env):
            try:
                for team in _client_teams(client, env):
                    if not team["attributes"].get("email"):
                        raise TeamMissingEmailWarning(team["name"])
            except ClientWarning as w:
                client_warnings.append(w)
            except TeamMissingEmailWarning as w:
                team_warnings.add(w)

        report_parts.append(
            _format_warnings(f"Klientadvarsler [{env}]", client_warnings)
        )

    report_parts.append(_format_warnings("Teamadvarsler", team_warnings))
    if report := "\n\n".join(filter(None, report_parts)):
        _send_email(["dataplattform@oslo.kommune.no"], report)
    else:
        logger.info("No errors to report!")
