from unittest.mock import Mock

import pytest
import requests_mock

from maskinporten_api.maskinporten_client import env_config, MaskinportenClient
from resources.errors import DigdirValidationErrorResponse

CLIENTS_ENDPOINT = env_config("test").maskinporten_clients_endpoint


def test_slugify_team_name():
    assert MaskinportenClient._slugify_team_name("Datapatruljen") == "datapatruljen"
    assert MaskinportenClient._slugify_team_name("Min Side") == "min-side"
    assert (
        MaskinportenClient._slugify_team_name("Kjøremiljø og verktøy!!!")
        == "kjøremiljø-og-verktøy"
    )


def test_make_client_name():
    assert (
        MaskinportenClient._make_client_name(
            "Skjemautvikling", "krr", "dvd-nae-fagprosess"
        )
        == "skjemautvikling-krr-dvd-nae-fagprosess"
    )


def test_make_client_description():
    assert (
        MaskinportenClient._make_client_description(
            "Min side", "freg", "tjenesteprofil"
        )
        == "Freg-klient for tjenesteprofil (Min side)"
    )


def test_create_maskinporten_client_validation_error(
    maskinporten_client, client_validation_error_response
):
    maskinporten_client.client.get_access_token = Mock(return_value="foobar")

    with requests_mock.Mocker(real_http=True) as rm:
        rm.post(
            CLIENTS_ENDPOINT, status_code=400, json=client_validation_error_response
        )
        with pytest.raises(DigdirValidationErrorResponse) as e:
            maskinporten_client.create_maskinporten_client(
                "team-x", "krr", "test-integration", ["krr:global/digitalpost.read"]
            )
            assert (
                str(e) == "Validation errors from Digdir's API:\n- error 1\n- error 2"
            )


def test_create_idporten_client_validation_error(
    maskinporten_client, client_validation_error_response
):
    maskinporten_client.client.get_access_token = Mock(return_value="foobar")

    with requests_mock.Mocker(real_http=True) as rm:
        rm.post(
            CLIENTS_ENDPOINT, status_code=400, json=client_validation_error_response
        )
        with pytest.raises(DigdirValidationErrorResponse) as e:
            maskinporten_client.create_idporten_client(
                "team-x",
                "krr",
                "test-integration",
                "http://example.org",
                "http://example.org",
                "http://example.org",
            )
            assert (
                str(e) == "Validation errors from Digdir's API:\n- error 1\n- error 2"
            )
