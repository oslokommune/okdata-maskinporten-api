from dataclasses import dataclass
from unittest.mock import Mock

import pytest
import requests_mock

from maskinporten_api.maskinporten_client import (
    _is_client_error_response,
    EnvConfig,
    MaskinportenClient,
)
from resources.errors import DigdirClientErrorResponse

CLIENTS_ENDPOINT = EnvConfig("dig", "test").maskinporten_clients_endpoint


def test_is_client_error_response():
    @dataclass
    class MockResponse:
        status_code: int

    assert not _is_client_error_response(MockResponse(200))
    assert _is_client_error_response(MockResponse(400))
    assert _is_client_error_response(MockResponse(428))
    assert _is_client_error_response(MockResponse(499))
    assert not _is_client_error_response(MockResponse(500))


def test_slugify_team_name():
    assert MaskinportenClient._slugify_team_name("Datapatruljen") == "datapatruljen"
    assert MaskinportenClient._slugify_team_name("Min Side") == "min-side"
    assert (
        MaskinportenClient._slugify_team_name("Kjøremiljø og verktøy!!!")
        == "kjøremiljø-og-verktøy"
    )


def test_make_client_name(maskinporten_client):
    assert (
        maskinporten_client._make_client_name(
            "test", "Skjemautvikling", "krr", "dvd-nae-fagprosess"
        )
        == "DIG - okdata-skjemautvikling-krr-dvd-nae-fagprosess - test"
    )


def test_make_client_description():
    assert (
        MaskinportenClient._make_client_description(
            "Min side", "freg", "tjenesteprofil"
        )
        == "Freg-klient for tjenesteprofil (Min side)"
    )


def test_create_maskinporten_client_error(maskinporten_client, client_error_response):
    maskinporten_client.client.get_access_token = Mock(return_value="foobar")

    with requests_mock.Mocker(real_http=True) as rm:
        rm.post(CLIENTS_ENDPOINT, status_code=400, json=client_error_response)
        with pytest.raises(DigdirClientErrorResponse) as e:
            maskinporten_client.create_maskinporten_client(
                "test",
                "team-x",
                "krr",
                "test-integration",
                ["krr:global/digitalpost.read"],
            )
            assert str(e) == "Client errors from Digdir's API:\n- error 1\n- error 2"


def test_create_idporten_client_error(maskinporten_client, client_error_response):
    maskinporten_client.client.get_access_token = Mock(return_value="foobar")

    with requests_mock.Mocker(real_http=True) as rm:
        rm.post(CLIENTS_ENDPOINT, status_code=400, json=client_error_response)
        with pytest.raises(DigdirClientErrorResponse) as e:
            maskinporten_client.create_idporten_client(
                "test",
                "team-x",
                "krr",
                "test-integration",
                "http://example.org",
                "http://example.org",
                "http://example.org",
            )
            assert str(e) == "Client errors from Digdir's API:\n- error 1\n- error 2"
