import os

import jwt
from freezegun import freeze_time

from maskinporten_api.jwt_client import JWTAuthClient
from test.mock_utils import mock_access_token_generation_requests


def test_jwt_generator_jws_headers(jwt_generator):
    assert jwt_generator._jws_headers() == {
        "x5c": [
            "MIIDBzCCAe+gAwIBAgIUfpZGrg6xU6DVaahvoPXI6N7foqMwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UECgwHVGVzdGluZzAgFw0yMTA5MDMwODM2MTBaGA8yMjk1MDYxOTA4MzYxMFowEjEQMA4GA1UECgwHVGVzdGluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALKyPcIn23gQtWsGZcm29d1gtvuvJudKYau9wbymxzi126R37IG/PvDX5pzrt4xYm7us7FwMtvyRlH4D5nQcf6MqJjAXLoVltHF3HaUkC99nJP5FLUDYDuGRQ/67t3FQWhNsZpxOLkXJqlnGmxIKlb7xWFoSaqdZHpqeF3e+yvlstlb9an906422Vxu33ns4P+DUEipFJaCJIfv5N7gWOfYpOsBI42IZ3HUJssbPy99PzPZaIIzxh+b4Mpom0T1Dvhk7NqsaJS5rSQgsdx1WyisRWXn+mCoQxtYzrg/O9RTpnRs9lkZCzUMpCHrG5XTmPZUZgHjRyjtn/k30+le7pIMCAwEAAaNTMFEwHQYDVR0OBBYEFFIX29MgBf/SgpiPbVJ0SVbTluaCMB8GA1UdIwQYMBaAFFIX29MgBf/SgpiPbVJ0SVbTluaCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHxpjsP4WyxkhGOgBxVyISs29eZ58DDFdiZsK58AKPVIGkwXYM0kgKk0Q0DJYU6Kou+Kdcr7xKIr5g1K4dJiry0+jzmWd2L+0XjeijW4gl9ApSrDbs8VOQ1mb7UNgGcoPf71BTFAMNHir3WOGRYsVTOZCNXYHj/H3HgCYgb91u+MFSOeoJPIYTgZEmqAf79s1fmLRvikP+vrCfsUYWGgNw1lEQYuNX/akcsLGkdkktcK285tU6x/QU8WUjnnKngbKLFDD/HJkCGZOANCZmgJ1qjpSRQIeVSD7B6SIJVSIZo5HAJ6EGau5lxHE7KRjJeXtXpqwfm4Le3CMvV6F83XUWA="
        ],
        "alg": "RS256",
    }


@freeze_time("1970-01-01")
def test_jwt_generator_claims(jwt_generator):
    claim_1 = jwt_generator._claims("audience", ["a", "b", "c"])

    assert claim_1["aud"] == "audience"
    assert claim_1["exp"] == 120
    assert claim_1["iat"] == 0
    assert claim_1["iss"] == "foo-corp"
    assert claim_1["scope"] == "a b c"
    assert claim_1["consumer_org"] == "123"

    claim_2 = jwt_generator._claims("audience", ["a", "b", "c"])

    # Don't care about the contents of `jti`, just that it differs between two
    # instances even when passed the same input.
    assert claim_1["jti"] != claim_2["jti"]


@freeze_time("1970-01-01")
def test_jwt_generator_generate_jwt(jwt_generator):
    encoded_token = jwt_generator.generate_jwt("audience", ["a", "b", "c"])

    with open("test/data/pubkey.pem", "rb") as f:
        public_key = f.read()

    token = jwt.decode(
        encoded_token, public_key, algorithms=["RS256"], audience="audience"
    )

    assert token["aud"] == "audience"
    assert token["exp"] == 120
    assert token["iat"] == 0
    assert token["iss"] == "foo-corp"
    assert token["jti"]
    assert token["scope"] == "a b c"
    assert token["consumer_org"] == "123"


def test_jwt_auth_client_get_access_token(jwt_config, requests_mock):
    mock_access_token_generation_requests(requests_mock)

    client = JWTAuthClient(jwt_config, os.getenv("IDPORTEN_OIDC_WELLKNOWN"))
    token = client.get_access_token(["foo:bar.read"])

    assert token.access_token == "access_token"
    assert token.token_type == "Bearer"
    assert token.expires_in == 119
    assert token.scope == "foo:bar.read"
