from maskinporten_api.maskinporten_client import MaskinportenClient


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
