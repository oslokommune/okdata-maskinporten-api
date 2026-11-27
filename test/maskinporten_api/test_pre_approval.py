from datetime import date, datetime

import pytest

from maskinporten_api.pre_approval import _holidays, keys_allowed_from


def test_holidays():
    assert _holidays(2026) == {
        date(2026, 1, 1),
        date(2026, 4, 2),
        date(2026, 4, 3),
        date(2026, 4, 6),
        date(2026, 5, 1),
        date(2026, 5, 14),
        date(2026, 5, 17),
        date(2026, 5, 25),
        date(2026, 12, 25),
        date(2026, 12, 26),
    }


@pytest.mark.parametrize(
    "created,expected",
    [
        # Tuesday to Wednesday.
        ("2026-11-24T10:00:00+01:00", "2026-11-25T10:00:00+01:00"),
        # Friday to Monday, skipping the weekend.
        ("2026-11-27T15:00:00+01:00", "2026-11-30T15:00:00+01:00"),
        # On a Saturday; the waiting period starts on Monday.
        ("2026-11-28T12:00:00+01:00", "2026-12-01T00:00:00+01:00"),
        # The evening before skjærtorsdag, skipping all of Easter.
        ("2026-04-01T20:00:00+02:00", "2026-04-07T20:00:00+02:00"),
        # Christmas Eve is a working day, but the two next days are not.
        ("2026-12-24T12:00:00+01:00", "2026-12-28T12:00:00+01:00"),
        # Into the next year, skipping New Year's Day and the weekend after it.
        ("2026-12-31T12:00:00+01:00", "2027-01-04T12:00:00+01:00"),
        # Across the weekend where daylight saving time starts.
        ("2026-03-27T15:00:00+01:00", "2026-03-30T15:00:00+02:00"),
        # Times are interpreted in the local time zone.
        ("2026-11-27T23:30:00+00:00", "2026-12-01T00:00:00+01:00"),
    ],
)
def test_keys_allowed_from(created, expected):
    assert keys_allowed_from(datetime.fromisoformat(created)) == (
        datetime.fromisoformat(expected)
    )
