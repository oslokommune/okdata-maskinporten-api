"""Calculation of the waiting period for keys.

The waiting period is meant for clients that aren't pre-approved for their
team, to give us time to react before they get keys.
"""

from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from dateutil.easter import easter

from maskinporten_api.util import getenv


def _holidays(year):
    """Return the Norwegian public holidays in `year`.

    Those that always fall on a weekend are left out, as weekends are
    non-working days anyway.
    """
    easter_sunday = easter(year)

    return {
        date(year, 1, 1),
        date(year, 5, 1),
        date(year, 5, 17),
        date(year, 12, 25),
        date(year, 12, 26),
        # Skjærtorsdag, langfredag, andre påskedag, Kristi himmelfartsdag,
        # andre pinsedag.
        *(easter_sunday + timedelta(days=n) for n in (-3, -2, 1, 39, 50)),
    }


def _is_working_day(day):
    return day.weekday() < 5 and day not in _holidays(day.year)


def keys_allowed_from(created):
    """Return when the waiting period ends for a client created at `created`.

    Only time on working days counts towards the waiting period, as it exists
    for someone to have the time to react.
    """
    tz = ZoneInfo(getenv("TIMEZONE"))
    now = created.astimezone(tz)
    remaining = timedelta(hours=int(getenv("KEY_WAITING_PERIOD_HOURS")))

    while True:
        next_day = datetime.combine(now.date() + timedelta(days=1), time.min, tz)

        if _is_working_day(now.date()):
            if now + remaining <= next_day:
                return now + remaining
            remaining -= next_day - now

        now = next_day
