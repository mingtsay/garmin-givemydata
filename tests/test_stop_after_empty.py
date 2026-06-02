"""Tests for the historical-fetch early-stop and empty-day filtering, driven by
a mocked Garmin client.

``fetch_direct_to_db`` walks backwards in yearly chunks. With
``stop_after_empty_days`` set it should stop once that many consecutive days
return no data (the void before the account existed); left unset it should walk
the whole range. In both cases the empty placeholder days Garmin returns must
never be written to the database.
"""

from datetime import date, timedelta

import pytest

from garmin_givemydata import fetch_direct_to_db

REFERENCE_TODAY = date(2026, 6, 2)


class FakeGarminClient:
    """Stand-in for GarminClient.fetch_all.

    Emits one ``daily_summary`` batch per day in each requested range. Days in
    ``data_days`` come back with real data; every other day comes back as the
    null placeholder Garmin returns for void days (all ``includes*`` flags
    false, with the ``netRemainingKilocalories: 0.0`` trap).
    """

    def __init__(self, data_days):
        self.data_days = set(data_days)
        self.calls = []  # one (start, end) tuple per fetch_all invocation

    def fetch_all(self, target_date, start_date, end_date, on_batch, known_activity_ids=None, save_raw=False):
        self.calls.append((start_date, end_date))
        d = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
        while d <= end:
            iso = d.isoformat()
            if iso in self.data_days:
                rec = {"calendarDate": iso, "includesWellnessData": True, "totalSteps": 1000}
            else:
                rec = {
                    "calendarDate": iso,
                    "includesWellnessData": False,
                    "includesActivityData": False,
                    "includesCalorieConsumedData": False,
                    "netRemainingKilocalories": 0.0,
                }
            on_batch("daily_summary", [rec], cal_date=iso)
            d += timedelta(days=1)


def _range(days_back):
    start = (REFERENCE_TODAY - timedelta(days=days_back)).isoformat()
    return start, REFERENCE_TODAY.isoformat()


def _recent_days(n):
    return [(REFERENCE_TODAY - timedelta(days=i)).isoformat() for i in range(n)]


def _row_counts(conn):
    total = conn.execute("SELECT COUNT(*) FROM daily_summary").fetchone()[0]
    empty = conn.execute("SELECT COUNT(*) FROM daily_summary WHERE total_steps IS NULL").fetchone()[0]
    return total, empty


@pytest.mark.unit
class TestStopAfterEmpty:
    def test_stops_early_after_empty_year(self, temp_db):
        # 800-day range -> 3 yearly chunks. Only the most recent 30 days have
        # data, so chunk 1 has data and chunk 2 is a full empty year.
        start, end = _range(800)
        client = FakeGarminClient(data_days=_recent_days(30))

        fetch_direct_to_db(client, temp_db, start, end, stop_after_empty_days=365)

        # Stopped after the first fully-empty chunk: chunk 3 never fetched.
        assert len(client.calls) == 2
        total, empty = _row_counts(temp_db)
        assert total == 30
        assert empty == 0  # no placeholder rows written

    def test_full_walk_when_flag_unset(self, temp_db):
        start, end = _range(800)
        client = FakeGarminClient(data_days=_recent_days(30))

        fetch_direct_to_db(client, temp_db, start, end, stop_after_empty_days=None)

        # All three chunks fetched — no early stop by default …
        assert len(client.calls) == 3
        total, empty = _row_counts(temp_db)
        # … yet empty days are still filtered out at write time.
        assert total == 30
        assert empty == 0

    def test_does_not_stop_before_threshold_met(self, temp_db):
        # A short empty gap (one ~68-day tail chunk) must not trigger a 365-day
        # stop: data spread so the final partial chunk is empty but < threshold.
        start, end = _range(800)
        # Put data in both year-chunks but leave the oldest ~68-day tail empty.
        client = FakeGarminClient(data_days=_recent_days(750))

        fetch_direct_to_db(client, temp_db, start, end, stop_after_empty_days=365)

        # Tail chunk (~68 days) is empty but under the 365 threshold -> no early
        # stop, all chunks fetched.
        assert len(client.calls) == 3
        total, empty = _row_counts(temp_db)
        assert empty == 0
        assert total == 750
