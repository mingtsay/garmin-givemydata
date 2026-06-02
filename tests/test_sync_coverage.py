"""Tests for sync coverage tracking.

Each sync records the date range it covered in ``sync_log`` (``data_start`` /
``data_end``) so incremental runs can anchor on coverage rather than inferring
it from ``MAX(calendar_date)`` — which lags once empty placeholder days are no
longer written.
"""

import sqlite3

import pytest

import garmin_givemydata as ggm
from garmin_mcp.db import init_db


@pytest.mark.unit
class TestSyncLogCoverage:
    def test_migration_adds_coverage_columns(self, temp_db):
        cols = {r[1] for r in temp_db.execute("PRAGMA table_info(sync_log)")}
        assert {"data_start", "data_end"} <= cols

    def test_log_sync_records_coverage_range(self, temp_db):
        ggm._log_sync(temp_db, "test", 42, data_start="2026-01-01", data_end="2026-01-31")
        row = temp_db.execute(
            "SELECT records_upserted, data_start, data_end FROM sync_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert tuple(row) == (42, "2026-01-01", "2026-01-31")

    def test_log_sync_without_range_leaves_columns_null(self, temp_db):
        ggm._log_sync(temp_db, "test", 1)
        row = temp_db.execute("SELECT data_start, data_end FROM sync_log ORDER BY id DESC LIMIT 1").fetchone()
        assert tuple(row) == (None, None)

    def test_get_db_status_returns_last_sync_end(self, tmp_path, monkeypatch):
        db_file = tmp_path / "garmin.db"
        conn = sqlite3.connect(str(db_file))
        init_db(conn)
        conn.execute("INSERT INTO daily_summary (calendar_date, total_steps) VALUES ('2026-05-01', 1234)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(ggm, "DATA_DIR", tmp_path)
        monkeypatch.setattr("garmin_mcp.db.DB_PATH", str(db_file))

        # No coverage logged yet -> falls back to None.
        assert ggm.get_db_status()["last_sync_end"] is None

        conn = sqlite3.connect(str(db_file))
        ggm._log_sync(conn, "test", 1, data_start="2026-04-01", data_end="2026-05-01")
        conn.close()

        status = ggm.get_db_status()
        assert status["last_sync_end"] == "2026-05-01"

    def test_get_db_status_uses_most_recent_sync(self, tmp_path, monkeypatch):
        db_file = tmp_path / "garmin.db"
        conn = sqlite3.connect(str(db_file))
        init_db(conn)
        conn.execute("INSERT INTO daily_summary (calendar_date, total_steps) VALUES ('2026-05-01', 1)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(ggm, "DATA_DIR", tmp_path)
        monkeypatch.setattr("garmin_mcp.db.DB_PATH", str(db_file))

        conn = sqlite3.connect(str(db_file))
        ggm._log_sync(conn, "test", 1, data_start="2026-01-01", data_end="2026-03-01")
        ggm._log_sync(conn, "test", 1, data_start="2026-03-01", data_end="2026-06-01")
        conn.close()

        assert ggm.get_db_status()["last_sync_end"] == "2026-06-01"
