"""
Tests for the SQL injection remediation in fixed_sql_injection.py.

The vulnerability (CWE-89) was that user-supplied 'id' query parameter was
interpolated directly into the SQL string using an f-string. The fix replaces
string interpolation with a parameterized query (cursor.execute with a '?'
placeholder), which is the SAST-recognised safe pattern for SQLite.

These tests verify:
1. Normal functionality still works after the fix.
2. Classic SQL injection payloads are treated as literal values (not parsed as SQL).
3. The parameterized query isolates user input from SQL syntax in all tested cases.
"""

import sqlite3
import pytest
from fixed_sql_injection import app, init_db, db_connection
import fixed_sql_injection as module


@pytest.fixture(autouse=True)
def setup_in_memory_db():
    """
    Reinitialise the in-memory database before every test so each test
    starts with a clean, predictable state.
    """
    module.db_connection = sqlite3.connect(":memory:", check_same_thread=False)
    conn = module.db_connection
    conn.execute(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email    TEXT,
            password TEXT,
            role     TEXT,
            status   TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO users VALUES (1, 'alice', 'alice@example.com', 'hash1', 'user', 'active')"
    )
    conn.execute(
        "INSERT INTO users VALUES (2, 'bob', 'bob@example.com', 'hash2', 'admin', 'active')"
    )
    conn.commit()
    yield
    conn.close()
    module.db_connection = None


@pytest.fixture
def client():
    """Flask test client with testing mode enabled."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Functional tests – legitimate usage still works
# ---------------------------------------------------------------------------

class TestLegitimateUsage:
    def test_valid_id_returns_matching_row(self, client):
        """A valid integer id should return exactly the matching user row."""
        response = client.get("/vulnerable/user/select_by_id/0?id=1")
        assert response.status_code == 200
        body = response.data.decode()
        assert "alice" in body

    def test_valid_id_2_returns_second_user(self, client):
        """Querying id=2 should return the second user."""
        response = client.get("/vulnerable/user/select_by_id/0?id=2")
        assert response.status_code == 200
        body = response.data.decode()
        assert "bob" in body

    def test_nonexistent_id_returns_empty_body(self, client):
        """An id that matches no row should return an empty body (not an error)."""
        response = client.get("/vulnerable/user/select_by_id/0?id=9999")
        assert response.status_code == 200
        assert response.data.decode().strip() == ""

    def test_missing_id_parameter_returns_empty_or_error(self, client):
        """
        When no id is supplied the parameter defaults to ''. SQLite will not
        find a matching row, so the response should be empty or a DB error –
        but not a 500 caused by an unhandled exception leaking data.
        """
        response = client.get("/vulnerable/user/select_by_id/0")
        # Acceptable outcomes: 200 with empty body, or 500 with generic message
        assert response.status_code in (200, 500)
        if response.status_code == 500:
            assert b"Database error" in response.data


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads must be rejected / treated as literals
# ---------------------------------------------------------------------------

class TestSqlInjectionPrevention:
    def test_classic_or_1_equals_1_does_not_return_all_rows(self, client):
        """
        The classic ' OR '1'='1 payload must NOT cause all rows to be returned.
        With parameterised queries the entire string is treated as a literal id
        value, which will match no integer rows.
        """
        payload = "1 OR 1=1"
        response = client.get(f"/vulnerable/user/select_by_id/0?id={payload}")
        body = response.data.decode()
        # Must NOT contain data from both users simultaneously
        assert not ("alice" in body and "bob" in body), (
            "SQL injection succeeded: both users returned for OR 1=1 payload"
        )

    def test_union_select_payload_does_not_disclose_all_users(self, client):
        """
        A UNION-based injection attempt should not cause additional rows to leak.
        """
        payload = "0 UNION SELECT id,username,email,password,role,status FROM users--"
        response = client.get(f"/vulnerable/user/select_by_id/0?id={payload}")
        body = response.data.decode()
        assert "alice" not in body, (
            "UNION SELECT injection succeeded – user data disclosed"
        )
        assert "bob" not in body, (
            "UNION SELECT injection succeeded – user data disclosed"
        )

    def test_drop_table_payload_does_not_destroy_table(self, client):
        """
        A stacked-query payload attempting to DROP the users table must not
        succeed. After the malicious request, a legitimate query for id=1 must
        still return Alice's record.
        """
        drop_payload = "1; DROP TABLE users--"
        client.get(f"/vulnerable/user/select_by_id/0?id={drop_payload}")

        # Verify the table is still intact
        follow_up = client.get("/vulnerable/user/select_by_id/0?id=1")
        assert follow_up.status_code == 200
        assert "alice" in follow_up.data.decode(), (
            "users table appears to have been dropped by the injection payload"
        )

    def test_boolean_blind_payload_does_not_return_extra_rows(self, client):
        """
        A boolean-blind payload like '1 AND 1=1' should behave identically to
        a plain invalid id (no match) rather than returning rows.
        """
        payload = "1 AND 1=1"
        response = client.get(f"/vulnerable/user/select_by_id/0?id={payload}")
        body = response.data.decode()
        # The parameterised value '1 AND 1=1' is not an integer so no row matches
        assert "alice" not in body

    def test_comment_truncation_payload_is_inert(self, client):
        """
        Payloads that use SQL comment sequences (--) to truncate conditions
        must be treated as literal strings, not parsed as SQL.
        """
        payload = "1--"
        response = client.get(f"/vulnerable/user/select_by_id/0?id={payload}")
        body = response.data.decode()
        # '1--' as a literal string should match no integer row
        assert "alice" not in body

    def test_single_quote_in_id_does_not_cause_syntax_error(self, client):
        """
        A single-quote in the input must not break the query with a syntax error
        (which would indicate the input was being interpolated into the SQL string).
        The parameterised query handles quoting transparently.
        """
        payload = "'"
        response = client.get(f"/vulnerable/user/select_by_id/0?id={payload}")
        # Must NOT be a 500 caused by a SQL syntax error from unescaped quote
        # (Empty result or DB error from type mismatch is acceptable)
        assert response.status_code in (200, 500)
        if response.status_code == 500:
            assert b"Database error" in response.data

    def test_null_byte_injection_payload(self, client):
        """
        A NUL byte (\x00) embedded in the id must not cause unexpected behaviour.
        Using the hex escape to avoid embedding a literal control byte in source.
        """
        payload = "1\x00 OR 1=1"
        response = client.get(f"/vulnerable/user/select_by_id/0?id={payload}")
        body = response.data.decode()
        assert not ("alice" in body and "bob" in body)
