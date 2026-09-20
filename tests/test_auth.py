"""
tests/test_auth.py — unit tests for api/auth.py

Uses a real temporary SQLite file (via db.py, same as test_db.py) so
registration/authentication is tested against real password hashing,
not mocks — this is exactly the kind of logic where a mock would hide
a real bug (e.g. accidentally comparing plaintext passwords).
"""

import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import db as db_module  # noqa: E402
import auth as auth_module  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch):
    """Point db.DB_PATH at a fresh temp file for every test in this file."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_module.init_db(db_path=path)
    monkeypatch.setattr(db_module, "DB_PATH", path)
    yield path
    os.remove(path)


# ---- validate_credentials ----

def test_validate_credentials_rejects_short_username():
    ok, error = auth_module.validate_credentials("ab", "goodpassword")
    assert ok is False
    assert "username" in error


def test_validate_credentials_rejects_bad_characters():
    ok, error = auth_module.validate_credentials("bad user!", "goodpassword")
    assert ok is False


def test_validate_credentials_rejects_short_password():
    ok, error = auth_module.validate_credentials("gooduser", "short")
    assert ok is False
    assert "password" in error


def test_validate_credentials_accepts_valid_input():
    ok, error = auth_module.validate_credentials("good_user.1", "goodpassword123")
    assert ok is True
    assert error is None


# ---- register_user ----

def test_register_user_creates_a_real_user():
    user, error = auth_module.register_user("alice", "supersecret1")
    assert error is None
    assert user["username"] == "alice"
    # the plaintext password should never be stored anywhere
    assert "supersecret1" not in user["password_hash"]


def test_register_user_rejects_duplicate_username():
    auth_module.register_user("alice", "supersecret1")
    user, error = auth_module.register_user("alice", "differentpass1")
    assert user is None
    assert "taken" in error


def test_register_user_rejects_invalid_credentials_without_touching_db():
    user, error = auth_module.register_user("ab", "short")
    assert user is None
    assert error is not None
    assert db_module.get_user_by_username("ab") is None


# ---- authenticate ----

def test_authenticate_succeeds_with_correct_password():
    auth_module.register_user("alice", "correcthorse1")
    user = auth_module.authenticate("alice", "correcthorse1")
    assert user is not None
    assert user["username"] == "alice"


def test_authenticate_fails_with_wrong_password():
    auth_module.register_user("alice", "correcthorse1")
    user = auth_module.authenticate("alice", "wrongpassword")
    assert user is None


def test_authenticate_fails_for_unknown_user():
    user = auth_module.authenticate("nobody", "whatever123")
    assert user is None


def test_password_is_never_stored_in_plaintext():
    auth_module.register_user("alice", "correcthorse1")
    stored = db_module.get_user_by_username("alice")
    assert stored["password_hash"] != "correcthorse1"
    assert "correcthorse1" not in stored["password_hash"]
    # PBKDF2 hashes produced by werkzeug are long and self-describing
    assert stored["password_hash"].startswith("pbkdf2:") or "$" in stored["password_hash"]
