"""
tests/test_db.py — unit tests for api/db.py

Uses a real temporary SQLite file per test (not mocked) — sqlite3 is
fast and self-contained enough that testing against the real thing is
both easy and more trustworthy than mocking the DB layer.
"""

import sys
import os
import sqlite3
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import db as db_module  # noqa: E402


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_module.init_db(db_path=path)
    yield path
    os.remove(path)


def make_scan_result(url="https://example.com", score=90, grade="A-"):
    return {
        "url": url,
        "headers": {}, "ssl": {}, "cms": {},
        "report": {"score": score, "grade": grade, "breakdown": {}, "max_breakdown": {},
                   "passed_checks": [], "failed_checks": []},
    }


def test_create_and_fetch_user(db_path):
    user_id = db_module.create_user("alice", "hashed-pw", db_path=db_path)
    assert user_id > 0

    user = db_module.get_user_by_username("alice", db_path=db_path)
    assert user["username"] == "alice"
    assert user["password_hash"] == "hashed-pw"

    same_user = db_module.get_user_by_id(user_id, db_path=db_path)
    assert same_user["username"] == "alice"


def test_duplicate_username_is_rejected(db_path):
    db_module.create_user("alice", "hash1", db_path=db_path)
    with pytest.raises(sqlite3.IntegrityError):
        db_module.create_user("alice", "hash2", db_path=db_path)


def test_unknown_username_returns_none(db_path):
    assert db_module.get_user_by_username("nobody", db_path=db_path) is None


def test_save_and_list_scan_history(db_path):
    user_id = db_module.create_user("bob", "hash", db_path=db_path)

    db_module.save_scan_to_history(user_id, "task-1", make_scan_result(score=90, grade="A-"), db_path=db_path)
    db_module.save_scan_to_history(user_id, "task-2", make_scan_result(url="https://other.com", score=60, grade="D"), db_path=db_path)

    history = db_module.get_history_for_user(user_id, db_path=db_path)
    assert len(history) == 2
    # newest first
    assert history[0]["url"] == "https://other.com"
    assert history[0]["score"] == 60
    assert history[1]["score"] == 90


def test_saving_same_task_id_twice_does_not_duplicate(db_path):
    user_id = db_module.create_user("bob", "hash", db_path=db_path)

    first_id = db_module.save_scan_to_history(user_id, "task-1", make_scan_result(score=90), db_path=db_path)
    second_id = db_module.save_scan_to_history(user_id, "task-1", make_scan_result(score=90), db_path=db_path)

    assert first_id == second_id
    assert len(db_module.get_history_for_user(user_id, db_path=db_path)) == 1


def test_history_is_scoped_to_the_owning_user(db_path):
    alice_id = db_module.create_user("alice", "hash", db_path=db_path)
    bob_id = db_module.create_user("bob", "hash", db_path=db_path)

    db_module.save_scan_to_history(alice_id, "task-1", make_scan_result(), db_path=db_path)

    assert len(db_module.get_history_for_user(alice_id, db_path=db_path)) == 1
    assert len(db_module.get_history_for_user(bob_id, db_path=db_path)) == 0


def test_get_scan_detail_returns_full_result(db_path):
    user_id = db_module.create_user("alice", "hash", db_path=db_path)
    scan_id = db_module.save_scan_to_history(user_id, "task-1", make_scan_result(score=77, grade="C+"), db_path=db_path)

    detail = db_module.get_scan_detail(scan_id, user_id, db_path=db_path)
    assert detail["result"]["report"]["score"] == 77
    assert detail["result"]["url"] == "https://example.com"


def test_get_scan_detail_returns_none_for_wrong_owner(db_path):
    alice_id = db_module.create_user("alice", "hash", db_path=db_path)
    bob_id = db_module.create_user("bob", "hash", db_path=db_path)
    scan_id = db_module.save_scan_to_history(alice_id, "task-1", make_scan_result(), db_path=db_path)

    assert db_module.get_scan_detail(scan_id, bob_id, db_path=db_path) is None


def test_get_scan_detail_returns_none_for_missing_id(db_path):
    user_id = db_module.create_user("alice", "hash", db_path=db_path)
    assert db_module.get_scan_detail(99999, user_id, db_path=db_path) is None
