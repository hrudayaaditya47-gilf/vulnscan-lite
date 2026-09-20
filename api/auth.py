"""
api/auth.py — minimal username/password auth using Flask sessions.

Deliberately simple: no email verification, no password reset, no OAuth.
The spec's requirement is just "logged-in users can see their scan
history" — this is the smallest thing that actually satisfies that
without pulling in a full auth framework.

Passwords are hashed with werkzeug's generate_password_hash (PBKDF2),
which ships with Flask already — no extra dependency needed.
"""

import re
from functools import wraps

from flask import session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import db

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 8


def validate_credentials(username: str, password: str):
    """Returns (is_valid, error_message)."""
    if not username or not USERNAME_PATTERN.match(username):
        return False, "username must be 3-32 characters (letters, numbers, _ . -)"
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    return True, None


def register_user(username: str, password: str):
    """
    Returns (user_dict, error_message) — exactly one will be None.
    """
    is_valid, error = validate_credentials(username, password)
    if not is_valid:
        return None, error

    if db.get_user_by_username(username):
        return None, "username is already taken"

    password_hash = generate_password_hash(password)
    user_id = db.create_user(username, password_hash)
    return db.get_user_by_id(user_id), None


def authenticate(username: str, password: str):
    """Returns the user dict if credentials are valid, else None."""
    user = db.get_user_by_username(username)
    if not user:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def current_user():
    """Returns the logged-in user's dict, or None if not logged in."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.get_user_by_id(user_id)


def login_required(view_func):
    """Decorator — returns 401 if no one is logged in for this session."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify(error="login required"), 401
        return view_func(user, *args, **kwargs)
    return wrapped
