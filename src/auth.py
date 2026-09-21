"""
auth.py
=======
Optional, dependency-free authentication gate for the dashboard.

Disabled by default (so the demo and the test-suite are not blocked). When
``SOC_AUTH_ENABLED=true`` the app renders a login form and blocks all content
until valid credentials are supplied. Passwords are verified against a SHA-256
hash using a constant-time comparison; the plaintext password is never stored and
only hashed in memory for the fallback path.

This is a pragmatic single-user gate suitable for a lab / dissertation
deployment. For a production multi-analyst SOC, front the app with an
authenticating reverse proxy or SSO instead.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import streamlit as st

import audit
from config import settings
from logging_config import get_logger

log = get_logger("auth")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _expected_hash() -> str:
    """Resolve the expected password hash from config (hash preferred)."""
    # Hash from a file (Docker/K8s secret) takes precedence when present.
    hash_file = settings.AUTH_PASSWORD_HASH_FILE
    if hash_file and os.path.exists(hash_file):
        try:
            with open(hash_file, encoding="utf-8") as fh:
                return fh.read().strip().lower()
        except OSError as exc:  # pragma: no cover
            log.warning("Could not read AUTH_PASSWORD_HASH_FILE: %s", exc)
    if settings.AUTH_PASSWORD_HASH:
        return settings.AUTH_PASSWORD_HASH.strip().lower()
    if settings.AUTH_PASSWORD:
        return _sha256(settings.AUTH_PASSWORD)
    return ""


def verify(username: str, password: str) -> bool:
    """Constant-time verification of a username/password pair."""
    expected = _expected_hash()
    if not expected:
        # Misconfigured: auth enabled but no credential set — deny.
        log.warning("Auth enabled but no password hash/password configured; denying.")
        return False
    user_ok = hmac.compare_digest(str(username), settings.AUTH_USERNAME)
    pass_ok = hmac.compare_digest(_sha256(password), expected)
    return user_ok and pass_ok


def require_login() -> None:
    """
    Gate the app. No-op when auth is disabled; otherwise renders a login form and
    calls ``st.stop()`` until the user authenticates.
    """
    if not settings.AUTH_ENABLED:
        return

    if st.session_state.get("authenticated"):
        with st.sidebar:
            st.caption(f"🔓 Signed in as **{st.session_state.get('auth_user', '')}**")
            if st.button("Log out", width="stretch"):
                st.session_state.pop("authenticated", None)
                st.session_state.pop("auth_user", None)
                st.rerun()
        return

    st.title("🛡️ SOC Dashboard — Sign in")
    with st.form("login"):
        username = st.text_input("Username", value="")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in"):
            if verify(username, password):
                st.session_state["authenticated"] = True
                st.session_state["auth_user"] = username
                audit.record("login.success", user=username)
                log.info("User %r authenticated.", username)
                st.rerun()
            else:
                audit.record("login.failure", user=username or "unknown")
                st.error("Invalid credentials.")
    st.stop()
