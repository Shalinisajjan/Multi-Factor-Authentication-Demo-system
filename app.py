"""Local-only MFA teaching demo. See README.md for scope and limitations."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote

import bcrypt
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for, send_file)

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("MFA_DB_PATH", os.path.join(ROOT, "mfa_demo.sqlite3"))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024,
)
FERNET_KEY = os.environ.get("MFA_FERNET_KEY", "")
TOTP_STEP = int(os.environ.get("TOTP_STEP_SECONDS", "30"))
TOTP_WINDOW = int(os.environ.get("TOTP_WINDOW", "1"))
LOCK_THRESHOLD = int(os.environ.get("LOGIN_FAILURE_LIMIT", "5"))
LOCK_SECONDS = int(os.environ.get("LOGIN_LOCK_SECONDS", "300"))


def ready_config() -> None:
    if not app.config["SECRET_KEY"] or not FERNET_KEY:
        raise RuntimeError("Set FLASK_SECRET_KEY and MFA_FERNET_KEY before starting. See README.md.")
    try:
        Fernet(FERNET_KEY.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("MFA_FERNET_KEY must be a valid Fernet key.") from exc
    if TOTP_STEP < 15 or not 0 <= TOTP_WINDOW <= 2:
        raise RuntimeError("Use TOTP_STEP_SECONDS >= 15 and TOTP_WINDOW between 0 and 2.")


def cipher() -> Fernet:
    return Fernet(FERNET_KEY.encode())


def db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash BLOB NOT NULL, totp_secret_enc BLOB,
          mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK(mfa_enabled IN (0,1)),
          failed_count INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_codes (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          code_hash BLOB NOT NULL, used_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id, used_at);
        CREATE TABLE IF NOT EXISTS security_events (
          id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
          event_type TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(user_id, id DESC);
        """)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit(event_type: str, user_id: int | None = None, detail: str = "") -> None:
    # Details are fixed labels only: never place credentials, OTPs, codes or secrets here.
    db().execute("INSERT INTO security_events(user_id,event_type,detail,created_at) VALUES(?,?,?,?)",
                 (user_id, event_type, detail[:80], now_iso()))
    db().commit()


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.context_processor
def inject_helpers():
    return {"csrf_token": csrf_token}


@app.before_request
def csrf_check():
    if request.method == "POST":
        expected = session.get("csrf", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid request. Reload the page and try again.")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def current_user():
    return db().execute("SELECT * FROM users WHERE id=?", (session.get("user_id"),)).fetchone()


def validate_username(value: str) -> str | None:
    value = value.strip().lower()
    return value if re.fullmatch(r"[a-z0-9_.-]{3,32}", value) else None


def totp(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{binary % 1_000_000:06d}"


def verify_totp(secret: bytes, supplied: str, timestamp: int | None = None) -> bool:
    if not re.fullmatch(r"\d{6}", supplied):
        return False
    counter = (timestamp if timestamp is not None else int(time.time())) // TOTP_STEP
    return any(hmac.compare_digest(totp(secret, counter + delta), supplied)
               for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1))


def new_totp_secret() -> bytes:
    return secrets.token_bytes(20)


def provisioning_uri(username: str, secret: bytes) -> str:
    encoded = base64.b32encode(secret).decode().rstrip("=")
    label = quote(f"MFA Demo:{username}")
    return (f"otpauth://totp/{label}?secret={encoded}&issuer=MFA%20Demo"
            f"&algorithm=SHA1&digits=6&period={TOTP_STEP}")


def new_recovery_codes(count: int = 8) -> list[str]:
    return [secrets.token_hex(5).upper() for _ in range(count)]


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def check_password(password: str, stored: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), stored)
    except (ValueError, TypeError):
        return False


def check_recovery_code(user_id: int, submitted: str) -> bool:
    normalized = re.sub(r"[^A-Fa-f0-9]", "", submitted).upper()
    if len(normalized) != 20:
        return False
    rows = db().execute("SELECT id,code_hash FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (user_id,)).fetchall()
    candidate = normalized.encode()
    for row in rows:
        if bcrypt.checkpw(candidate, row["code_hash"]):
            cur = db().execute("UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL", (now_iso(), row["id"]))
            db().commit()
            return cur.rowcount == 1
    return False


@app.get("/")
def index():
    return redirect(url_for("dashboard" if session.get("user_id") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = validate_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        if not username or len(password) < 12 or len(password) > 128:
            flash("Use a 3–32 character username and a password of 12–128 characters.", "error")
        else:
            try:
                cur = db().execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                                   (username, hash_password(password), now_iso()))
                audit("registration_success", cur.lastrowid)
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Could not create account with those details.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = validate_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE username=?", (username or "",)).fetchone()
        current = int(time.time())
        if user and user["locked_until"] > current:
            audit("login_throttled", user["id"])
            flash("Sign-in failed. Check your details or try again later.", "error")
            return render_template("login.html")
        valid = bool(user and check_password(password, user["password_hash"]))
        if not valid:
            if user:
                failures = user["failed_count"] + 1
                lock_until = current + LOCK_SECONDS if failures >= LOCK_THRESHOLD else 0
                db().execute("UPDATE users SET failed_count=?,locked_until=? WHERE id=?", (0 if lock_until else failures, lock_until, user["id"]))
                audit("login_failure", user["id"], "locked" if lock_until else "password")
                db().commit()
            flash("Sign-in failed. Check your details or try again later.", "error")
            return render_template("login.html")
        db().execute("UPDATE users SET failed_count=0,locked_until=0 WHERE id=?", (user["id"],))
        db().commit()
        # Discard pre-authentication state and rotate session contents to reduce fixation risk.
        session.clear()
        session["csrf"] = secrets.token_urlsafe(32)
        if user["mfa_enabled"]:
            session["pending_user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("verify_login"))
        session["user_id"] = user["id"]
        session.permanent = True
        audit("login_success", user["id"], "password_only")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify_login():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))
    if request.method == "POST":
        user = db().execute("SELECT * FROM users WHERE id=? AND mfa_enabled=1", (user_id,)).fetchone()
        if user and user["locked_until"] > int(time.time()):
            audit("login_throttled", user_id, "mfa")
            flash("Verification failed. Check the code and try again later.", "error")
            return render_template("verify.html")
        otp = request.form.get("code", "")
        valid = False
        if user and user["totp_secret_enc"]:
            try:
                valid = verify_totp(cipher().decrypt(user["totp_secret_enc"]), otp)
            except InvalidToken:
                audit("mfa_error", user_id, "decryption")
        if not valid and user:
            valid = check_recovery_code(user_id, otp)
        if valid:
            db().execute("UPDATE users SET failed_count=0,locked_until=0 WHERE id=?", (user_id,))
            db().commit()
            session.clear()
            session["csrf"] = secrets.token_urlsafe(32)
            session["user_id"] = user_id
            session.permanent = True
            audit("login_success", user_id, "mfa")
            return redirect(url_for("dashboard"))
        failures = user["failed_count"] + 1 if user else LOCK_THRESHOLD
        lock_until = int(time.time()) + LOCK_SECONDS if failures >= LOCK_THRESHOLD else 0
        db().execute("UPDATE users SET failed_count=?,locked_until=? WHERE id=?",
                     (0 if lock_until else failures, lock_until, user_id))
        audit("mfa_failure", user_id, "locked" if lock_until else "code")
        db().commit()
        flash("Verification failed. Check the code and try again.", "error")
    return render_template("verify.html")


@app.post("/logout")
def logout():
    user_id = session.get("user_id") or session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))
    audit("logout", user_id)
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    events = db().execute("SELECT event_type,detail,created_at FROM security_events WHERE user_id=? ORDER BY id DESC LIMIT 12", (user["id"],)).fetchall()
    remaining = db().execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (user["id"],)).fetchone()[0]
    return render_template("dashboard.html", user=user, events=events, remaining=remaining)


@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def setup_mfa():
    user = current_user()
    if user["mfa_enabled"]:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if not check_password(password, user["password_hash"]):
            audit("mfa_enrollment_failure", user["id"])
            flash("Could not verify your password.", "error")
        elif session.get("enroll_secret"):
            try:
                secret = base64.b32decode(session["enroll_secret"] + "=" * (-len(session["enroll_secret"]) % 8))
                if verify_totp(secret, request.form.get("code", "")):
                    codes = new_recovery_codes()
                    db().execute("UPDATE users SET totp_secret_enc=?,mfa_enabled=1 WHERE id=?", (cipher().encrypt(secret), user["id"]))
                    db().execute("DELETE FROM recovery_codes WHERE user_id=?", (user["id"],))
                    for code in codes:
                        db().execute("INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)",
                                     (user["id"], bcrypt.hashpw(code.encode(), bcrypt.gensalt(rounds=12))))
                    audit("mfa_enabled", user["id"])
                    db().commit()
                    session.pop("enroll_secret", None)
                    session["show_recovery_codes"] = codes
                    return redirect(url_for("recovery_codes"))
            except InvalidToken:
                pass
            flash("Could not verify your password or authenticator code.", "error")
        else:
            secret = new_totp_secret()
            session["enroll_secret"] = base64.b32encode(secret).decode().rstrip("=")
            session["enroll_uri"] = provisioning_uri(user["username"], secret)
            return redirect(url_for("setup_mfa"))
    uri = session.get("enroll_uri")
    return render_template("setup_mfa.html", uri=uri)


@app.get("/mfa/qr.png")
@login_required
def enrollment_qr():
    uri = session.get("enroll_uri")
    if not uri:
        abort(404)
    image = qrcode.make(uri)
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    stream.seek(0)
    return send_file(stream, mimetype="image/png", max_age=0)


@app.get("/mfa/recovery-codes")
@login_required
def recovery_codes():
    codes = session.pop("show_recovery_codes", None)
    if codes is None:
        return redirect(url_for("dashboard"))
    return render_template("recovery_codes.html", codes=codes)


@app.route("/mfa/disable", methods=["GET", "POST"])
@login_required
def disable_mfa():
    user = current_user()
    if request.method == "POST":
        if check_password(request.form.get("password", ""), user["password_hash"]):
            db().execute("UPDATE users SET totp_secret_enc=NULL,mfa_enabled=0 WHERE id=?", (user["id"],))
            db().execute("DELETE FROM recovery_codes WHERE user_id=?", (user["id"],))
            audit("mfa_disabled", user["id"])
            db().commit()
            flash("Authenticator sign-in has been disabled.", "success")
            return redirect(url_for("dashboard"))
        audit("mfa_disable_failure", user["id"])
        flash("Could not verify your password.", "error")
    return render_template("disable_mfa.html", enabled=bool(user["mfa_enabled"]))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", message=getattr(error, "description", "Invalid request.")), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", message="Page not found."), 404


if __name__ == "__main__":
    ready_config()
    init_db()
    # Local loopback only; do not expose the development server to a network.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
