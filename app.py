import csv
import hmac
import io
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import threading
import time

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    has_request_context,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-only-change-this-key"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ssl_dashboard.db"
BACKUP_DIR = BASE_DIR / "backups"

MAX_PARALLEL_CHECKS = 8
ACTIVITY_LIMIT = 20          # rows shown in the dashboard "Recent Activity" card
CACHE_SECONDS = 300          # popups reuse a certificate check for 5 minutes
OPEN_STATUSES = ("Pending", "Failed", "Unverified")

DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
)
CERT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,200}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
CERTBOT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9_./\\:-]{1,200}$")
BACKUP_NAME_PATTERN = re.compile(r"^ssl_dashboard_\d{8}_\d{6}(?:_[a-z]+)?\.db$")

# Every setting lives in the database; these are the defaults.
DEFAULT_SETTINGS = {
    "org_name": "Zam Certcure",
    "page_size": "25",
    # monitoring
    "critical_days": "7",
    "warning_days": "30",
    "check_timeout": "10",
    "monitor_enabled": "0",
    "monitor_interval_hours": "12",
    "last_monitor_run": "0",
    # renewals
    "auto_tasks": "1",
    "auto_renew": "0",
    "renew_before_days": "30",
    # alerts
    "alerts_enabled": "0",
    "alert_recipients": "",
    "reminder_days": "30,14,7,3,1",
    "alert_on_failed": "1",
    # integrations
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_security": "starttls",
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
    "certbot_path": "certbot",
    # backups
    "auto_backup": "0",
    "backup_keep": "10",
    "last_backup_run": "0",
}

ROLES = {"admin": "Administrator", "operator": "Operator", "viewer": "Viewer"}

PERMISSIONS = {
    "view": "View dashboard, monitoring and renewals",
    "manage_websites": "Add, edit and delete websites",
    "renew": "Create tasks and run renewals",
    "manage_alerts": "Configure and send email alerts",
    "export_reports": "Generate and export reports",
    "view_audit": "View audit logs",
    "manage_users": "Manage users and permissions",
    "manage_settings": "Change settings and backups",
}

ROLE_PERMISSIONS = {
    "admin": set(PERMISSIONS),
    "operator": {
        "view", "manage_websites", "renew",
        "manage_alerts", "export_reports", "view_audit",
    },
    "viewer": {"view", "export_reports"},
}

PANELS = {
    "expiry": {
        "title": "Expiry Monitoring",
        "subtitle": "Track expiry dates and certificates requiring renewal.",
        "icon": "fa-hourglass-half", "perm": "view",
    },
    "notifications": {
        "title": "Notifications & Alerts",
        "subtitle": "Configure email alerts and renewal reminders.",
        "icon": "fa-bell", "perm": "manage_alerts",
    },
    "renewals": {
        "title": "Renewals",
        "subtitle": "Track renewal tasks, replacement certificates and automation.",
        "icon": "fa-rotate", "perm": "view",
    },
    "reports": {
        "title": "Reports",
        "subtitle": "Generate and export certificate status and expiry reports.",
        "icon": "fa-chart-column", "perm": "export_reports",
    },
    "audit": {
        "title": "Audit Logs",
        "subtitle": "Track certificate changes, imports, deletions and user actions.",
        "icon": "fa-clipboard-list", "perm": "view_audit",
    },
    "users": {
        "title": "Users & Permissions",
        "subtitle": "Manage administrators, users and access rights.",
        "icon": "fa-users-gear", "perm": "manage_users",
    },
    "settings": {
        "title": "Settings",
        "subtitle": "Configure the application, integrations, backups and preferences.",
        "icon": "fa-sliders", "perm": "manage_settings",
    },
}

AUDIT_CATEGORIES = {
    "certificate": "Certificates",
    "renewal": "Renewals",
    "alert": "Alerts",
    "user": "Users",
    "settings": "Settings",
    "backup": "Backups",
    "auth": "Sign-ins",
    "report": "Reports",
    "import": "Imports",
    "general": "General",
}

REPORTS = {
    "status": "Certificate status (all websites)",
    "expiring": "Expiring certificates",
    "problems": "Expired and failed checks",
    "renewals": "Renewal history",
}


# ---------------- HELPERS ----------------

def iso_now():
    return datetime.now(timezone.utc).isoformat()


def fmt_ts(value):
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return value or "—"


def fmt_epoch(value):
    try:
        number = float(value)
        if number <= 0:
            return None
        return datetime.fromtimestamp(number, timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (ValueError, TypeError, OverflowError, OSError):
        return None


app.jinja_env.filters["ts"] = fmt_ts


def as_int(value, default, low, high):
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        return default
    return max(low, min(high, number))


def as_bool(value):
    return str(value) == "1"


def parse_days(text):
    days = set()
    for part in re.split(r"[,\s;]+", text or ""):
        if part.isdigit() and 0 < int(part) <= 365:
            days.add(int(part))
    return sorted(days, reverse=True)


def parse_recipients(text):
    return [p for p in re.split(r"[,;\s]+", text or "") if p]


def is_fetch():
    return request.headers.get("X-Requested-With") == "fetch"


# ---------------- DATABASE ----------------

@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    BACKUP_DIR.mkdir(exist_ok=True)

    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL UNIQUE,
                cert_name TEXT NOT NULL,
                added_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                user TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(activity_log)")}
        if "category" not in columns:
            conn.execute(
                "ALTER TABLE activity_log "
                "ADD COLUMN category TEXT NOT NULL DEFAULT 'general'"
            )
        if "detail" not in columns:
            conn.execute(
                "ALTER TABLE activity_log "
                "ADD COLUMN detail TEXT NOT NULL DEFAULT ''"
            )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'viewer',
                password_hash TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT NOT NULL DEFAULT ''
            )
        """)
        user_columns = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if "perms" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN perms TEXT NOT NULL DEFAULT ''")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS renewals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER,
                host TEXT NOT NULL,
                cert_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                source TEXT NOT NULL DEFAULT 'manual',
                note TEXT NOT NULL DEFAULT '',
                old_expiry TEXT NOT NULL DEFAULT '',
                new_expiry TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notification_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                recipients TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_keys (
                key TEXT PRIMARY KEY,
                sent_at TEXT NOT NULL
            )
        """)


def get_websites():
    with db() as conn:
        return conn.execute("""
            SELECT id, host, cert_name, added_at
            FROM websites
            ORDER BY host
        """).fetchall()


def get_website(website_id):
    with db() as conn:
        return conn.execute("""
            SELECT id, host, cert_name, added_at
            FROM websites
            WHERE id = ?
        """, (website_id,)).fetchone()


def load_settings():
    values = dict(DEFAULT_SETTINGS)
    with db() as conn:
        for row in conn.execute("SELECT key, value FROM settings"):
            if row["key"] in values:
                values[row["key"]] = row["value"]
    return values


def save_settings(updates):
    with db() as conn:
        conn.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(k, str(v)) for k, v in updates.items()],
        )


def get_limits(settings=None):
    s = settings or load_settings()
    critical = as_int(s["critical_days"], 7, 0, 365)
    warning = as_int(s["warning_days"], 30, 1, 365)
    if warning <= critical:
        warning = critical + 1
    return {
        "critical": critical,
        "warning": warning,
        "renew": as_int(s["renew_before_days"], 30, 1, 365),
        "timeout": as_int(s["check_timeout"], 10, 2, 60),
    }


# ---------------- AUTH & PERMISSIONS ----------------
# Until an administrator with a password exists the app stays in "open mode"
# (exactly like before: no login). Creating the first administrator in
# Users & Permissions switches sign-in on.

_login_failures = {}


def auth_enabled():
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM users "
            "WHERE role = 'admin' AND active = 1 AND password_hash != '' LIMIT 1"
        ).fetchone()
    return row is not None


def current_user():
    if "user" in g:
        return g.user

    user = None
    if auth_enabled():
        user_id = session.get("user_id")
        if user_id:
            with db() as conn:
                row = conn.execute(
                    "SELECT id, username, email, role, perms FROM users "
                    "WHERE id = ? AND active = 1", (user_id,)
                ).fetchone()
            user = dict(row) if row else None
    else:
        user = {"id": 0, "username": "Administrator", "email": "", "role": "admin", "perms": ""}

    g.user = user
    return user


def effective_permissions(user):
    """Administrators always have everything. Others use their custom set if the
    administrator picked one, otherwise the defaults of their role."""
    if user["role"] == "admin":
        return set(PERMISSIONS)
    custom = {p for p in (user.get("perms") or "").split(",") if p in PERMISSIONS}
    if custom:
        return custom | {"view"}
    return set(ROLE_PERMISSIONS.get(user["role"], ()))


def can(permission):
    user = current_user()
    return bool(user and permission in effective_permissions(user))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def requires(permission):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not can(permission):
                if is_fetch():
                    return Response(
                        render_template("panels.html", panel="denied",
                                        meta=PANELS["expiry"]), 403)
                flash("Your role does not allow that action.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.before_request
def guard():
    g.auth = auth_enabled()

    if request.endpoint in (None, "static"):
        return None

    if request.method == "POST":
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            message = "Your session token expired. Reload the page and try again."
            if is_fetch():
                return Response(
                    '<div class="panel-fragment" data-title="Session expired" '
                    'data-subtitle="" data-icon="fa-triangle-exclamation">'
                    f'<div class="notice notice-error">{message}</div></div>', 400)
            return Response(message, 400)

    if request.endpoint == "login":
        return None

    if g.auth and current_user() is None:
        if is_fetch():
            return Response("Signed out", 401)
        return redirect(url_for("login", next=request.full_path.rstrip("?")))

    return None


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token,
        "can": can,
        "current_user": current_user(),
        "auth_enabled": g.get("auth", False),
        "PANELS": PANELS,
        "ROLES": ROLES,
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if not auth_enabled():
        return redirect(url_for("dashboard"))

    error = None
    next_url = request.values.get("next", "")
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = ""

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        recent = [t for t in _login_failures.get(ip, []) if time.time() - t < 300]
        _login_failures[ip] = recent

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(recent) >= 5:
            error = "Too many failed attempts. Wait a few minutes and try again."
        else:
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND active = 1",
                    (username,),
                ).fetchone()

            if row and row["password_hash"] and check_password_hash(row["password_hash"], password):
                session.clear()
                session["user_id"] = row["id"]
                csrf_token()
                with db() as conn:
                    conn.execute("UPDATE users SET last_login = ? WHERE id = ?",
                                 (iso_now(), row["id"]))
                _login_failures.pop(ip, None)
                log_activity("Signed in", "auth", user=row["username"])
                return redirect(next_url or url_for("dashboard"))

            _login_failures.setdefault(ip, []).append(time.time())
            log_activity(f"Failed sign-in for '{username[:40]}'", "auth", user="anonymous")
            error = "Invalid username or password."

    return render_template("login.html", error=error, next_url=next_url)


@app.route("/logout", methods=["POST"])
def logout():
    if not auth_enabled():
        flash("Sign-in is not turned on yet. Add an Administrator with a password in "
              "Users & Permissions to enable signing in and out.", "info")
        return redirect(url_for("dashboard"))
    log_activity("Signed out", "auth")
    session.clear()
    return redirect(url_for("login"))


# ---------------- ACTIVITY / AUDIT LOG ----------------

def actor():
    if has_request_context():
        user = current_user()
        if user:
            return user["username"]
    return "System"


def log_activity(action, category="general", detail="", user=None):
    """Record an action. Never lets a logging error break a request."""
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO activity_log (action, user, timestamp, category, detail)
                VALUES (?, ?, ?, ?, ?)
            """, (action, user or actor(), iso_now(), category, detail[:500]))
    except sqlite3.Error as error:
        app.logger.warning("Could not write activity log: %s", error)


def get_recent_activity(limit=ACTIVITY_LIMIT):
    with db() as conn:
        rows = conn.execute("""
            SELECT action, user, timestamp
            FROM activity_log
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    activity = []
    for row in rows:
        item = dict(row)
        item["timestamp"] = fmt_ts(item["timestamp"])
        activity.append(item)
    return activity


def query_audit(search="", category="", page=1, per_page=25):
    where, params = [], []
    if search:
        where.append("(action LIKE ? OR user LIKE ? OR detail LIKE ?)")
        params += [f"%{search}%"] * 3
    if category:
        where.append("category = ?")
        params.append(category)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    with db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM activity_log {clause}", params
        ).fetchone()[0]

        sql = f"SELECT * FROM activity_log {clause} ORDER BY id DESC"
        args = list(params)
        if per_page:
            sql += " LIMIT ? OFFSET ?"
            args += [per_page, (page - 1) * per_page]
        else:
            sql += " LIMIT 50000"
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]

    return total, rows


# ---------------- INPUT VALIDATION ----------------

def validate_website_input():
    host = request.form.get("host", "").strip().lower().rstrip(".")
    cert_name = request.form.get("cert_name", "").strip()

    if not DOMAIN_PATTERN.fullmatch(host):
        return None, None, "Enter a valid domain, such as example.com."

    if not cert_name:
        cert_name = host

    if not CERT_NAME_PATTERN.fullmatch(cert_name):
        return None, None, "Invalid Certbot certificate name."

    return host, cert_name, None


# ---------------- SSL CERTIFICATE MONITORING ----------------

def _name_value(name, oid):
    attributes = name.get_attributes_for_oid(oid)
    return attributes[0].value if attributes else None


def cert_info(host, port=443, timeout=10):
    """Read the publicly presented TLS certificate details."""

    with socket.create_connection((host, port), timeout=timeout) as sock:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Read the certificate for expiry monitoring.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert_der = tls.getpeercert(binary_form=True)

    if not cert_der:
        raise ValueError("The server did not provide a certificate.")

    cert = x509.load_der_x509_certificate(cert_der)

    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)

    valid_from = getattr(cert, "not_valid_before_utc", None)
    if valid_from is None:
        valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)

    issuer = (
        _name_value(cert.issuer, NameOID.ORGANIZATION_NAME)
        or _name_value(cert.issuer, NameOID.COMMON_NAME)
        or "Unknown issuer"
    )

    now = datetime.now(timezone.utc)
    days_left = int((expiry - now).total_seconds() // 86400)

    return {
        "expiry": expiry.strftime("%Y-%m-%d"),
        "valid_from": valid_from.strftime("%Y-%m-%d"),
        "issuer": issuer,
        "days_left": days_left,
    }


def classify(days_left, limits):
    if days_left < 0:
        return "Expired"
    if days_left <= limits["critical"]:
        return "Critical"
    if days_left <= limits["warning"]:
        return "Expiring Soon"
    return "Healthy"


def check_website(host, limits=None):
    limits = limits or get_limits()
    result = {
        "expiry": "Unknown",
        "valid_from": None,
        "issuer": None,
        "days_left": None,
        "status": "Check Failed",
        "message": "",
    }

    try:
        result.update(cert_info(host, timeout=limits["timeout"]))
        result["status"] = classify(result["days_left"], limits)

    except Exception as error:
        app.logger.warning("Certificate check failed for %s: %s", host, error)
        result["message"] = f"{type(error).__name__}: {error}"

    return result


_cache = {}
_cache_lock = threading.Lock()


def invalidate(host=None):
    with _cache_lock:
        if host is None:
            _cache.clear()
        else:
            _cache.pop(host, None)


def get_checked_websites(force=False):
    """All websites with live certificate details.

    force=True re-checks everything (dashboard load, scheduler); otherwise
    results younger than CACHE_SECONDS are reused so popups open instantly.
    """
    rows = get_websites()
    if not rows:
        return []

    limits = get_limits()
    now = time.time()

    with _cache_lock:
        stale = [
            r["host"] for r in rows
            if force or r["host"] not in _cache
            or now - _cache[r["host"]][0] > CACHE_SECONDS
        ]

    if stale:
        workers = min(MAX_PARALLEL_CHECKS, len(stale))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fresh = list(pool.map(lambda h: check_website(h, limits), stale))
        with _cache_lock:
            for host, result in zip(stale, fresh):
                _cache[host] = (now, result)

    with _cache_lock:
        snapshot = dict(_cache)

    websites = []
    for row in rows:
        stamp, result = snapshot.get(row["host"]) or (now, check_website(row["host"], limits))
        website = dict(row)
        website.update(result)
        website["checked_at"] = stamp
        if website["days_left"] is not None:
            website["status"] = classify(website["days_left"], limits)
        websites.append(website)

    return websites


# ---------------- DASHBOARD ----------------

def next_check_text(settings):
    if not as_bool(settings["monitor_enabled"]):
        return "On next page load or refresh"
    interval = as_int(settings["monitor_interval_hours"], 12, 1, 168) * 3600
    try:
        last = float(settings["last_monitor_run"])
    except ValueError:
        last = 0
    return (fmt_epoch(last + interval) or "Within a minute") + " (background)"


@app.route("/")
def dashboard():
    checked_at = datetime.now(timezone.utc)
    settings = load_settings()
    limits = get_limits(settings)
    websites = get_checked_websites(force=True)

    def count(status):
        return sum(w["status"] == status for w in websites)

    stats = {
        "total": len(websites),
        "healthy": count("Healthy"),
        "expiring": count("Expiring Soon"),   # "Warning" card
        "critical": count("Critical"),
        "expired": count("Expired"),
        "failed": count("Check Failed"),
    }

    monitoring = {
        "last_check": checked_at.strftime("%Y-%m-%d %H:%M UTC"),
        "next_check": next_check_text(settings),
    }

    return render_template(
        "index.html",
        websites=websites,
        stats=stats,
        limits=limits,
        monitoring=monitoring,
    )


# ---------------- ADD / EDIT / DELETE WEBSITE ----------------

@app.route("/add-website", methods=["POST"])
@requires("manage_websites")
def add_website():
    host, cert_name, error = validate_website_input()

    if error:
        flash(error, "error")
        return redirect(url_for("dashboard") + "#add-website")

    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO websites (host, cert_name, added_at)
                VALUES (?, ?, ?)
            """, (host, cert_name, iso_now()))

        log_activity(f"Added website {host}", "certificate",
                     f"Certbot certificate name: {cert_name}")
        flash(f"{host} was added successfully.", "success")

    except sqlite3.IntegrityError:
        flash(f"{host} is already registered.", "error")

    return redirect(url_for("dashboard"))


@app.route("/edit-website/<int:website_id>", methods=["GET", "POST"])
@requires("manage_websites")
def edit_website(website_id):
    website = get_website(website_id)

    if website is None:
        flash("Website not found.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        host, cert_name, error = validate_website_input()

        if error:
            flash(error, "error")
            return redirect(url_for("dashboard"))

        try:
            with db() as conn:
                conn.execute("""
                    UPDATE websites SET host = ?, cert_name = ? WHERE id = ?
                """, (host, cert_name, website_id))

            changes = []
            if host != website["host"]:
                changes.append(f"domain: {website['host']} -> {host}")
            if cert_name != website["cert_name"]:
                changes.append(f"certificate name: {website['cert_name']} -> {cert_name}")

            log_activity(f"Edited website {website['host']}", "certificate",
                         "; ".join(changes) or "No field changed")
            flash(f"{host} was updated successfully.", "success")

        except sqlite3.IntegrityError:
            flash("That domain is already registered.", "error")

    return redirect(url_for("dashboard"))


@app.route("/delete-website/<int:website_id>", methods=["POST"])
@requires("manage_websites")
def delete_website(website_id):
    website = get_website(website_id)

    if website is None:
        flash("Website not found.", "error")
        return redirect(url_for("dashboard"))

    with db() as conn:
        conn.execute("DELETE FROM websites WHERE id = ?", (website_id,))
        conn.execute(
            "UPDATE renewals SET status = 'Cancelled', updated_at = ? "
            "WHERE website_id = ? AND status IN ('Pending','Failed','Unverified')",
            (iso_now(), website_id),
        )

    invalidate(website["host"])
    log_activity(f"Deleted website {website['host']}", "certificate",
                 f"Certbot certificate name: {website['cert_name']}")
    flash(f"{website['host']} was removed from the dashboard.", "success")

    return redirect(url_for("dashboard"))


# ---------------- CERTIFICATE RENEWAL ----------------

def renew_certificate(cert_name, certbot_path="certbot"):
    if not CERT_NAME_PATTERN.fullmatch(cert_name):
        return False, "Invalid Certbot certificate name."

    if not CERTBOT_PATH_PATTERN.fullmatch(certbot_path or ""):
        return False, "Invalid Certbot path in Settings."

    try:
        result = subprocess.run(
            [certbot_path, "renew", "--cert-name", cert_name],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            shell=False,
        )

        if result.returncode != 0:
            message = result.stderr or result.stdout or "Certbot reported an error."
            return False, message[-1000:]

        return True, (
            result.stdout[-1000:]
            or "Certbot completed. Verify the live certificate."
        )

    except subprocess.TimeoutExpired:
        return False, "Certbot timed out after 5 minutes."

    except OSError as error:
        return False, f"Could not run Certbot: {error}"


def open_task_ids():
    with db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT website_id FROM renewals "
            "WHERE status IN ('Pending','Failed','Unverified')"
        ).fetchall()
    return {r["website_id"] for r in rows}


def create_task(website, source="manual", note=""):
    """Create a Pending renewal task unless the website already has an open one."""
    now = iso_now()
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM renewals WHERE website_id = ? "
            "AND status IN ('Pending','Failed','Unverified') LIMIT 1",
            (website["id"],),
        ).fetchone()
        if existing:
            return None
        cursor = conn.execute("""
            INSERT INTO renewals (website_id, host, cert_name, status, source,
                                  note, created_at, updated_at)
            VALUES (?, ?, ?, 'Pending', ?, ?, ?, ?)
        """, (website["id"], website["host"], website["cert_name"],
              source, note[:300], now, now))
        return cursor.lastrowid


def execute_renewal(website, task_id=None, source="manual"):
    """Run Certbot, verify the live certificate and record the result.

    Returns (status, message) where status is Completed, Unverified or Failed.
    """
    host = website["host"]
    settings = load_settings()
    limits = get_limits(settings)

    before = check_website(host, limits)
    old_expiry = before["expiry"] if before["days_left"] is not None else ""

    if task_id is None:
        task_id = create_task(website, source)
        if task_id is None:
            with db() as conn:
                task_id = conn.execute(
                    "SELECT id FROM renewals WHERE website_id = ? "
                    "AND status IN ('Pending','Failed','Unverified') "
                    "ORDER BY id DESC LIMIT 1", (website["id"],)
                ).fetchone()["id"]

    with db() as conn:
        conn.execute(
            "UPDATE renewals SET old_expiry = ?, host = ?, cert_name = ?, "
            "updated_at = ? WHERE id = ?",
            (old_expiry, host, website["cert_name"], iso_now(), task_id),
        )

    ok, message = renew_certificate(website["cert_name"], settings["certbot_path"])

    invalidate(host)
    after = check_website(host, limits)
    new_expiry = after["expiry"] if after["days_left"] is not None else ""

    if not ok:
        status, note = "Failed", message[-300:]
    else:
        replaced = after["days_left"] is not None and (
            before["days_left"] is None or after["expiry"] > before["expiry"]
        )
        if replaced:
            status = "Completed"
            note = f"Certificate replaced. New expiry {new_expiry}."
        else:
            status = "Unverified"
            note = ("Certbot finished but the live certificate did not change. "
                    "Reload your web server or check the Certbot output.")

    with db() as conn:
        conn.execute(
            "UPDATE renewals SET status = ?, new_expiry = ?, note = ?, updated_at = ? "
            "WHERE id = ?",
            (status, new_expiry, note, iso_now(), task_id),
        )

    log_activity(f"Renewal {status.lower()} for {host}", "renewal",
                 f"{old_expiry or '?'} -> {new_expiry or '?'} ({source})")
    return status, message


@app.route("/renew/<int:website_id>", methods=["POST"])
@requires("renew")
def manual_renew(website_id):
    website = get_website(website_id)

    if website is None:
        flash("Website not found.", "error")
        return respond("renewals")

    limits = get_limits()
    current = check_website(website["host"], limits)

    if current["days_left"] is None:
        flash(f"Cannot check {website['host']}. Check DNS and connectivity.", "error")
        return respond("renewals")

    if current["days_left"] > limits["renew"]:
        flash(f"{website['host']} does not need renewal yet.", "info")
        return respond("renewals")

    status, message = execute_renewal(website, source="manual")

    if status == "Completed":
        flash(f"Certificate for {website['host']} was renewed and verified.", "success")
    elif status == "Unverified":
        flash(f"Certbot completed for {website['host']}, but the live certificate "
              "has not changed yet. Reload your web server and re-check.", "info")
    else:
        flash(f"Renewal failed for {website['host']}: {message}", "error")

    return respond("renewals")


# ---------------- ALERT EMAILS ----------------

def smtp_configured(settings):
    return bool(settings["smtp_host"] and settings["smtp_from"])


def send_email(subject, body, recipients, settings):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings["smtp_from"]
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    host = settings["smtp_host"]
    port = as_int(settings["smtp_port"], 587, 1, 65535)
    security = settings["smtp_security"]
    context = ssl.create_default_context()

    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=20)

    with server:
        if security == "starttls":
            server.starttls(context=context)
        if settings["smtp_user"]:
            server.login(settings["smtp_user"], settings["smtp_password"])
        server.send_message(message)


def deliver(kind, subject, body, settings):
    """Send an email and record the outcome. Returns (ok, message)."""
    recipients = parse_recipients(settings["alert_recipients"])

    if not recipients:
        return False, "Add at least one recipient in Notifications & Alerts."
    if not smtp_configured(settings):
        return False, "Configure the SMTP server in Settings > Integrations first."

    try:
        send_email(subject, body, recipients, settings)
        status, detail, ok = "Sent", "", True
        message = f"Email sent to {', '.join(recipients)}."
    except Exception as error:
        status, detail, ok = "Failed", str(error)[:300], False
        message = f"Could not send email: {error}"

    with db() as conn:
        conn.execute(
            "INSERT INTO notification_log (kind, subject, recipients, status, detail, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (kind, subject, ", ".join(recipients), status, detail, iso_now()),
        )

    log_activity(f"Alert email {status.lower()} ({kind})", "alert", subject)
    return ok, message


def build_alert_items(websites, settings, dedupe):
    """Return [(website, text, primary_key, all_keys)] needing an alert."""
    reminder_days = parse_days(settings["reminder_days"])
    limits = get_limits(settings)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items = []

    for w in websites:
        days = w["days_left"]
        host = w["host"]

        if days is None:
            if as_bool(settings["alert_on_failed"]):
                key = f"failed|{host}|{today}"
                items.append((w, f"certificate check failed ({w['message']})", key, [key]))
        elif days < 0:
            key = f"expired|{host}|{w['expiry']}"
            items.append((w, f"EXPIRED {abs(days)} day(s) ago", key, [key]))
        elif dedupe:
            applicable = [r for r in reminder_days if days <= r]
            if applicable:
                tight = min(applicable)
                keys = [f"remind|{host}|{w['expiry']}|{r}" for r in applicable]
                key = f"remind|{host}|{w['expiry']}|{tight}"
                items.append((w, f"{days} day(s) left (reminder at {tight} days)", key, keys))
        elif days <= limits["warning"]:
            key = f"manual|{host}"
            items.append((w, f"{days} day(s) left", key, []))

    return items


def dispatch_alerts(settings, manual=False, websites=None):
    websites = websites if websites is not None else get_checked_websites()
    items = build_alert_items(websites, settings, dedupe=not manual)

    if not manual:
        with db() as conn:
            sent = {r["key"] for r in conn.execute("SELECT key FROM alert_keys")}
        items = [i for i in items if i[2] not in sent]

    if not items:
        return True, "No certificates need an alert right now."

    org = settings["org_name"]
    lines = [f"{org} - SSL certificate alert", f"Generated {fmt_ts(iso_now())}", ""]
    for w, text, _, _ in items:
        lines.append(f"- {w['host']}: {text} "
                     f"(valid until {w['expiry']}, issuer {w['issuer'] or 'unknown'})")
    lines += ["", "Open the dashboard to review and renew these certificates."]

    subject = f"[{org}] {len(items)} certificate(s) need attention"
    ok, message = deliver("manual" if manual else "reminder", subject, "\n".join(lines), settings)

    if ok and not manual:
        with db() as conn:
            for _, _, _, keys in items:
                for key in keys:
                    conn.execute("INSERT OR IGNORE INTO alert_keys (key, sent_at) VALUES (?, ?)",
                                 (key, iso_now()))
    return ok, message


# ---------------- BACKUPS ----------------

def create_backup(label=""):
    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"ssl_dashboard_{stamp}{'_' + label if label else ''}.db"
    target = BACKUP_DIR / name

    source = sqlite3.connect(DB_PATH)
    destination = sqlite3.connect(target)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()

    prune_backups()
    return name


def list_backups():
    BACKUP_DIR.mkdir(exist_ok=True)
    backups = []
    for path in BACKUP_DIR.iterdir():
        if path.is_file() and BACKUP_NAME_PATTERN.fullmatch(path.name):
            info = path.stat()
            backups.append({
                "name": path.name,
                "size_kb": max(1, info.st_size // 1024),
                "mtime": info.st_mtime,
                "created": fmt_epoch(info.st_mtime),
            })
    backups.sort(key=lambda b: b["mtime"], reverse=True)
    return backups


def prune_backups():
    keep = as_int(load_settings()["backup_keep"], 10, 1, 365)
    for old in list_backups()[keep:]:
        try:
            (BACKUP_DIR / old["name"]).unlink()
        except OSError:
            pass


def backup_path(name):
    if not BACKUP_NAME_PATTERN.fullmatch(name):
        abort(404)
    path = BACKUP_DIR / name
    if not path.is_file():
        abort(404)
    return path


# ---------------- BACKGROUND MONITORING ----------------

def monitor_cycle():
    settings = load_settings()
    limits = get_limits(settings)
    websites = get_checked_websites(force=True)

    for w in websites:
        due = w["days_left"] is not None and w["days_left"] <= limits["renew"]
        if not due:
            continue

        if as_bool(settings["auto_tasks"]):
            create_task(w, source="auto", note="Created automatically by monitoring.")

        if as_bool(settings["auto_renew"]):
            with db() as conn:
                last = conn.execute(
                    "SELECT status, updated_at FROM renewals WHERE website_id = ? "
                    "ORDER BY id DESC LIMIT 1", (w["id"],)
                ).fetchone()
            recent_failure = False
            if last and last["status"] in ("Failed", "Unverified"):
                try:
                    age = (datetime.now(timezone.utc)
                           - datetime.fromisoformat(last["updated_at"])).total_seconds()
                    recent_failure = age < 86400
                except ValueError:
                    pass
            if not recent_failure:
                execute_renewal(w, source="auto")

    if as_bool(settings["alerts_enabled"]):
        dispatch_alerts(load_settings(), manual=False, websites=get_checked_websites())

    if as_bool(settings["auto_backup"]):
        try:
            last = float(settings["last_backup_run"])
        except ValueError:
            last = 0
        if time.time() - last >= 86400:
            name = create_backup("auto")
            save_settings({"last_backup_run": time.time()})
            log_activity(f"Automatic backup created: {name}", "backup", user="System")

    save_settings({"last_monitor_run": time.time()})


def scheduler_loop():
    while True:
        time.sleep(60)
        try:
            settings = load_settings()
            if not as_bool(settings["monitor_enabled"]):
                continue
            interval = as_int(settings["monitor_interval_hours"], 12, 1, 168) * 3600
            try:
                last = float(settings["last_monitor_run"])
            except ValueError:
                last = 0
            if time.time() - last >= interval:
                monitor_cycle()
        except Exception:
            app.logger.exception("Background monitoring cycle failed")


def start_scheduler():
    if os.environ.get("ZAM_DISABLE_SCHEDULER") == "1":
        return
    if os.environ.get("FLASK_DEBUG") == "1" and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return   # the debug reloader's parent process must not run a second scheduler
    threading.Thread(target=scheduler_loop, name="zam-monitor", daemon=True).start()


# ---------------- POPUP PANELS ----------------

def respond(default="renewals"):
    name = request.values.get("panel", default)
    if name not in PANELS or not can(PANELS[name]["perm"]):
        name = default
    if is_fetch():
        return render_panel(name)
    return redirect(url_for("dashboard"))


def build_expiry(settings, limits):
    window = request.values.get("window", "all")
    refresh = request.args.get("refresh") == "1"
    websites = get_checked_websites(force=refresh)

    counts = {
        "due": sum(1 for w in websites if w["days_left"] is not None and w["days_left"] <= limits["renew"]),
        "expired": sum(w["status"] == "Expired" for w in websites),
        "critical": sum(w["status"] == "Critical" for w in websites),
        "warning": sum(w["status"] == "Expiring Soon" for w in websites),
        "healthy": sum(w["status"] == "Healthy" for w in websites),
        "failed": sum(w["status"] == "Check Failed" for w in websites),
    }

    rows = websites
    if window.isdigit():
        rows = [w for w in rows if w["days_left"] is not None and w["days_left"] <= int(window)]
    rows = sorted(rows, key=lambda w: (w["days_left"] is None, w["days_left"] or 0))

    stamps = [w["checked_at"] for w in websites]
    return {
        "rows": rows,
        "window": window,
        "counts": counts,
        "open_ids": open_task_ids(),
        "checked_at": fmt_epoch(min(stamps)) if stamps else None,
    }


def build_notifications(settings, limits):
    with db() as conn:
        history = [dict(r) for r in conn.execute(
            "SELECT * FROM notification_log ORDER BY id DESC LIMIT 15")]
    websites = get_checked_websites()
    attention = sum(1 for w in websites if w["days_left"] is None or w["days_left"] <= limits["warning"])
    return {
        "history": history,
        "smtp_ok": smtp_configured(settings),
        "attention": attention,
    }


def build_renewals(settings, limits):
    websites = get_checked_websites()
    with db() as conn:
        tasks = [dict(r) for r in conn.execute(
            "SELECT * FROM renewals ORDER BY "
            "CASE WHEN status IN ('Pending','Failed','Unverified') THEN 0 ELSE 1 END, "
            "id DESC LIMIT 100")]
    open_ids = {t["website_id"] for t in tasks if t["status"] in OPEN_STATUSES}
    due = [w for w in websites
           if w["days_left"] is not None and w["days_left"] <= limits["renew"]
           and w["id"] not in open_ids]
    return {"tasks": tasks, "due": due, "websites": websites, "open_statuses": OPEN_STATUSES}


def status_label(status):
    return "Warning" if status == "Expiring Soon" else status


def build_report(kind, days):
    if kind == "renewals":
        with db() as conn:
            data = conn.execute("SELECT * FROM renewals ORDER BY id DESC").fetchall()
        headers = ["Domain", "Certificate name", "Status", "Source", "Old expiry",
                   "New expiry", "Created", "Updated", "Note"]
        rows = [[r["host"], r["cert_name"], r["status"], r["source"], r["old_expiry"] or "—",
                 r["new_expiry"] or "—", fmt_ts(r["created_at"]), fmt_ts(r["updated_at"]),
                 r["note"]] for r in data]
        return REPORTS[kind], headers, rows

    websites = get_checked_websites()
    if kind == "expiring":
        websites = [w for w in websites if w["days_left"] is not None and w["days_left"] <= days]
        title = f"Certificates expiring within {days} days"
    elif kind == "problems":
        websites = [w for w in websites if w["status"] in ("Expired", "Check Failed")]
        title = REPORTS[kind]
    else:
        title = REPORTS[kind]

    websites.sort(key=lambda w: (w["days_left"] is None, w["days_left"] or 0))
    headers = ["Domain", "Certificate name", "Issuer", "Valid from", "Valid until",
               "Days left", "Status", "Message"]
    rows = [[w["host"], w["cert_name"], w["issuer"] or "—", w["valid_from"] or "—", w["expiry"],
             w["days_left"] if w["days_left"] is not None else "N/A",
             status_label(w["status"]), w["message"]] for w in websites]
    return title, headers, rows


def build_reports(settings, limits):
    kind = request.values.get("type", "status")
    if kind not in REPORTS:
        kind = "status"
    days = as_int(request.values.get("days", "30"), 30, 1, 3650)
    title, headers, rows = build_report(kind, days)
    return {
        "kind": kind, "days": days, "report_title": title, "headers": headers,
        "rows": rows[:50], "total": len(rows), "REPORTS": REPORTS,
    }


def build_audit(settings, limits):
    search = request.values.get("q", "").strip()
    category = request.values.get("category", "")
    if category not in AUDIT_CATEGORIES:
        category = ""
    per_page = as_int(settings["page_size"], 25, 5, 200)
    page = as_int(request.values.get("page", "1"), 1, 1, 100000)
    total, rows = query_audit(search, category, page, per_page)
    pages = max(1, -(-total // per_page))
    return {
        "q": search, "category": category, "page": min(page, pages), "pages": pages,
        "total": total, "entries": rows, "categories": AUDIT_CATEGORIES,
    }


def build_users(settings, limits):
    with db() as conn:
        users = [dict(r) for r in conn.execute(
            "SELECT id, username, email, role, active, perms, created_at, last_login "
            "FROM users ORDER BY username")]
    editing = None
    edit_id = as_int(request.values.get("edit"), 0, 0, 10**9)
    if edit_id and not g.get("close_edit"):
        editing = next((u for u in users if u["id"] == edit_id), None)
    return {
        "users": users, "auth_on": auth_enabled(), "role_perms": ROLE_PERMISSIONS,
        "permissions": PERMISSIONS, "editing": editing,
        "editing_perms": effective_permissions(editing) if editing else set(),
    }


def build_settings(settings, limits):
    tab = request.values.get("tab", "general")
    if tab not in ("general", "monitoring", "integrations", "backups"):
        tab = "general"
    return {
        "tab": tab,
        "backups": list_backups(),
        "last_run": fmt_epoch(settings["last_monitor_run"]),
        "next_run": next_check_text(settings),
        "smtp_password_set": bool(settings["smtp_password"]),
    }


PANEL_BUILDERS = {
    "expiry": build_expiry, "notifications": build_notifications,
    "renewals": build_renewals, "reports": build_reports, "audit": build_audit,
    "users": build_users, "settings": build_settings,
}


def render_panel(name):
    settings = load_settings()
    limits = get_limits(settings)
    context = {"panel": name, "meta": PANELS[name], "settings": settings, "limits": limits}
    context.update(PANEL_BUILDERS[name](settings, limits))
    return render_template("panels.html", **context)


@app.route("/panel/<name>")
def panel(name):
    if name not in PANELS:
        abort(404)
    if not can(PANELS[name]["perm"]):
        return Response(render_template("panels.html", panel="denied", meta=PANELS[name]), 403)
    return render_panel(name)


# ---- renewals ----

@app.route("/renewals/add", methods=["POST"])
@requires("renew")
def renewals_add():
    website = get_website(as_int(request.form.get("website_id"), 0, 0, 10**9))
    if website is None:
        flash("Choose a website first.", "error")
    elif create_task(website, "manual", request.form.get("note", "").strip()) is None:
        flash(f"{website['host']} already has an open renewal task.", "info")
    else:
        log_activity(f"Created renewal task for {website['host']}", "renewal")
        flash(f"Renewal task created for {website['host']}.", "success")
    return respond("renewals")


def _task(task_id):
    with db() as conn:
        return conn.execute("SELECT * FROM renewals WHERE id = ?", (task_id,)).fetchone()


@app.route("/renewals/<int:task_id>/run", methods=["POST"])
@requires("renew")
def renewals_run(task_id):
    task = _task(task_id)
    website = get_website(task["website_id"]) if task else None
    if task is None or website is None:
        flash("That task or its website no longer exists.", "error")
    else:
        status, message = execute_renewal(website, task_id=task_id, source="manual")
        if status == "Completed":
            flash(f"{website['host']} was renewed and verified.", "success")
        elif status == "Unverified":
            flash(f"Certbot finished for {website['host']}, but the live certificate "
                  "has not changed yet.", "info")
        else:
            flash(f"Renewal failed for {website['host']}: {message}", "error")
    return respond("renewals")


@app.route("/renewals/<int:task_id>/complete", methods=["POST"])
@requires("renew")
def renewals_complete(task_id):
    task = _task(task_id)
    if task is None:
        flash("Task not found.", "error")
    else:
        current = next((w for w in get_checked_websites() if w["id"] == task["website_id"]), None)
        new_expiry = current["expiry"] if current and current["days_left"] is not None else ""
        with db() as conn:
            conn.execute(
                "UPDATE renewals SET status = 'Completed', new_expiry = ?, "
                "note = 'Marked complete manually.', updated_at = ? WHERE id = ?",
                (new_expiry or task["new_expiry"], iso_now(), task_id))
        log_activity(f"Marked renewal complete for {task['host']}", "renewal")
        flash("Task marked as completed.", "success")
    return respond("renewals")


@app.route("/renewals/<int:task_id>/cancel", methods=["POST"])
@requires("renew")
def renewals_cancel(task_id):
    task = _task(task_id)
    if task:
        with db() as conn:
            conn.execute("UPDATE renewals SET status = 'Cancelled', updated_at = ? WHERE id = ?",
                         (iso_now(), task_id))
        log_activity(f"Cancelled renewal task for {task['host']}", "renewal")
        flash("Task cancelled.", "success")
    return respond("renewals")


@app.route("/renewals/<int:task_id>/delete", methods=["POST"])
@requires("renew")
def renewals_delete(task_id):
    task = _task(task_id)
    if task and task["status"] not in OPEN_STATUSES:
        with db() as conn:
            conn.execute("DELETE FROM renewals WHERE id = ?", (task_id,))
        log_activity(f"Deleted renewal record for {task['host']}", "renewal")
        flash("Record removed.", "success")
    return respond("renewals")


@app.route("/renewals/automation", methods=["POST"])
@requires("renew")
def renewals_automation():
    before = load_settings()
    updates = {
        "auto_tasks": "1" if request.form.get("auto_tasks") == "1" else "0",
        "auto_renew": "1" if request.form.get("auto_renew") == "1" else "0",
        "renew_before_days": str(as_int(request.form.get("renew_before_days"), 30, 1, 365)),
    }
    save_settings(updates)
    changed = [k for k, v in updates.items() if before[k] != v]
    log_activity("Updated renewal automation", "settings", ", ".join(changed) or "no change")
    flash("Renewal automation saved."
          + ("" if as_bool(load_settings()["monitor_enabled"]) else
             " Automation only runs while background monitoring is on (Settings > Monitoring)."),
          "success")
    return respond("renewals")


# ---- notifications ----

@app.route("/notifications/save", methods=["POST"])
@requires("manage_alerts")
def notifications_save():
    recipients = parse_recipients(request.form.get("alert_recipients", ""))
    bad = [r for r in recipients if not EMAIL_PATTERN.fullmatch(r)]
    days = parse_days(request.form.get("reminder_days", ""))
    enabled = request.form.get("alerts_enabled") == "1"

    if bad:
        flash(f"Invalid email address: {bad[0]}", "error")
    elif not days:
        flash("Enter at least one reminder day, for example 30, 14, 7, 1.", "error")
    elif enabled and not recipients:
        flash("Add at least one recipient before enabling alerts.", "error")
    else:
        save_settings({
            "alerts_enabled": "1" if enabled else "0",
            "alert_recipients": ", ".join(recipients),
            "reminder_days": ",".join(str(d) for d in days),
            "alert_on_failed": "1" if request.form.get("alert_on_failed") == "1" else "0",
        })
        log_activity("Updated alert settings", "settings",
                     f"recipients: {len(recipients)}; reminder days: {days}")
        flash("Alert settings saved.", "success")
    return respond("notifications")


@app.route("/notifications/test", methods=["POST"])
@requires("manage_alerts")
def notifications_test():
    settings = load_settings()
    org = settings["org_name"]
    ok, message = deliver("test", f"[{org}] Test alert",
                          f"This is a test email from {org} SSL monitoring.\n"
                          "If you can read this, alert delivery works.", settings)
    flash(message, "success" if ok else "error")
    return respond("notifications")


@app.route("/notifications/send-now", methods=["POST"])
@requires("manage_alerts")
def notifications_send_now():
    ok, message = dispatch_alerts(load_settings(), manual=True)
    flash(message, "success" if ok else "error")
    return respond("notifications")


# ---- reports ----

def csv_safe(value):
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def csv_response(filename, headers, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([csv_safe(v) for v in row])
    return Response(
        "\ufeff" + buffer.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/reports/export")
@requires("export_reports")
def reports_export():
    kind = request.args.get("type", "status")
    if kind not in REPORTS:
        abort(400)
    days = as_int(request.args.get("days", "30"), 30, 1, 3650)
    fmt = "print" if request.args.get("format") == "print" else "csv"

    title, headers, rows = build_report(kind, days)
    log_activity(f"Exported report: {title}", "report", f"format: {fmt}; rows: {len(rows)}")

    if fmt == "print":
        return render_template(
            "report.html", title=title, headers=headers, rows=rows,
            org=load_settings()["org_name"], generated=fmt_ts(iso_now()))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return csv_response(f"certcure_{kind}_{stamp}.csv", headers, rows)


# ---- audit ----

@app.route("/audit/export")
@requires("view_audit")
def audit_export():
    category = request.args.get("category", "")
    _, rows = query_audit(request.args.get("q", "").strip(),
                          category if category in AUDIT_CATEGORIES else "", per_page=None)
    log_activity("Exported audit log", "report", f"rows: {len(rows)}")
    return csv_response(
        "certcure_audit_log.csv",
        ["Time (UTC)", "User", "Category", "Action", "Detail"],
        [[fmt_ts(r["timestamp"]), r["user"], r["category"], r["action"], r["detail"]] for r in rows],
    )


# ---- users ----

def other_admins(conn, user_id):
    return conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1 "
        "AND password_hash != '' AND id != ?", (user_id,)
    ).fetchone()[0]


@app.route("/users/add", methods=["POST"])
@requires("manage_users")
def users_add():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "viewer")
    password = request.form.get("password", "")

    if not USERNAME_PATTERN.fullmatch(username):
        flash("Username must be 3-32 characters: letters, numbers, dot, dash or underscore.", "error")
    elif role not in ROLES:
        flash("Choose a valid role.", "error")
    elif email and not EMAIL_PATTERN.fullmatch(email):
        flash("Enter a valid email address or leave it empty.", "error")
    elif len(password) < 8:
        flash("The password must be at least 8 characters.", "error")
    else:
        first_admin = role == "admin" and not auth_enabled()
        try:
            with db() as conn:
                new_id = conn.execute(
                    "INSERT INTO users (username, email, role, password_hash, active, created_at) "
                    "VALUES (?, ?, ?, ?, 1, ?)",
                    (username, email, role, generate_password_hash(password), iso_now()),
                ).lastrowid
            log_activity(f"Created user {username}", "user", f"role: {ROLES[role]}")
            if first_admin:
                session["user_id"] = new_id
                flash(f"{username} created. Sign-in is now required for everyone.", "success")
            else:
                flash(f"User {username} created.", "success")
        except sqlite3.IntegrityError:
            flash("That username already exists.", "error")
    return respond("users")


@app.route("/users/<int:user_id>/update", methods=["POST"])
@requires("manage_users")
def users_update(user_id):
    form = request.form
    with db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            flash("User not found.", "error")
            return respond("users")

        username = form.get("username", target["username"]).strip()
        email = form.get("email", target["email"]).strip().lower()
        role = form.get("role", target["role"])
        active = form.get("active") == "1"
        password = form.get("password", "")
        confirm = form.get("password_confirm", password)
        custom_mode = form.get("perm_mode") == "custom"
        picked = [p for p in form.getlist("perm") if p in PERMISSIONS]
        perms = ",".join(sorted(set(picked) | {"view"})) if custom_mode and role != "admin" else ""

        me = current_user()
        was_admin = target["role"] == "admin" and target["active"] and target["password_hash"]

        error = None
        if not USERNAME_PATTERN.fullmatch(username):
            error = "Login name must be 3-32 characters: letters, numbers, dot, dash or underscore."
        elif email and not EMAIL_PATTERN.fullmatch(email):
            error = "Enter a valid email address or leave it empty."
        elif role not in ROLES:
            error = "Choose a valid role."
        elif password and len(password) < 8:
            error = "The new password must be at least 8 characters."
        elif password != confirm:
            error = "The two password fields do not match."
        elif me and me["id"] == user_id and not active:
            error = "You cannot deactivate your own account."
        elif was_admin and (role != "admin" or not active) and other_admins(conn, user_id) == 0:
            error = "At least one active administrator must remain."

        if error:
            flash(error, "error")
            return respond("users")

        try:
            conn.execute(
                "UPDATE users SET username = ?, email = ?, role = ?, active = ?, perms = ? "
                "WHERE id = ?",
                (username, email, role, 1 if active else 0, perms, user_id))
        except sqlite3.IntegrityError:
            flash("That login name is already taken.", "error")
            return respond("users")

        if password:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (generate_password_hash(password), user_id))

        changes = []
        if username != target["username"]:
            changes.append(f"login name: {target['username']} -> {username}")
        if email != target["email"]:
            changes.append("email changed")
        if role != target["role"]:
            changes.append(f"role: {ROLES[target['role']]} -> {ROLES[role]}")
        if active != bool(target["active"]):
            changes.append("activated" if active else "deactivated")
        if perms != target["perms"]:
            changes.append("custom permissions" if perms else "permissions reset to role defaults")
        if password:
            changes.append("password reset")

    log_activity(f"Updated user {target['username']}", "user", "; ".join(changes) or "no change")
    flash(f"{username} updated.", "success")
    g.close_edit = True
    return respond("users")


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@requires("manage_users")
def users_delete(user_id):
    with db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        me = current_user()
        if target is None:
            flash("User not found.", "error")
        elif me and me["id"] == user_id:
            flash("You cannot delete your own account.", "error")
        elif (target["role"] == "admin" and target["active"]
              and other_admins(conn, user_id) == 0):
            flash("At least one active administrator must remain.", "error")
        else:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            log_activity(f"Deleted user {target['username']}", "user")
            flash(f"{target['username']} was deleted.", "success")
    return respond("users")


# ---- settings & backups ----

@app.route("/settings/save", methods=["POST"])
@requires("manage_settings")
def settings_save():
    section = request.form.get("section", "")
    form = request.form
    current = load_settings()
    updates, error = {}, None

    if section == "general":
        org = form.get("org_name", "").strip()
        if not 1 <= len(org) <= 80:
            error = "Organisation name must be 1-80 characters."
        else:
            updates = {"org_name": org,
                       "page_size": str(as_int(form.get("page_size"), 25, 10, 100))}

    elif section == "monitoring":
        critical = as_int(form.get("critical_days"), -1, 0, 365)
        warning = as_int(form.get("warning_days"), -1, 1, 365)
        if critical < 0 or warning < 1 or warning <= critical:
            error = "Warning days must be greater than critical days (e.g. 30 and 7)."
        else:
            updates = {
                "critical_days": str(critical),
                "warning_days": str(warning),
                "check_timeout": str(as_int(form.get("check_timeout"), 10, 2, 60)),
                "monitor_enabled": "1" if form.get("monitor_enabled") == "1" else "0",
                "monitor_interval_hours": str(as_int(form.get("monitor_interval_hours"), 12, 1, 168)),
            }

    elif section == "integrations":
        host = form.get("smtp_host", "").strip()
        sender = form.get("smtp_from", "").strip()
        certbot = form.get("certbot_path", "").strip() or "certbot"
        security = form.get("smtp_security", "starttls")
        if security not in ("starttls", "ssl", "none"):
            security = "starttls"
        if sender and not EMAIL_PATTERN.fullmatch(sender):
            error = "The From address is not a valid email address."
        elif not CERTBOT_PATH_PATTERN.fullmatch(certbot):
            error = "The Certbot path may only contain letters, numbers and . / \\ : _ -"
        else:
            updates = {
                "smtp_host": host,
                "smtp_port": str(as_int(form.get("smtp_port"), 587, 1, 65535)),
                "smtp_security": security,
                "smtp_user": form.get("smtp_user", "").strip(),
                "smtp_from": sender,
                "certbot_path": certbot,
            }
            if form.get("smtp_password"):
                updates["smtp_password"] = form.get("smtp_password")

    elif section == "backups":
        updates = {
            "auto_backup": "1" if form.get("auto_backup") == "1" else "0",
            "backup_keep": str(as_int(form.get("backup_keep"), 10, 1, 365)),
        }
    else:
        error = "Unknown settings section."

    if error:
        flash(error, "error")
    else:
        save_settings(updates)
        changed = [k for k, v in updates.items() if current.get(k) != v]
        log_activity(f"Updated {section} settings", "settings", ", ".join(changed) or "no change")
        flash("Settings saved.", "success")
    return respond("settings")


@app.route("/settings/backup/create", methods=["POST"])
@requires("manage_settings")
def backup_create():
    try:
        name = create_backup()
        log_activity(f"Created backup {name}", "backup")
        flash(f"Backup created: {name}", "success")
    except (sqlite3.Error, OSError) as error:
        flash(f"Backup failed: {error}", "error")
    return respond("settings")


@app.route("/settings/backup/<name>/download")
@requires("manage_settings")
def backup_download(name):
    backup_path(name)
    log_activity(f"Downloaded backup {name}", "backup")
    return send_from_directory(BACKUP_DIR, name, as_attachment=True)


@app.route("/settings/backup/<name>/restore", methods=["POST"])
@requires("manage_settings")
def backup_restore(name):
    path = backup_path(name)
    try:
        safety = create_backup("prerestore")
        source = sqlite3.connect(path)
        destination = sqlite3.connect(DB_PATH)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        init_db()
        invalidate()
        log_activity(f"Restored backup {name}", "backup", f"safety copy: {safety}")
        flash(f"Backup {name} restored. A safety copy was saved as {safety}.", "success")
    except (sqlite3.Error, OSError) as error:
        flash(f"Restore failed: {error}", "error")
    return respond("settings")


@app.route("/settings/backup/<name>/delete", methods=["POST"])
@requires("manage_settings")
def backup_delete(name):
    path = backup_path(name)
    try:
        path.unlink()
        log_activity(f"Deleted backup {name}", "backup")
        flash("Backup deleted.", "success")
    except OSError as error:
        flash(f"Could not delete backup: {error}", "error")
    return respond("settings")


# ---------------- STARTUP ----------------

init_db()
start_scheduler()

if __name__ == "__main__":
    # Local development only. Do not expose the debug server publicly.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")