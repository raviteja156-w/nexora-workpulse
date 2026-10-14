"""NEXORA WORKPULSE - Team Work & Attendance Monitoring Portal (Flask).

Run locally:   flask --app app run --debug
Production:    gunicorn "app:create_app()"
CLI:           flask --app app init-db | create-admin
"""
import csv
import io
import os
import re
import secrets
from datetime import date, datetime, time, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote, unquote, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import (Blueprint, Flask, Response, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from models import (Acknowledgement, Assignment, AssignmentReview, AttendanceSession, AuditLog,
                    BreakRecord, Task, User, db, utcnow)


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


STATUS = {"not_started": "Not Started", "in_progress": "In Progress", "submitted": "Submitted",
          "completed": "Completed", "needs_changes": "Needs Changes"}
PRIORITIES = {"low": "Low", "medium": "Medium", "high": "High", "urgent": "Urgent"}
MIN_PASSWORD = 12
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

csrf = CSRFProtect()
limiter = Limiter(get_remote_address, default_limits=[], storage_uri="memory://")
bp = Blueprint("web", __name__)
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))  # equalises timing for unknown emails


# --------------------------------------------------------------------------- configuration
def normalize_database_url(raw):
    """Accept Supabase strings as pasted; fix [brackets] and special characters in the password."""
    url = raw.strip().strip('"').strip("'")
    if any(x in url for x in ("YOUR_DB_PASSWORD", "YOUR_PROJECT_REF", "YOUR-PASSWORD", "YOUR_REGION")):
        raise ConfigError("DATABASE_URL still contains placeholder text. Paste your real Supabase Session pooler string "
                          "with your real database password.")
    m = re.match(r"^postgres(?:ql)?(?:\+psycopg2)?://([^:/@]+):(.*)@([^@/]+)/([^?]*)(\?.*)?$", url)
    if not m:
        raise ConfigError("DATABASE_URL must look like postgresql://USER:PASSWORD@HOST:5432/postgres")
    user, pw, host, dbname, query = m.groups()
    if pw.startswith("[") and pw.endswith("]"):
        pw = pw[1:-1]
    pw = quote(unquote(pw), safe="")  # makes @ # / ? etc. in the password safe
    return f"postgresql+psycopg2://{user}:{pw}@{host}/{dbname or 'postgres'}{query or ''}"


def load_config():
    missing = [k for k in ("DATABASE_URL", "FLASK_SECRET_KEY") if not os.environ.get(k, "").strip()]
    if missing:
        raise ConfigError("Missing required environment variable(s): " + ", ".join(missing)
                          + ". Set them in Render > Environment (or in a local .env). See README.md.")
    secret = os.environ["FLASK_SECRET_KEY"].strip()
    if len(secret) < 32:
        raise ConfigError("FLASK_SECRET_KEY must be at least 32 characters long.")
    if secret.lower().startswith("replace-with"):
        raise ConfigError("FLASK_SECRET_KEY is still the placeholder. Run 'python make_env.py' or paste a real random key.")
    url = normalize_database_url(os.environ["DATABASE_URL"])
    tzname = os.environ.get("APP_TIMEZONE", "Asia/Kolkata")
    try:
        ZoneInfo(tzname)
        hours = float(os.environ.get("DAILY_TARGET_HOURS", "4"))
        max_hours = float(os.environ.get("SESSION_MAX_HOURS", "16"))
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"Invalid APP_TIMEZONE / DAILY_TARGET_HOURS / SESSION_MAX_HOURS: {exc}") from exc
    dev = os.environ.get("APP_ENV", "production").lower() == "development"
    return {
        "SECRET_KEY": secret,
        "SQLALCHEMY_DATABASE_URI": url,
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "pool_size": 5, "max_overflow": 5, "pool_recycle": 280, "pool_pre_ping": True,
            "connect_args": {"sslmode": os.environ.get("DB_SSLMODE", "require")},
        },
        "APP_TIMEZONE": tzname,
        "DAILY_TARGET_MINUTES": int(hours * 60),
        "SESSION_MAX_HOURS": max_hours,
        "DEV_MODE": dev,
        "SESSION_COOKIE_SECURE": not dev,
    }


def create_app(test_config=None):
    app = Flask(__name__)
    if test_config is None:
        try:
            from dotenv import load_dotenv
            load_dotenv(Path(__file__).parent / ".env", override=True)  # local only; Render has no .env file
        except ImportError:  # pragma: no cover
            pass
        app.config.update(load_config())
    else:
        app.config.update(test_config)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=256 * 1024,
        WTF_CSRF_TIME_LIMIT=None, SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # Render terminates TLS
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    app.register_blueprint(bp)
    register_filters(app)
    register_errors(app)
    register_cli(app)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        if not app.config.get("DEV_MODE") and not app.config.get("TESTING"):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


# --------------------------------------------------------------------------- time & attendance helpers
def tz():
    return ZoneInfo(current_app.config["APP_TIMEZONE"])


def to_local(dt):
    return dt.replace(tzinfo=timezone.utc).astimezone(tz())


def local_today():
    return to_local(utcnow()).date()


def day_bounds(d):
    start = datetime.combine(d, time.min, tzinfo=tz())
    end = datetime.combine(d + timedelta(days=1), time.min, tzinfo=tz())
    return (start.astimezone(timezone.utc).replace(tzinfo=None),
            end.astimezone(timezone.utc).replace(tzinfo=None))


def target_minutes():
    return current_app.config["DAILY_TARGET_MINUTES"]


def max_session():
    return timedelta(hours=current_app.config["SESSION_MAX_HOURS"])


def session_minutes(s, now):
    """Recorded minutes = (clock_out or now, capped) - clock_in - breaks. Server-side only."""
    end = s.clock_out or min(now, s.clock_in + max_session())
    total = (end - s.clock_in).total_seconds()
    for b in s.breaks:
        be = min(b.ended_at or end, end)
        if be > b.started_at:
            total -= (be - b.started_at).total_seconds()
    return max(total, 0.0) / 60.0


def is_stale(s, now):
    return s.clock_out is None and now - s.clock_in > max_session()


def empty_day():
    return dict(sessions=[], minutes=0.0, first_in=None, last_out=None, active=False,
                on_break=False, incomplete=False)


def build_daily(user_ids, start, end, now=None):
    """Aggregate attendance per (user_id, local date). A session belongs to its clock-in day."""
    now = now or utcnow()
    lo, hi = day_bounds(start)[0], day_bounds(end)[1]
    sessions = (AttendanceSession.query
                .filter(AttendanceSession.user_id.in_(list(user_ids)),
                        AttendanceSession.clock_in >= lo, AttendanceSession.clock_in < hi)
                .order_by(AttendanceSession.clock_in).all())
    out = {}
    for s in sessions:
        d = out.setdefault((s.user_id, to_local(s.clock_in).date()), empty_day())
        d["sessions"].append(s)
        d["minutes"] += session_minutes(s, now)
        d["first_in"] = d["first_in"] or s.clock_in
        if s.clock_out:
            d["last_out"] = max(d["last_out"] or s.clock_out, s.clock_out)
        else:
            d["active"] = True
            d["on_break"] = any(b.ended_at is None for b in s.breaks)
        if s.incomplete or is_stale(s, now):
            d["incomplete"] = True
    return out


def add_carryover(user_ids, daily, today, now):
    """Open sessions that started before today still count as active and must be visible/closable."""
    lo = day_bounds(today)[0]
    for s in AttendanceSession.query.filter(AttendanceSession.user_id.in_(list(user_ids)),
                                            AttendanceSession.clock_out.is_(None),
                                            AttendanceSession.clock_in < lo).all():
        d = daily.setdefault((s.user_id, today), empty_day())
        d["active"], d["first_in"] = True, d["first_in"] or s.clock_in
        d["on_break"] = d["on_break"] or any(b.ended_at is None for b in s.breaks)
        d["incomplete"] = d["incomplete"] or is_stale(s, now)
        d["sessions"].append(s)
    return daily


def attendance_status(day):
    if day["active"]:
        return "On Break" if day["on_break"] else "Clocked In"
    return "Clocked Out" if day["sessions"] else "Not Started"


# --------------------------------------------------------------------------- generic helpers
def clean(value, maxlen):
    return (value or "").strip()[:maxlen]


def parse_date(value):
    try:
        return date.fromisoformat((value or "").strip())
    except ValueError:
        return None


def valid_url(value):
    p = urlparse(value or "")
    return p.scheme in ("http", "https") and bool(p.netloc) and len(value) <= 500 and " " not in value


def audit(action, detail="", user_id=None):
    uid = user_id if user_id is not None else (g.user.id if getattr(g, "user", None) else None)
    db.session.add(AuditLog(user_id=uid, action=action, detail=detail[:500],
                            ip_address=(request.remote_addr or "")[:45]))


def csv_safe(value):
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def is_overdue(a):
    return a.status not in ("completed", "submitted") and a.task.deadline < local_today()


def check_new_password(pw, confirm):
    if len(pw) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if pw != confirm:
        return "Password confirmation does not match."
    return None


# --------------------------------------------------------------------------- auth
@bp.before_app_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        u = db.session.get(User, uid)
        if u and u.is_active and session.get("sv") == u.session_version:
            g.user = u
        else:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            return redirect(url_for("web.login"))
        return view(*a, **kw)
    return wrapped


def role_required(role):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapped(*a, **kw):
            if g.user.role != role:
                abort(403)
            return view(*a, **kw)
        return wrapped
    return deco


admin_required = role_required("admin")
member_required = role_required("member")


@bp.route("/")
def index():
    return redirect(url_for("web.dashboard" if g.user else "web.login"))


@bp.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "ok"}, 200
    except Exception:  # noqa: BLE001 - never leak details
        return {"status": "database unavailable"}, 503


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute;40 per hour", methods=["POST"])
def login():
    if g.user:
        return redirect(url_for("web.dashboard"))
    error, email = None, ""
    if request.method == "POST":
        email = clean(request.form.get("email"), 254).lower()
        password = request.form.get("password", "")[:200]
        if not EMAIL_RE.match(email) or not password:
            error = "Enter a valid email address and your password."
        else:
            user = User.query.filter_by(email=email).first()
            ok = check_password_hash(user.password_hash if user else DUMMY_HASH, password)
            if user and ok and user.is_active:
                session.clear()
                session.permanent = True
                session["uid"], session["sv"] = user.id, user.session_version
                user.last_login_at = utcnow()
                audit("login", "Signed in", user.id)
                db.session.commit()
                return redirect(url_for("web.dashboard"))
            audit("login_failed", f"email={email[:100]}")
            db.session.commit()
            error = "Incorrect email or password, or the account is disabled."
    return render_template("login.html", error=error, email=email)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", "Signed out")
    db.session.commit()
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("web.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new, confirm = request.form.get("new_password", ""), request.form.get("confirm_password", "")
        if not check_password_hash(g.user.password_hash, current):
            error = "Current password is incorrect."
        else:
            error = check_new_password(new, confirm)
        if not error:
            g.user.password_hash = generate_password_hash(new)
            g.user.session_version += 1
            session["sv"] = g.user.session_version
            audit("password_changed", "Own password changed")
            db.session.commit()
            flash("Password updated.", "success")
            return redirect(url_for("web.dashboard"))
    return render_template("password.html", error=error, min_length=MIN_PASSWORD)


# --------------------------------------------------------------------------- dashboards
@bp.route("/dashboard")
@login_required
def dashboard():
    return admin_dashboard() if g.user.role == "admin" else member_dashboard()


def member_dashboard():
    now, today = utcnow(), local_today()
    daily = add_carryover([g.user.id], build_daily([g.user.id], today, today, now), today, now)
    day = daily.get((g.user.id, today), empty_day())
    assignments = Assignment.query.join(Task).filter(Assignment.user_id == g.user.id).all()
    assignments.sort(key=lambda a: (a.status == "completed", a.task.deadline, a.id))
    ack_today = Acknowledgement.query.filter_by(user_id=g.user.id, ack_date=today).count() > 0
    hist = build_daily([g.user.id], today - timedelta(days=6), today, now)
    history = [(d, hist.get((g.user.id, d), empty_day()))
               for d in (today - timedelta(days=i) for i in range(7))]
    minutes, tgt = day["minutes"], target_minutes()
    return render_template(
        "member_dashboard.html", day=day, status=attendance_status(day), minutes=minutes,
        target=tgt, remaining=max(tgt - minutes, 0), pct=min(100, int(minutes * 100 / tgt)),
        assignments=assignments, overdue=[a for a in assignments if is_overdue(a)],
        ack_today=ack_today, history=history, values={}, errors=[])


def admin_dashboard():
    now, today = utcnow(), local_today()
    members = User.query.filter_by(role="member", is_active=True).order_by(User.name).all()
    ids = [m.id for m in members]
    daily = add_carryover(ids, build_daily(ids, today, today, now), today, now)
    by_user = {}
    for a in Assignment.query.filter(Assignment.user_id.in_(ids)).all():
        by_user.setdefault(a.user_id, []).append(a)
    acked = {r[0] for r in db.session.query(Acknowledgement.user_id)
             .filter(Acknowledgement.ack_date == today).all()}
    rows = []
    for m in members:
        d = daily.get((m.id, today), empty_day())
        mine = by_user.get(m.id, [])
        open_a = [a for a in mine if a.status != "completed"]
        rows.append(dict(user=m, day=d, status=attendance_status(d), tasks=len(mine), open=len(open_a),
                         progress=(sum(a.progress for a in open_a) // len(open_a)) if open_a else None,
                         acked=m.id in acked, met=d["minutes"] >= target_minutes(),
                         overdue=sum(1 for a in open_a if is_overdue(a))))
    stats = dict(
        members=len(members), clocked_in=sum(1 for r in rows if r["day"]["active"]),
        tasks=Task.query.count(),
        review=Assignment.query.filter_by(status="submitted").count(),
        met=sum(1 for r in rows if r["met"]))
    return render_template("admin_dashboard.html", rows=rows, stats=stats, target=target_minutes(), today=today)


# --------------------------------------------------------------------------- attendance (members)
def open_session(user_id):
    return AttendanceSession.query.filter_by(user_id=user_id, clock_out=None).first()


@bp.route("/clock-in", methods=["POST"])
@member_required
def clock_in():
    if open_session(g.user.id):
        flash("You already have an active session. Clock out first.", "warning")
    else:
        try:
            db.session.add(AttendanceSession(user_id=g.user.id, clock_in=utcnow()))
            audit("clock_in", "Clocked in")
            db.session.commit()
            flash("Clocked in. Your session is now being recorded.", "success")
        except IntegrityError:
            db.session.rollback()
            flash("You already have an active session.", "warning")
    return redirect(url_for("web.dashboard"))


@bp.route("/clock-out", methods=["POST"])
@member_required
def clock_out():
    s, now = open_session(g.user.id), utcnow()
    if not s:
        flash("You have no active session.", "warning")
        return redirect(url_for("web.dashboard"))
    if is_stale(s, now):  # forgotten session: cap at the maximum and flag it
        end, s.incomplete = s.clock_in + max_session(), True
        flash("Your previous session ran past the maximum length and was capped and flagged as incomplete.",
              "warning")
    else:
        end = now
    for b in s.breaks:
        if b.ended_at is None:
            b.ended_at = min(end, now)
    s.clock_out = end
    audit("clock_out", f"Recorded {session_minutes(s, now):.0f} minutes")
    db.session.commit()
    flash("Clocked out. Session saved.", "success")
    return redirect(url_for("web.dashboard"))


@bp.route("/break/start", methods=["POST"])
@member_required
def break_start():
    s = open_session(g.user.id)
    if not s:
        flash("Clock in before starting a break.", "warning")
    elif any(b.ended_at is None for b in s.breaks):
        flash("A break is already in progress.", "warning")
    else:
        db.session.add(BreakRecord(session_id=s.id, started_at=utcnow()))
        audit("break_start", "Break started")
        db.session.commit()
        flash("Break started. Break time is not counted toward your target.", "info")
    return redirect(url_for("web.dashboard"))


@bp.route("/break/end", methods=["POST"])
@member_required
def break_end():
    s = open_session(g.user.id)
    b = next((b for b in (s.breaks if s else []) if b.ended_at is None), None)
    if not b:
        flash("No break is in progress.", "warning")
    else:
        b.ended_at = utcnow()
        audit("break_end", "Break ended")
        db.session.commit()
        flash("Welcome back. Break ended.", "success")
    return redirect(url_for("web.dashboard"))


@bp.route("/attendance")
@member_required
def attendance_history():
    now, today = utcnow(), local_today()
    start = today - timedelta(days=29)
    daily = build_daily([g.user.id], start, today, now)
    days = [(d, daily[(g.user.id, d)]) for d in (today - timedelta(days=i) for i in range(30))
            if (g.user.id, d) in daily]
    return render_template("attendance.html", days=days, target=target_minutes())


# --------------------------------------------------------------------------- member tasks
@bp.route("/my-tasks/<int:aid>", methods=["GET", "POST"])
@member_required
def my_task(aid):
    a = db.session.get(Assignment, aid)
    if a is None or a.user_id != g.user.id:
        abort(404)
    errors = []
    locked = a.status in ("submitted", "completed")
    if request.method == "POST":
        if locked:
            abort(403)
        notes, url = clean(request.form.get("work_notes"), 5000), clean(request.form.get("deliverable_url"), 500)
        try:
            progress = int(request.form.get("progress", ""))
            if not 0 <= progress <= 100:
                raise ValueError
        except ValueError:
            progress = None
            errors.append("Progress must be a whole number from 0 to 100.")
        if url and not valid_url(url):
            errors.append("Deliverable link must be a valid http:// or https:// URL.")
        submit = request.form.get("action") == "submit"
        if submit and not (notes or url):
            errors.append("Add work notes or a deliverable link before submitting for review.")
        if not errors:
            a.progress, a.work_notes, a.deliverable_url = progress, notes, url or None
            if submit:
                a.status, a.submitted_at = "submitted", utcnow()
                audit("task_submitted", f"assignment={a.id} task={a.task_id}")
                flash("Submitted for review.", "success")
            else:
                if a.status in ("not_started", "needs_changes") and (progress > 0 or notes):
                    a.status = "in_progress"
                audit("task_progress", f"assignment={a.id} progress={progress}")
                flash("Progress saved.", "success")
            db.session.commit()
            return redirect(url_for("web.my_task", aid=a.id))
    return render_template("my_task.html", a=a, errors=errors, locked=locked, form=request.form)


@bp.route("/acknowledgement", methods=["POST"])
@member_required
def submit_ack():
    f = request.form
    v = {k: clean(f.get(k), n) for k, n in (("tasks_worked", 3000), ("work_completed", 5000),
                                            ("deliverable_links", 2000), ("problems", 3000),
                                            ("pending_work", 3000), ("next_steps", 3000))}
    errors = []
    if not v["tasks_worked"]:
        errors.append("List the tasks you worked on.")
    if not v["work_completed"]:
        errors.append("Describe the work you completed.")
    for line in filter(None, (x.strip() for x in v["deliverable_links"].splitlines())):
        if not valid_url(line):
            errors.append("Each deliverable link must be a full http:// or https:// URL, one per line.")
            break
    if errors:
        return render_template("ack_form_page.html", values=v, errors=errors), 400
    db.session.add(Acknowledgement(user_id=g.user.id, ack_date=local_today(), **v))
    audit("acknowledgement", "Daily acknowledgement submitted")
    db.session.commit()
    flash("Daily work acknowledgement recorded.", "success")
    return redirect(url_for("web.dashboard"))


# --------------------------------------------------------------------------- admin: users
@bp.route("/admin/users")
@admin_required
def users():
    return render_template("users.html", users=User.query.order_by(User.role, User.name).all())


@bp.route("/admin/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    errors, v = [], {"name": "", "email": ""}
    if request.method == "POST":
        v = {"name": clean(request.form.get("name"), 80), "email": clean(request.form.get("email"), 254).lower()}
        pw, confirm = request.form.get("password", ""), request.form.get("confirm_password", "")
        if len(v["name"]) < 2:
            errors.append("Name must be at least 2 characters.")
        if not EMAIL_RE.match(v["email"]):
            errors.append("Enter a valid email address.")
        elif User.query.filter_by(email=v["email"]).first():
            errors.append("An account with this email already exists.")
        err = check_new_password(pw, confirm)
        if err:
            errors.append(err)
        if not errors:
            try:
                u = User(name=v["name"], email=v["email"], role="member", password_hash=generate_password_hash(pw))
                db.session.add(u)
                db.session.flush()
                audit("user_created", f"user={u.id} email={u.email}")
                db.session.commit()
                flash(f"Account created for {u.name}. Share the password securely.", "success")
                return redirect(url_for("web.users"))
            except IntegrityError:
                db.session.rollback()
                errors.append("An account with this email already exists.")
    return render_template("user_form.html", errors=errors, v=v, min_length=MIN_PASSWORD)


@bp.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def user_toggle(uid):
    u = db.session.get(User, uid) or abort(404)
    if u.id == g.user.id:
        flash("You cannot disable your own account.", "warning")
    else:
        u.is_active = not u.is_active
        u.session_version += 1  # signs the user out immediately
        audit("user_enabled" if u.is_active else "user_disabled", f"user={u.id}")
        db.session.commit()
        flash(f"{u.name} is now {'active' if u.is_active else 'disabled'}.", "success")
    return redirect(url_for("web.users"))


@bp.route("/admin/users/<int:uid>/reset-password", methods=["POST"])
@admin_required
def user_reset(uid):
    u = db.session.get(User, uid) or abort(404)
    pw = request.form.get("password", "")
    err = check_new_password(pw, pw)
    if err:
        flash(err, "error")
    else:
        u.password_hash = generate_password_hash(pw)
        u.session_version += 1
        audit("password_reset", f"user={u.id}")
        db.session.commit()
        flash(f"Password reset for {u.name}.", "success")
    return redirect(url_for("web.users"))


# --------------------------------------------------------------------------- admin: tasks
def parse_task_form(form, members):
    v = {k: clean(form.get(k), n) for k, n in (("title", 150), ("description", 5000),
                                               ("expected_deliverable", 1000), ("instructions", 3000),
                                               ("priority", 10), ("target_hours", 10),
                                               ("start_date", 10), ("deadline", 10))}
    errors = []
    if len(v["title"]) < 3:
        errors.append("Task title must be at least 3 characters.")
    if not v["description"]:
        errors.append("A detailed description is required.")
    if v["priority"] not in PRIORITIES:
        errors.append("Choose a valid priority.")
    try:
        hours = float(v["target_hours"])
        if not 0 < hours <= 200:
            raise ValueError
    except ValueError:
        hours = None
        errors.append("Target hours must be a number greater than 0 and at most 200.")
    sd, dl = parse_date(v["start_date"]), parse_date(v["deadline"])
    if not sd or not dl:
        errors.append("Start date and deadline are required.")
    elif dl < sd:
        errors.append("Deadline cannot be before the start date.")
    valid_ids = {m.id for m in members}
    all_team = form.get("all_team") == "1"
    ids = valid_ids if all_team else {int(x) for x in form.getlist("assignees") if x.isdigit()} & valid_ids
    if not ids:
        errors.append("Select at least one team member, or choose the entire team.")
    return v, hours, sd, dl, ids, all_team, errors


def apply_task_fields(task, v, hours, sd, dl):
    task.title, task.description, task.priority = v["title"], v["description"], v["priority"]
    task.target_hours, task.start_date, task.deadline = hours, sd, dl
    task.expected_deliverable, task.instructions = v["expected_deliverable"] or None, v["instructions"] or None


@bp.route("/admin/tasks")
@admin_required
def tasks():
    items = Task.query.order_by(Task.deadline.desc(), Task.id.desc()).all()
    return render_template("tasks.html", tasks=items)


@bp.route("/admin/tasks/new", methods=["GET", "POST"])
@admin_required
def task_new():
    members = User.query.filter_by(role="member", is_active=True).order_by(User.name).all()
    errors, v, selected, all_team = [], {"priority": "medium", "start_date": local_today().isoformat()}, set(), False
    if request.method == "POST":
        v, hours, sd, dl, selected, all_team, errors = parse_task_form(request.form, members)
        if not errors:
            t = Task(created_by=g.user.id)
            apply_task_fields(t, v, hours, sd, dl)
            db.session.add(t)
            db.session.flush()
            for uid in selected:
                db.session.add(Assignment(task_id=t.id, user_id=uid))
            audit("task_created", f"task={t.id} assignees={len(selected)}")
            db.session.commit()
            flash(f"Task posted to {len(selected)} team member(s).", "success")
            return redirect(url_for("web.task_detail", tid=t.id))
    return render_template("task_form.html", task=None, members=members, v=v, selected=selected,
                           all_team=all_team, errors=errors)


@bp.route("/admin/tasks/<int:tid>/edit", methods=["GET", "POST"])
@admin_required
def task_edit(tid):
    t = db.session.get(Task, tid) or abort(404)
    members = User.query.filter_by(role="member", is_active=True).order_by(User.name).all()
    existing = {a.user_id: a for a in t.assignments}
    errors, selected, all_team = [], set(existing), False
    v = dict(title=t.title, description=t.description, priority=t.priority, target_hours=t.target_hours,
             start_date=t.start_date.isoformat(), deadline=t.deadline.isoformat(),
             expected_deliverable=t.expected_deliverable or "", instructions=t.instructions or "")
    if request.method == "POST":
        v, hours, sd, dl, selected, all_team, errors = parse_task_form(request.form, members)
        if not errors:
            apply_task_fields(t, v, hours, sd, dl)
            kept = 0
            for uid in selected - set(existing):
                db.session.add(Assignment(task_id=t.id, user_id=uid))
            for uid, a in existing.items():
                if uid not in selected:
                    if a.status == "not_started":
                        db.session.delete(a)
                    else:
                        kept += 1
            audit("task_edited", f"task={t.id} assignees={len(selected)}")
            db.session.commit()
            flash("Task updated." + (f" {kept} member(s) with work in progress kept on the task." if kept else ""),
                  "success")
            return redirect(url_for("web.task_detail", tid=t.id))
    return render_template("task_form.html", task=t, members=members, v=v, selected=selected,
                           all_team=all_team, errors=errors)


@bp.route("/admin/tasks/<int:tid>")
@admin_required
def task_detail(tid):
    t = db.session.get(Task, tid) or abort(404)
    assignments = sorted(t.assignments, key=lambda a: a.user.name.lower())
    return render_template("task_detail.html", task=t, assignments=assignments)


@bp.route("/admin/assignments/<int:aid>/review", methods=["POST"])
@admin_required
def review(aid):
    a = db.session.get(Assignment, aid) or abort(404)
    decision, feedback = request.form.get("decision"), clean(request.form.get("feedback"), 3000)
    if a.status != "submitted":
        flash("Only submitted work can be reviewed.", "warning")
    elif decision not in ("approved", "changes"):
        flash("Choose approve or request changes.", "error")
    elif decision == "changes" and not feedback:
        flash("Feedback is required when requesting changes.", "error")
    else:
        if decision == "approved":
            a.status, a.completed_at, a.progress = "completed", utcnow(), 100
        else:
            a.status = "needs_changes"
        db.session.add(AssignmentReview(assignment_id=a.id, reviewer_id=g.user.id, decision=decision,
                                        feedback=feedback or None))
        audit("task_reviewed", f"assignment={a.id} decision={decision}")
        db.session.commit()
        flash("Work approved." if decision == "approved" else "Changes requested.", "success")
    return redirect(url_for("web.task_detail", tid=a.task_id))


# --------------------------------------------------------------------------- admin: acknowledgements, audit
@bp.route("/admin/acknowledgements")
@admin_required
def acknowledgements():
    q = Acknowledgement.query.join(User)
    uid, d1, d2 = request.args.get("user_id", ""), parse_date(request.args.get("start")), parse_date(request.args.get("end"))
    if uid.isdigit():
        q = q.filter(Acknowledgement.user_id == int(uid))
    if d1:
        q = q.filter(Acknowledgement.ack_date >= d1)
    if d2:
        q = q.filter(Acknowledgement.ack_date <= d2)
    items = q.order_by(Acknowledgement.created_at.desc()).limit(200).all()
    members = User.query.filter_by(role="member").order_by(User.name).all()
    return render_template("acknowledgements.html", items=items, members=members, f=request.args)


@bp.route("/admin/audit")
@admin_required
def audit_log():
    items = AuditLog.query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(200).all()
    return render_template("audit.html", items=items)


# --------------------------------------------------------------------------- admin: reports
def report_data(args):
    today = local_today()
    rng, errors = args.get("range", "week"), []
    if rng == "today":
        start, end = today, today
    elif rng == "month":
        start, end = today.replace(day=1), today
    elif rng == "custom":
        start, end = parse_date(args.get("start")), parse_date(args.get("end"))
        if not start or not end:
            errors.append("Enter both a start and an end date.")
            start, end = today - timedelta(days=today.weekday()), today
        elif end < start or (end - start).days > 92:
            errors.append("End date must not precede the start date, and the range is limited to 93 days.")
            start, end = today - timedelta(days=today.weekday()), today
    else:
        rng, start, end = "week", today - timedelta(days=today.weekday()), today
    members = User.query.filter_by(role="member").order_by(User.name).all()
    uid = args.get("user_id", "")
    chosen = [m for m in members if uid.isdigit() and m.id == int(uid)] or members
    ids = [m.id for m in chosen]
    daily = build_daily(ids, start, end)
    counts = {}
    for u, st, n in (db.session.query(Assignment.user_id, Assignment.status, func.count())
                     .join(Task).filter(Task.start_date <= end, Task.deadline >= start,
                                        Assignment.user_id.in_(ids))
                     .group_by(Assignment.user_id, Assignment.status).all()):
        counts.setdefault(u, {})[st] = n
    ack_days = {}
    for u, d in (db.session.query(Acknowledgement.user_id, Acknowledgement.ack_date)
                 .filter(Acknowledgement.ack_date >= start, Acknowledgement.ack_date <= end,
                         Acknowledgement.user_id.in_(ids)).distinct().all()):
        ack_days.setdefault(u, set()).add(d)
    tgt = target_minutes()
    summary, detail = [], []
    for m in chosen:
        c = counts.get(m.id, {})
        mine = {d: v for (u, d), v in daily.items() if u == m.id}
        summary.append(dict(
            user=m, days=len(mine), minutes=sum(v["minutes"] for v in mine.values()),
            met=sum(1 for v in mine.values() if v["minutes"] >= tgt),
            assigned=sum(c.values()), submitted=c.get("submitted", 0), completed=c.get("completed", 0),
            pending=c.get("not_started", 0) + c.get("in_progress", 0) + c.get("needs_changes", 0),
            acks=len(ack_days.get(m.id, ()))))
        for d in sorted(mine, reverse=True):
            v = mine[d]
            detail.append(dict(date=d, user=m, day=v, met=v["minutes"] >= tgt,
                               acked=d in ack_days.get(m.id, ())))
    detail.sort(key=lambda r: (r["date"], r["user"].name), reverse=True)
    return dict(rng=rng, start=start, end=end, members=members, uid=uid, summary=summary,
                detail=detail, errors=errors, target=tgt)


@bp.route("/admin/reports")
@admin_required
def reports():
    return render_template("reports.html", **report_data(request.args))


@bp.route("/admin/reports/export.csv")
@admin_required
def reports_export():
    data = report_data(request.args)
    by_user = {s["user"].id: s for s in data["summary"]}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Date", "Employee", "Email", "First login", "Last logout", "Recorded minutes", "Recorded duration",
                "Target achieved", "Incomplete session", "Acknowledgement submitted", "Assigned tasks (period)",
                "Submitted", "Completed", "Pending"])
    for r in data["detail"]:
        s, d = by_user[r["user"].id], r["day"]
        mins = int(round(d["minutes"]))
        w.writerow([csv_safe(x) for x in [
            r["date"].isoformat(), r["user"].name, r["user"].email,
            to_local(d["first_in"]).strftime("%H:%M") if d["first_in"] else "",
            to_local(d["last_out"]).strftime("%H:%M") if d["last_out"] else ("Active" if d["active"] else ""),
            mins, f"{mins // 60}h {mins % 60:02d}m", "Yes" if r["met"] else "No",
            "Yes" if d["incomplete"] else "No", "Yes" if r["acked"] else "No",
            s["assigned"], s["submitted"], s["completed"], s["pending"]]])
    audit("report_exported", f"{data['start']}..{data['end']}")
    db.session.commit()
    name = f"workpulse_report_{data['start']}_{data['end']}.csv"
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# --------------------------------------------------------------------------- template filters, errors
def register_filters(app):
    @app.template_filter("hm")
    def hm(minutes):
        m = int(round(minutes or 0))
        return f"{m // 60}h {m % 60:02d}m"

    @app.template_filter("ltime")
    def ltime(dt):
        return to_local(dt).strftime("%I:%M %p").lstrip("0") if dt else "—"

    @app.template_filter("ldt")
    def ldt(dt):
        return to_local(dt).strftime("%d %b %Y, %I:%M %p") if dt else "—"

    @app.template_filter("ldate")
    def ldate(d):
        return d.strftime("%a, %d %b %Y") if d else "—"

    app.jinja_env.globals.update(STATUS=STATUS, PRIORITIES=PRIORITIES, is_overdue=is_overdue,
                                 session_mins=lambda s: session_minutes(s, utcnow()))


def register_errors(app):
    def page(code, title, msg):
        return render_template("error.html", code=code, title=title, message=msg), code

    @app.errorhandler(403)
    def e403(_):
        return page(403, "Access denied", "Your account does not have permission to view this page.")

    @app.errorhandler(404)
    def e404(_):
        return page(404, "Page not found", "The page you requested does not exist or is not available to you.")

    @app.errorhandler(429)
    def e429(_):
        return page(429, "Too many attempts", "Please wait a few minutes before trying again.")

    @app.errorhandler(CSRFError)
    def ecsrf(_):
        return page(400, "Session expired", "Your form session expired or was invalid. Go back, refresh, and try again.")

    @app.errorhandler(500)
    def e500(_):
        db.session.rollback()
        return page(500, "Something went wrong", "An unexpected error occurred. Nothing has been exposed; please try again.")


# --------------------------------------------------------------------------- CLI
def run_migrations():
    folder = Path(__file__).parent / "migrations"
    with db.engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS nwp_schema_migrations (version VARCHAR(100) PRIMARY KEY, "
                             "applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        done = {r[0] for r in conn.exec_driver_sql("SELECT version FROM nwp_schema_migrations")}
        for f in sorted(folder.glob("*.sql")):
            if f.name not in done:
                conn.exec_driver_sql(f.read_text(encoding="utf-8"))
                conn.exec_driver_sql("INSERT INTO nwp_schema_migrations (version) VALUES (%s)", (f.name,))
                print(f"Applied migration {f.name}")
    print("Database schema is up to date.")


def create_admin(email, password, name="Administrator"):
    """Create an admin. Never overwrites an existing account. Returns (ok, message)."""
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return False, "ADMIN_EMAIL is missing or not a valid email address."
    if len(password or "") < MIN_PASSWORD:
        return False, f"ADMIN_PASSWORD must be at least {MIN_PASSWORD} characters."
    if User.query.filter_by(email=email).first():
        return False, "An account with that email already exists; nothing changed."
    u = User(name=name[:80], email=email, role="admin", password_hash=generate_password_hash(password))
    db.session.add(u)
    db.session.flush()
    db.session.add(AuditLog(user_id=u.id, action="admin_created", detail="Initial administrator created"))
    db.session.commit()
    return True, f"Administrator {email} created."


def prepare_database():
    """Create/upgrade nwp_ tables (safe, additive) and create the first admin if none exists."""
    run_migrations()
    if User.query.filter_by(role="admin").count():
        print("An administrator already exists; skipping admin bootstrap.")
    elif os.environ.get("ADMIN_EMAIL") and os.environ.get("ADMIN_PASSWORD"):
        print(create_admin(os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"],
                           os.environ.get("ADMIN_NAME", "Administrator"))[1])
    else:
        print("No administrator yet. Set ADMIN_EMAIL and ADMIN_PASSWORD in .env and start again.")


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Apply SQL migrations (safe, additive) and create the first admin if none exists."""
        prepare_database()

    @app.cli.command("create-admin")
    def create_admin_cmd():
        """Create an administrator from ADMIN_EMAIL / ADMIN_PASSWORD (never overwrites)."""
        ok, msg = create_admin(os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_PASSWORD"),
                               os.environ.get("ADMIN_NAME", "Administrator"))
        print(msg)
        raise SystemExit(0 if ok else 1)


DEMO_ADMIN = ("admin@example.com", "Admin-Demo-2026!")
DEMO_MEMBER_PW = "Member-Demo-2026!"


def demo_config():
    """Local-only fallback: SQLite file + auto-generated secret, so the app can be explored with zero setup."""
    base = Path(__file__).parent
    keyfile = base / ".local_secret"
    if not keyfile.exists():
        keyfile.write_text(secrets.token_urlsafe(48))
    return {
        "SECRET_KEY": keyfile.read_text().strip(),
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(base / "workpulse_demo.db"),
        "APP_TIMEZONE": os.environ.get("APP_TIMEZONE", "Asia/Kolkata"),
        "DAILY_TARGET_MINUTES": 240, "SESSION_MAX_HOURS": 16,
        "DEV_MODE": True, "SESSION_COOKIE_SECURE": False,
    }


def seed_demo():
    if User.query.count():
        return
    today = local_today()
    db.session.add(User(name="Demo Admin", email=DEMO_ADMIN[0], role="admin",
                        password_hash=generate_password_hash(DEMO_ADMIN[1])))
    members = [User(name=n, email=e, role="member", password_hash=generate_password_hash(DEMO_MEMBER_PW))
               for n, e in (("Mia Member", "mia@example.com"), ("Raj Member", "raj@example.com"))]
    db.session.add_all(members)
    db.session.flush()
    t = Task(title="Prepare weekly status report", description="Collect progress from your work this week and "
             "write a one-page summary.", priority="high", target_hours=3, start_date=today,
             deadline=today + timedelta(days=3), expected_deliverable="Link to the report document",
             instructions="Keep it short and factual.", created_by=1)
    db.session.add(t)
    db.session.flush()
    for m in members:
        db.session.add(Assignment(task_id=t.id, user_id=m.id))
    db.session.commit()


if __name__ == "__main__":
    # Local use:  python app.py   ->  http://127.0.0.1:5000
    # (Render uses gunicorn "app:create_app()" instead and always needs real settings.)
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent / ".env", override=True)
    except ImportError:
        pass
    _demo = not os.environ.get("DATABASE_URL", "").strip()
    try:
        _app = create_app(demo_config()) if _demo else create_app()
    except ConfigError as exc:
        raise SystemExit(f"\nCONFIGURATION ERROR: {exc}\n")
    try:
        with _app.app_context():
            if _demo:
                db.create_all()
                seed_demo()
            else:
                print("Connecting to the database and preparing tables ...")
                prepare_database()
    except Exception as exc:  # noqa: BLE001
        raise SystemExit("\nDATABASE ERROR: could not connect or set up the tables.\n"
                         "Check DATABASE_URL (use the Supabase *Session pooler* string, correct password).\n"
                         f"Technical detail: {type(exc).__name__}: {str(exc).splitlines()[0][:200]}\n")
    _port = int(os.environ.get("PORT", "5000"))
    print("\n" + "=" * 62)
    print("NEXORA WORKPULSE is running.   Open:  http://127.0.0.1:%d" % _port)
    if _demo:
        print("DEMO MODE (no Supabase needed; data is in workpulse_demo.db)")
        print("  Admin  : %s  /  %s" % DEMO_ADMIN)
        print("  Member : mia@example.com  /  %s" % DEMO_MEMBER_PW)
        print("  Member : raj@example.com  /  %s" % DEMO_MEMBER_PW)
    print("Press CTRL+C to stop.")
    print("=" * 62 + "\n")
    _app.run(host="127.0.0.1", port=_port, debug=False)
