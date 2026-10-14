from datetime import datetime, timedelta

import pytest

from app import (ConfigError, build_daily, create_admin, create_app, local_today, session_minutes, to_local)
from models import (Acknowledgement, Assignment, AttendanceSession, AuditLog, BreakRecord, Task, User, db, utcnow)
from tests.conftest import PW, login, make_app

TASK = {"title": "Quarterly report", "description": "Compile numbers", "priority": "high", "target_hours": "3",
        "start_date": "2026-01-01", "deadline": "2099-01-31", "expected_deliverable": "PDF", "instructions": ""}


def uid(app, email):
    with app.app_context():
        return User.query.filter_by(email=email).one().id


def post_task(admin, **over):
    data = {**TASK, **over}
    return admin.post("/admin/tasks/new", data=data, follow_redirects=False)


# ---------------------------------------------------------------- configuration
def test_missing_env_fails_clearly(monkeypatch):
    for k in ("DATABASE_URL", "FLASK_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ConfigError) as e:
        create_app()
    assert "DATABASE_URL" in str(e.value) and "FLASK_SECRET_KEY" in str(e.value)


def test_short_secret_rejected(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h:5432/db")
    monkeypatch.setenv("FLASK_SECRET_KEY", "short")
    with pytest.raises(ConfigError):
        create_app()


def test_valid_env_builds_postgres_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
    monkeypatch.setenv("FLASK_SECRET_KEY", "x" * 40)
    a = create_app()
    assert a.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql+psycopg2://")
    assert a.config["SESSION_COOKIE_SECURE"] is True and a.config["SESSION_COOKIE_HTTPONLY"] is True


# ---------------------------------------------------------------- auth & access
def test_login_page_has_warning_and_no_register(app):
    c = app.test_client()
    html = c.get("/login").get_data(as_text=True)
    assert "YOUR WORK IS OBSERVED" in html and "visible to authorized administrators" in html
    assert c.get("/register").status_code == 404 and c.post("/register").status_code == 404


def test_login_success_failure_and_disabled(app):
    c = app.test_client()
    assert login(c, "mia@example.com").status_code == 302
    c2 = app.test_client()
    r = login(c2, "mia@example.com", "wrong-password-123")
    assert r.status_code == 200 and b"Incorrect email or password" in r.data
    assert login(app.test_client(), "nobody@example.com").status_code == 200
    with app.app_context():
        User.query.filter_by(email="mia@example.com").one().is_active = False
        db.session.commit()
    assert b"disabled" in login(app.test_client(), "mia@example.com").data
    with app.app_context():
        assert AuditLog.query.filter_by(action="login_failed").count() >= 2


def test_unauthenticated_redirected(app):
    c = app.test_client()
    for url in ("/dashboard", "/admin/users", "/admin/reports", "/attendance"):
        assert c.get(url).status_code == 302
    assert c.post("/clock-in").status_code == 302


def test_member_cannot_access_admin_routes(mia):
    for url in ("/admin/users", "/admin/users/new", "/admin/tasks", "/admin/tasks/new", "/admin/reports",
                "/admin/reports/export.csv", "/admin/acknowledgements", "/admin/audit"):
        assert mia.get(url).status_code == 403, url
    assert mia.post("/admin/users/1/toggle").status_code == 403
    assert mia.post("/admin/assignments/1/review", data={"decision": "approved"}).status_code == 403


def test_admin_cannot_use_member_actions(admin):
    assert admin.post("/clock-in").status_code == 403
    assert admin.get("/attendance").status_code == 403


def test_logout_and_session_invalidation(app):
    c = app.test_client(); login(c, "mia@example.com")
    assert c.get("/dashboard").status_code == 200
    assert c.post("/logout").status_code == 302
    assert c.get("/dashboard").status_code == 302


def test_disable_user_logs_them_out(app, admin, mia):
    assert mia.get("/dashboard").status_code == 200
    admin.post(f"/admin/users/{uid(app, 'mia@example.com')}/toggle")
    assert mia.get("/dashboard").status_code == 302


def test_csrf_enforced_when_enabled():
    app = make_app(WTF_CSRF_ENABLED=True)
    c = app.test_client()
    r = c.post("/login", data={"email": "mia@example.com", "password": PW})
    assert r.status_code == 400


def test_login_rate_limited():
    app = make_app(RATELIMIT_ENABLED=True)
    c = app.test_client()
    codes = [login(c, "mia@example.com", "bad-password-xyz").status_code for _ in range(12)]
    assert 429 in codes


def test_security_headers_and_health(app):
    c = app.test_client()
    r = c.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY" and "script-src 'none'" in r.headers["Content-Security-Policy"]
    h = c.get("/health")
    assert h.status_code == 200 and h.get_json() == {"status": "ok"}


def test_pages_never_expose_secrets(app, admin):
    body = admin.get("/admin/users").get_data(as_text=True)
    assert "password_hash" not in body and "scrypt:" not in body and "pbkdf2:" not in body
    with app.app_context():
        assert User.query.first().password_hash.startswith(("scrypt:", "pbkdf2:"))


# ---------------------------------------------------------------- user management
def test_admin_creates_member_and_validation(app, admin):
    bad = admin.post("/admin/users/new", data={"name": "X", "email": "bad", "password": "short", "confirm_password": "x"})
    assert bad.status_code == 200 and b"valid email" in bad.data
    dup = admin.post("/admin/users/new", data={"name": "Dup", "email": "MIA@example.com", "password": PW, "confirm_password": PW})
    assert b"already exists" in dup.data
    ok = admin.post("/admin/users/new", data={"name": "New Person", "email": "new@example.com", "password": PW, "confirm_password": PW})
    assert ok.status_code == 302
    c = app.test_client()
    assert login(c, "new@example.com").status_code == 302
    with app.app_context():
        u = User.query.filter_by(email="new@example.com").one()
        assert u.role == "member" and PW not in u.password_hash


def test_create_admin_never_overwrites(app):
    with app.app_context():
        assert create_admin("fresh@example.com", PW)[0] is True
        assert create_admin("fresh@example.com", "AnotherLongPass123")[0] is False
        assert create_admin("x@example.com", "short")[0] is False


def test_password_change(app, mia):
    r = mia.post("/account/password", data={"current_password": "nope", "new_password": "NewPassword-12345", "confirm_password": "NewPassword-12345"})
    assert b"incorrect" in r.data
    r = mia.post("/account/password", data={"current_password": PW, "new_password": "NewPassword-12345", "confirm_password": "NewPassword-12345"})
    assert r.status_code == 302 and mia.get("/dashboard").status_code == 200
    assert login(app.test_client(), "mia@example.com", "NewPassword-12345").status_code == 302


# ---------------------------------------------------------------- attendance
def test_duration_example_login_9_logout_130_break_30_is_4_hours(app):
    with app.app_context():
        u = uid(app, "mia@example.com")
        s = AttendanceSession(user_id=u, clock_in=datetime(2026, 3, 2, 3, 30), clock_out=datetime(2026, 3, 2, 8, 0))  # 9:00-13:30 IST
        s.breaks.append(BreakRecord(started_at=datetime(2026, 3, 2, 5, 0), ended_at=datetime(2026, 3, 2, 5, 30)))
        db.session.add(s); db.session.commit()
        assert session_minutes(s, utcnow()) == pytest.approx(240.0)
        d = build_daily([u], datetime(2026, 3, 2).date(), datetime(2026, 3, 2).date())[(u, datetime(2026, 3, 2).date())]
        assert d["minutes"] == pytest.approx(240.0) and d["minutes"] >= 240 and not d["active"]


def test_multiple_sessions_sum_and_clock_in_day_attribution(app):
    with app.app_context():
        u = uid(app, "mia@example.com")
        day = datetime(2026, 3, 3).date()
        db.session.add_all([
            AttendanceSession(user_id=u, clock_in=datetime(2026, 3, 3, 4, 0), clock_out=datetime(2026, 3, 3, 6, 0)),
            AttendanceSession(user_id=u, clock_in=datetime(2026, 3, 3, 7, 0), clock_out=datetime(2026, 3, 3, 8, 30))])
        db.session.commit()
        d = build_daily([u], day, day)[(u, day)]
        assert d["minutes"] == pytest.approx(210.0) and len(d["sessions"]) == 2


def test_clock_flow_duplicate_prevention_and_server_time(app, mia):
    mia.post("/clock-in", data={"clock_in": "2000-01-01T00:00:00"})
    r = mia.post("/clock-in", follow_redirects=True)
    assert b"already have an active session" in r.data
    with app.app_context():
        rows = AttendanceSession.query.all()
        assert len(rows) == 1 and rows[0].clock_in.year >= 2026  # client-sent timestamp ignored
    mia.post("/break/start"); assert b"already in progress" in mia.post("/break/start", follow_redirects=True).data
    mia.post("/break/end")
    mia.post("/clock-out")
    with app.app_context():
        s = AttendanceSession.query.one()
        assert s.clock_out is not None and len(s.breaks) == 1 and s.breaks[0].ended_at is not None
    assert b"no active session" in mia.post("/clock-out", follow_redirects=True).data


def test_database_blocks_two_open_sessions(app):
    from sqlalchemy.exc import IntegrityError
    with app.app_context():
        u = uid(app, "mia@example.com")
        db.session.add(AttendanceSession(user_id=u)); db.session.commit()
        db.session.add(AttendanceSession(user_id=u))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_stale_session_flagged_and_capped(app, mia):
    with app.app_context():
        u = uid(app, "mia@example.com")
        db.session.add(AttendanceSession(user_id=u, clock_in=utcnow() - timedelta(hours=20))); db.session.commit()
        s = AttendanceSession.query.one()
        assert session_minutes(s, utcnow()) == pytest.approx(16 * 60)
    assert b"incomplete" in mia.get("/dashboard").data.lower()
    mia.post("/clock-out")
    with app.app_context():
        s = AttendanceSession.query.one()
        assert s.incomplete is True and session_minutes(s, utcnow()) == pytest.approx(16 * 60)


def test_member_dashboard_progress_and_admin_target_flag(app, mia, admin):
    with app.app_context():
        u = uid(app, "mia@example.com")
        now = utcnow()
        db.session.add(AttendanceSession(user_id=u, clock_in=now - timedelta(hours=5), clock_out=now - timedelta(minutes=30)))
        db.session.commit()
    html = mia.get("/dashboard").get_data(as_text=True)
    assert "Target achieved" in html and "YOUR WORK IS OBSERVED" in html
    a = admin.get("/dashboard").get_data(as_text=True)
    assert "Target met" in a and "POST A TASK" in a and "YOUR WORK IS OBSERVED" in a


# ---------------------------------------------------------------- tasks & reviews
def test_task_validation_and_all_team_assignment(app, admin):
    r = post_task(admin, title="", target_hours="0", deadline="2025-01-01")
    assert r.status_code == 200 and b"title" in r.data and b"Target hours" in r.data and b"Deadline cannot" in r.data
    assert b"Select at least one" in post_task(admin).data
    r = post_task(admin, all_team="1")
    assert r.status_code == 302
    with app.app_context():
        assert Task.query.count() == 1 and Assignment.query.count() == 2


def test_assign_individual_edit_and_reassign(app, admin):
    mia_id, raj_id = uid(app, "mia@example.com"), uid(app, "raj@example.com")
    post_task(admin, assignees=[str(mia_id)])
    with app.app_context():
        assert [a.user_id for a in Assignment.query.all()] == [mia_id]
        tid = Task.query.one().id
    admin.post(f"/admin/tasks/{tid}/edit", data={**TASK, "title": "Renamed", "priority": "urgent", "assignees": [str(raj_id)]})
    with app.app_context():
        assert Task.query.one().title == "Renamed" and [a.user_id for a in Assignment.query.all()] == [raj_id]


def test_full_submission_and_review_cycle(app, admin, mia, raj):
    mia_id = uid(app, "mia@example.com")
    post_task(admin, assignees=[str(mia_id)])
    with app.app_context():
        aid = Assignment.query.one().id
    # another member cannot see or touch it
    assert raj.get(f"/my-tasks/{aid}").status_code == 404
    assert raj.post(f"/my-tasks/{aid}", data={"progress": "100", "action": "submit", "work_notes": "x"}).status_code == 404
    # validation
    assert b"valid http" in mia.post(f"/my-tasks/{aid}", data={"progress": "50", "deliverable_url": "javascript:alert(1)", "action": "save"}).data
    assert b"whole number" in mia.post(f"/my-tasks/{aid}", data={"progress": "500", "action": "save"}).data
    assert b"Add work notes" in mia.post(f"/my-tasks/{aid}", data={"progress": "100", "action": "submit"}).data
    # progress then submit
    mia.post(f"/my-tasks/{aid}", data={"progress": "40", "work_notes": "halfway", "action": "save"})
    with app.app_context():
        assert Assignment.query.one().status == "in_progress"
    mia.post(f"/my-tasks/{aid}", data={"progress": "100", "work_notes": "done", "deliverable_url": "https://example.com/doc", "action": "submit"})
    with app.app_context():
        assert Assignment.query.one().status == "submitted"
    assert mia.post(f"/my-tasks/{aid}", data={"progress": "10", "action": "save"}).status_code == 403  # locked while in review
    assert b"Awaiting review" in admin.get("/dashboard").data
    # admin requires feedback to request changes
    assert b"Feedback is required" in admin.post(f"/admin/assignments/{aid}/review", data={"decision": "changes"}, follow_redirects=True).data
    admin.post(f"/admin/assignments/{aid}/review", data={"decision": "changes", "feedback": "Add charts"})
    with app.app_context():
        assert Assignment.query.one().status == "needs_changes"
    assert b"Add charts" in mia.get(f"/my-tasks/{aid}").data
    mia.post(f"/my-tasks/{aid}", data={"progress": "100", "work_notes": "charts added", "action": "submit"})
    admin.post(f"/admin/assignments/{aid}/review", data={"decision": "approved"})
    with app.app_context():
        a = Assignment.query.one()
        assert a.status == "completed" and a.progress == 100 and len(a.reviews) == 2
    assert admin.get(f"/admin/tasks/{a.task_id}").status_code == 200


def test_attendance_does_not_complete_tasks(app, admin, mia):
    post_task(admin, all_team="1")
    mia.post("/clock-in")
    with app.app_context():
        s = AttendanceSession.query.one(); s.clock_in = utcnow() - timedelta(hours=5); db.session.commit()
        assert all(a.status == "not_started" for a in Assignment.query.all())


# ---------------------------------------------------------------- acknowledgements & reports
def test_acknowledgement_flow_and_admin_review(app, admin, mia, raj):
    bad = mia.post("/acknowledgement", data={"tasks_worked": "", "work_completed": ""})
    assert bad.status_code == 400 and b"List the tasks" in bad.data
    assert mia.post("/acknowledgement", data={"tasks_worked": "T1", "work_completed": "W", "deliverable_links": "notaurl"}).status_code == 400
    ok = mia.post("/acknowledgement", data={"tasks_worked": "Report", "work_completed": "Wrote draft", "deliverable_links": "https://example.com/a",
                                            "problems": "None", "pending_work": "Review", "next_steps": "Publish"})
    assert ok.status_code == 302
    with app.app_context():
        a = Acknowledgement.query.one()
        assert a.user_id == uid(app, "mia@example.com") and a.created_at and a.ack_date == local_today()
    page = admin.get("/admin/acknowledgements").get_data(as_text=True)
    assert "Wrote draft" in page and "Mia Member" in page
    assert b"No acknowledgements" in admin.get(f"/admin/acknowledgements?user_id={uid(app, 'raj@example.com')}").data
    assert raj.get("/admin/acknowledgements").status_code == 403


def test_report_and_csv_export(app, admin, mia):
    with app.app_context():
        u = uid(app, "mia@example.com"); now = utcnow()
        db.session.add(AttendanceSession(user_id=u, clock_in=now - timedelta(hours=5), clock_out=now - timedelta(hours=1)))
        db.session.commit()
    post_task(admin, all_team="1")
    mia.post("/acknowledgement", data={"tasks_worked": "=cmd()", "work_completed": "x"})
    html = admin.get("/admin/reports?range=today").get_data(as_text=True)
    assert "Mia Member" in html and "Achieved" in html
    r = admin.get("/admin/reports/export.csv?range=today")
    assert r.status_code == 200 and r.mimetype == "text/csv" and "attachment" in r.headers["Content-Disposition"]
    text = r.get_data(as_text=True)
    assert "Mia Member" in text and "Yes" in text and "Raj Member" not in text.split("\n", 1)[1]
    assert b"limited to 93 days" in admin.get("/admin/reports?range=custom&start=2020-01-01&end=2026-01-01").data
    assert admin.get(f"/admin/reports?range=week&user_id={uid(app, 'raj@example.com')}").status_code == 200


def test_every_template_renders(app, admin, mia):
    post_task(admin, all_team="1")
    for url in ("/dashboard", "/admin/users", "/admin/users/new", "/admin/tasks", "/admin/tasks/new", "/admin/tasks/1",
                "/admin/tasks/1/edit", "/admin/acknowledgements", "/admin/audit", "/admin/reports", "/account/password"):
        assert admin.get(url).status_code == 200, url
    for url in ("/dashboard", "/attendance", "/account/password", "/my-tasks/1"):
        assert mia.get(url).status_code in (200, 404), url
    assert mia.get("/nope").status_code == 404


# ---------------------------------------------------------------- database URL handling
def test_database_url_special_characters_and_brackets():
    from app import normalize_database_url
    u = normalize_database_url("postgresql://postgres.abc:p@ss#w/rd?@aws-0-x.pooler.supabase.com:5432/postgres")
    assert u == "postgresql+psycopg2://postgres.abc:p%40ss%23w%2Frd%3F@aws-0-x.pooler.supabase.com:5432/postgres"
    assert "%40" in normalize_database_url("postgres://u:[a@b]@h:5432/postgres")
    assert normalize_database_url("postgresql://u:already%40enc@h:5432/db").count("%40") == 1


def test_placeholder_values_rejected(monkeypatch):
    from app import normalize_database_url
    with pytest.raises(ConfigError):
        normalize_database_url("postgresql://postgres.YOUR_PROJECT_REF:YOUR_DB_PASSWORD@h:5432/postgres")
    with pytest.raises(ConfigError):
        normalize_database_url("not-a-url")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h:5432/db")
    monkeypatch.setenv("FLASK_SECRET_KEY", "replace-with-a-long-random-string-of-at-least-32-characters")
    with pytest.raises(ConfigError):
        create_app()
