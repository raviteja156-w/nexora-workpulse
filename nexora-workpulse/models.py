"""Database models. All tables use the `nwp_` prefix to avoid clashing with existing NEXORA tables."""
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, text

db = SQLAlchemy()


def utcnow():
    """Naive UTC timestamp generated on the server."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "nwp_users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(254), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="member")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    __table_args__ = (db.CheckConstraint("role IN ('admin','member')", name="ck_nwp_users_role"),)


class Task(db.Model):
    __tablename__ = "nwp_tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(10), nullable=False, default="medium")
    target_hours = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    expected_deliverable = db.Column(db.String(1000))
    instructions = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey("nwp_users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    assignments = db.relationship("Assignment", back_populates="task", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_nwp_tasks_deadline", "deadline"),)


class Assignment(db.Model):
    """One row per (task, team member). Progress and status are tracked per member."""
    __tablename__ = "nwp_task_assignments"
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("nwp_tasks.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("nwp_users.id"), nullable=False)
    status = db.Column(db.String(15), nullable=False, default="not_started")
    progress = db.Column(db.Integer, nullable=False, default=0)
    work_notes = db.Column(db.Text)
    deliverable_url = db.Column(db.String(500))
    submitted_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    task = db.relationship("Task", back_populates="assignments")
    user = db.relationship("User")
    reviews = db.relationship("AssignmentReview", back_populates="assignment",
                              order_by="AssignmentReview.created_at.desc()", cascade="all, delete-orphan")
    __table_args__ = (
        db.UniqueConstraint("task_id", "user_id", name="uq_nwp_assignment_task_user"),
        Index("ix_nwp_assign_user_status", "user_id", "status"),
    )


class AssignmentReview(db.Model):
    __tablename__ = "nwp_task_reviews"
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey("nwp_task_assignments.id", ondelete="CASCADE"), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("nwp_users.id"), nullable=False)
    decision = db.Column(db.String(10), nullable=False)  # approved | changes
    feedback = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    assignment = db.relationship("Assignment", back_populates="reviews")
    reviewer = db.relationship("User")
    __table_args__ = (Index("ix_nwp_reviews_assignment", "assignment_id"),)


class AttendanceSession(db.Model):
    __tablename__ = "nwp_attendance_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("nwp_users.id"), nullable=False)
    clock_in = db.Column(db.DateTime, nullable=False, default=utcnow)
    clock_out = db.Column(db.DateTime)
    incomplete = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    user = db.relationship("User")
    breaks = db.relationship("BreakRecord", back_populates="session", lazy="selectin",
                             cascade="all, delete-orphan", order_by="BreakRecord.started_at")
    __table_args__ = (
        Index("ix_nwp_att_user_in", "user_id", "clock_in"),
        # Database-level guarantee: at most one open session per user.
        Index("uq_nwp_att_one_open", "user_id", unique=True,
              postgresql_where=text("clock_out IS NULL"), sqlite_where=text("clock_out IS NULL")),
    )


class BreakRecord(db.Model):
    __tablename__ = "nwp_break_records"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("nwp_attendance_sessions.id", ondelete="CASCADE"), nullable=False)
    started_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    ended_at = db.Column(db.DateTime)
    session = db.relationship("AttendanceSession", back_populates="breaks")
    __table_args__ = (
        Index("ix_nwp_break_session", "session_id"),
        Index("uq_nwp_break_one_open", "session_id", unique=True,
              postgresql_where=text("ended_at IS NULL"), sqlite_where=text("ended_at IS NULL")),
    )


class Acknowledgement(db.Model):
    __tablename__ = "nwp_acknowledgements"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("nwp_users.id"), nullable=False)
    ack_date = db.Column(db.Date, nullable=False)  # local calendar day, server-derived
    tasks_worked = db.Column(db.Text, nullable=False)
    work_completed = db.Column(db.Text, nullable=False)
    deliverable_links = db.Column(db.Text)
    problems = db.Column(db.Text)
    pending_work = db.Column(db.Text)
    next_steps = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    user = db.relationship("User")
    __table_args__ = (Index("ix_nwp_ack_user_date", "user_id", "ack_date"),)


class AuditLog(db.Model):
    __tablename__ = "nwp_audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("nwp_users.id"))
    action = db.Column(db.String(60), nullable=False)
    detail = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    user = db.relationship("User")
    __table_args__ = (Index("ix_nwp_audit_created", "created_at"),)
