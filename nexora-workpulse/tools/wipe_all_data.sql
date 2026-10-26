-- NEXORA WORKPULSE: delete ALL WorkPulse data and start fresh.
-- Run once in Supabase -> SQL Editor (after deploying v2 so nwp_task_updates / nwp_settings exist).
-- Keeps ONLY administrator accounts so you can still sign in. Touches nwp_* tables only.
-- THIS CANNOT BE UNDONE.
BEGIN;
DELETE FROM nwp_task_updates;
DELETE FROM nwp_task_reviews;
DELETE FROM nwp_task_assignments;
DELETE FROM nwp_tasks;
DELETE FROM nwp_break_records;
DELETE FROM nwp_attendance_sessions;
DELETE FROM nwp_acknowledgements;
DELETE FROM nwp_audit_logs;
DELETE FROM nwp_users WHERE role <> 'admin';
UPDATE nwp_users SET first_login_at = NULL;
COMMIT;
