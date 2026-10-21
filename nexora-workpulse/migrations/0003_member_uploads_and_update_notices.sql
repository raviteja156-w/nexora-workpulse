-- Additive schema for member uploads, signatures, and admin update notices.
-- File bytes are stored in PostgreSQL so uploaded deliverables persist across Render restarts.
-- Existing project, attendance, task, and user data is preserved.
ALTER TABLE nwp_project_files ADD COLUMN IF NOT EXISTS file_data BYTEA;
ALTER TABLE nwp_agreement_confirmations ADD COLUMN IF NOT EXISTS signature_data BYTEA;
CREATE TABLE IF NOT EXISTS nwp_project_notices (
 id SERIAL PRIMARY KEY,
 title VARCHAR(200) NOT NULL,
 message TEXT NOT NULL,
 created_by INTEGER NOT NULL REFERENCES nwp_users(id),
 created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_nwp_project_notices_created ON nwp_project_notices(created_at DESC);

CREATE TABLE IF NOT EXISTS nwp_project_notice_acknowledgements (
 id SERIAL PRIMARY KEY,
 notice_id INTEGER NOT NULL REFERENCES nwp_project_notices(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES nwp_users(id),
 acknowledged_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT uq_nwp_notice_ack_user UNIQUE (notice_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_nwp_notice_ack_notice ON nwp_project_notice_acknowledgements(notice_id);
