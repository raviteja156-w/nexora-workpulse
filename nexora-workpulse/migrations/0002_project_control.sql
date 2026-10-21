-- Additive project-control migration. Existing project/task/attendance records are preserved.
ALTER TABLE nwp_users DROP CONSTRAINT IF EXISTS ck_nwp_users_role;
ALTER TABLE nwp_users ADD CONSTRAINT ck_nwp_users_role CHECK (role IN ('admin','member','founder','connector'));

-- Retain historical foreign-key records but revoke access for all non-admin accounts.
UPDATE nwp_users SET is_active = FALSE, session_version = session_version + 1 WHERE role <> 'admin';

CREATE TABLE IF NOT EXISTS nwp_project_stages (
 id SERIAL PRIMARY KEY, name VARCHAR(120) NOT NULL, description TEXT, position INTEGER NOT NULL DEFAULT 0,
 status VARCHAR(20) NOT NULL DEFAULT 'upcoming', progress INTEGER NOT NULL DEFAULT 0,
 responsible_person VARCHAR(120), start_date DATE, due_date DATE, completion_date DATE,
 admin_approved BOOLEAN NOT NULL DEFAULT FALSE, updated_by INTEGER REFERENCES nwp_users(id),
 updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_nwp_project_stages_order ON nwp_project_stages(position, id);

CREATE TABLE IF NOT EXISTS nwp_project_updates (
 id SERIAL PRIMARY KEY, title VARCHAR(200) NOT NULL, description TEXT NOT NULL,
 update_type VARCHAR(30) NOT NULL DEFAULT 'update', submitted_by INTEGER NOT NULL REFERENCES nwp_users(id),
 status VARCHAR(20) NOT NULL DEFAULT 'pending', reviewer_comment TEXT,
 reviewed_by INTEGER REFERENCES nwp_users(id), created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TIMESTAMP WITHOUT TIME ZONE
);
CREATE INDEX IF NOT EXISTS ix_nwp_project_updates_status ON nwp_project_updates(status, created_at);

CREATE TABLE IF NOT EXISTS nwp_project_files (
 id SERIAL PRIMARY KEY, title VARCHAR(200) NOT NULL, filename VARCHAR(255) NOT NULL,
 storage_path VARCHAR(1000) NOT NULL, description TEXT, task_id INTEGER REFERENCES nwp_tasks(id),
 submission_notes TEXT, submitted_by INTEGER NOT NULL REFERENCES nwp_users(id),
 status VARCHAR(20) NOT NULL DEFAULT 'pending', reviewer_comment TEXT,
 uploaded_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_by INTEGER REFERENCES nwp_users(id), reviewed_at TIMESTAMP WITHOUT TIME ZONE
);
CREATE INDEX IF NOT EXISTS ix_nwp_project_files_status ON nwp_project_files(status, uploaded_at);

CREATE TABLE IF NOT EXISTS nwp_project_agreements (
 id SERIAL PRIMARY KEY, version INTEGER NOT NULL, title VARCHAR(200) NOT NULL DEFAULT 'NEXORA WORKPULSE Project Agreement',
 body TEXT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'draft', updated_by INTEGER REFERENCES nwp_users(id),
 created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_nwp_agreement_version ON nwp_project_agreements(version DESC);

CREATE TABLE IF NOT EXISTS nwp_agreement_confirmations (
 id SERIAL PRIMARY KEY, agreement_id INTEGER NOT NULL REFERENCES nwp_project_agreements(id),
 user_id INTEGER NOT NULL REFERENCES nwp_users(id), confirmation VARCHAR(20) NOT NULL,
 signature_path VARCHAR(1000), confirmed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_nwp_agreement_confirmations_version ON nwp_agreement_confirmations(agreement_id, confirmed_at DESC);
