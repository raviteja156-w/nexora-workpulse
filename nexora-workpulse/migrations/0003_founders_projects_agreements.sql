-- NEXORA WORKPULSE v3: founder accounts, founder projects, change requests, agreements with digital signature.
-- Additive: new tables and one new column. The role check is widened to allow 'founder'.
ALTER TABLE nwp_users DROP CONSTRAINT IF EXISTS ck_nwp_users_role;
-- Clean up role values typed by hand (e.g. 'Founder', ' admin ', 'co-founder') before enforcing the rule.
ALTER TABLE nwp_users ALTER COLUMN role TYPE VARCHAR(20);
UPDATE nwp_users SET role = lower(trim(role)) WHERE role IS DISTINCT FROM lower(trim(role));
UPDATE nwp_users SET role = 'admin' WHERE role IN ('administrator','superadmin','super_admin','super admin','owner');
UPDATE nwp_users SET role = 'founder' WHERE role IN ('founders','co-founder','cofounder','co founder','client','customer');
UPDATE nwp_users SET role = 'member' WHERE role IS NULL OR role NOT IN ('admin','member','founder');
ALTER TABLE nwp_users ADD CONSTRAINT ck_nwp_users_role CHECK (role IN ('admin','member','founder'));

CREATE TABLE IF NOT EXISTS nwp_projects (
	id SERIAL NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	summary TEXT, 
	live_url VARCHAR(500), 
	phase VARCHAR(20) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	progress INTEGER NOT NULL, 
	status_note TEXT, 
	start_date DATE, 
	target_date DATE, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS nwp_milestones (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	title VARCHAR(150) NOT NULL, 
	due_date DATE, 
	status VARCHAR(15) NOT NULL, 
	sort_order INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES nwp_projects (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_nwp_milestones_project ON nwp_milestones (project_id);

CREATE TABLE IF NOT EXISTS nwp_project_updates (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	author_id INTEGER, 
	body TEXT NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES nwp_projects (id) ON DELETE CASCADE, 
	FOREIGN KEY(author_id) REFERENCES nwp_users (id)
);

CREATE INDEX IF NOT EXISTS ix_nwp_pupdates_project ON nwp_project_updates (project_id);

CREATE TABLE IF NOT EXISTS nwp_change_requests (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	user_id INTEGER, 
	title VARCHAR(150) NOT NULL, 
	details TEXT NOT NULL, 
	priority VARCHAR(10) NOT NULL, 
	page_url VARCHAR(500), 
	status VARCHAR(15) NOT NULL, 
	admin_reply TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES nwp_projects (id) ON DELETE CASCADE, 
	FOREIGN KEY(user_id) REFERENCES nwp_users (id)
);

CREATE INDEX IF NOT EXISTS ix_nwp_requests_project ON nwp_change_requests (project_id, status);

CREATE TABLE IF NOT EXISTS nwp_agreements (
	id SERIAL NOT NULL, 
	project_id INTEGER NOT NULL, 
	title VARCHAR(200) NOT NULL, 
	body TEXT NOT NULL, 
	version INTEGER NOT NULL, 
	updated_by INTEGER, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (project_id), 
	FOREIGN KEY(project_id) REFERENCES nwp_projects (id) ON DELETE CASCADE, 
	FOREIGN KEY(updated_by) REFERENCES nwp_users (id)
);

CREATE TABLE IF NOT EXISTS nwp_agreement_signatures (
	id SERIAL NOT NULL, 
	agreement_id INTEGER NOT NULL, 
	user_id INTEGER, 
	version INTEGER NOT NULL, 
	signed_name VARCHAR(120) NOT NULL, 
	body_hash VARCHAR(64) NOT NULL, 
	ip_address VARCHAR(45), 
	user_agent VARCHAR(300), 
	signed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(agreement_id) REFERENCES nwp_agreements (id) ON DELETE CASCADE, 
	FOREIGN KEY(user_id) REFERENCES nwp_users (id)
);

CREATE INDEX IF NOT EXISTS ix_nwp_signatures_agreement ON nwp_agreement_signatures (agreement_id);

ALTER TABLE nwp_users ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES nwp_projects (id) ON DELETE SET NULL;
