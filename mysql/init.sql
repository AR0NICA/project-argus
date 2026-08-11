-- D0A-LOCAL only: no production identities, credentials, or data.
USE argus_synthetic;

CREATE TABLE users (
  id INT PRIMARY KEY,
  username VARCHAR(32) NOT NULL UNIQUE,
  role VARCHAR(16) NOT NULL,
  display_name VARCHAR(64) NOT NULL
);

INSERT INTO users (id, username, role, display_name) VALUES
  (1, 'synthetic_admin', 'administrator', 'Synthetic Administrator'),
  (2, 'synthetic_analyst', 'analyst', 'Synthetic Analyst'),
  (3, 'synthetic_viewer', 'viewer', 'Synthetic Viewer');

CREATE USER 'argus_auth_reader'@'%' IDENTIFIED BY 'argus_auth_reader_local_only';
GRANT SELECT (id, username, role) ON argus_synthetic.users TO 'argus_auth_reader'@'%';
