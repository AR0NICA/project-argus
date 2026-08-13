-- D1 benign-only synthetic relation. Apply through the approved database migration path.
CREATE TABLE IF NOT EXISTS d1_synthetic_records (
  record_id INT NOT NULL PRIMARY KEY,
  fixture_id VARCHAR(32) NOT NULL,
  category VARCHAR(32) NOT NULL,
  summary VARCHAR(128) NOT NULL
);

INSERT INTO d1_synthetic_records (record_id, fixture_id, category, summary) VALUES
  (1, 'BEN-D1-OBS-001', 'synthetic', 'D1 benign observation row 01'),
  (2, 'BEN-D1-OBS-001', 'synthetic', 'D1 benign observation row 02'),
  (3, 'BEN-D1-OBS-001', 'synthetic', 'D1 benign observation row 03')
ON DUPLICATE KEY UPDATE fixture_id = VALUES(fixture_id), category = VALUES(category), summary = VALUES(summary);

GRANT SELECT (record_id, fixture_id, category, summary) ON argus_synthetic.d1_synthetic_records TO 'argus_d1_reader'@'%';
