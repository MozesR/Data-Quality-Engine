CREATE TABLE IF NOT EXISTS customer_profile (
  customer_id TEXT,
  segment TEXT,
  risk_score INT,
  country TEXT
);

CREATE TABLE IF NOT EXISTS credit_facility (
  facility_id TEXT,
  customer_id TEXT,
  limit_amount NUMERIC,
  dpd INT
);

TRUNCATE TABLE customer_profile;
TRUNCATE TABLE credit_facility;

INSERT INTO customer_profile (customer_id, segment, risk_score, country) VALUES
('X001', 'CORP', 12, 'US'),
('X002', 'SME', 67, 'GB'),
('X003', 'RETAIL', NULL, 'USA'),
('X004', NULL, 34, 'ES');

INSERT INTO credit_facility (facility_id, customer_id, limit_amount, dpd) VALUES
('XF001', 'X001', 1250000, 5),
('XF002', 'X002', 33000, NULL),
('XF003', 'X003', -500, 0),
('XF004', 'X004', 78000, 420);
