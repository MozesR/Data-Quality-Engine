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
('C001', 'SME', 45, 'NL'),
('C002', NULL, 76, 'DE'),
('C003', 'CORP', 140, 'NLD'),
(NULL, 'RETAIL', 22, 'FR');

INSERT INTO credit_facility (facility_id, customer_id, limit_amount, dpd) VALUES
('F001', 'C001', 500000, 10),
('F002', 'C002', -3000, NULL),
(NULL, 'C003', 20000, 4),
('F004', 'C004', 999999999, 600);
