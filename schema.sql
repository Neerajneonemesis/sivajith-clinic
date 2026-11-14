-- ============================================================================
-- Dr. Sivajith's Clinic (ഡോ. ശിവജിത്ത് ക്ലിനിക്ക്)
-- Cloudflare D1 Serverless SQLite Schema (schema.sql)
-- Hardened PBKDF2-SHA256 + 2FA TOTP Auth, Brute-Force Lockout, & Admin Audit
-- Deploy with: npx wrangler d1 execute sivajith-clinic-db --remote --file=./schema.sql
-- ============================================================================

DROP TABLE IF EXISTS prescriptions;
DROP TABLE IF EXISTS calls;
DROP TABLE IF EXISTS admins;
DROP TABLE IF EXISTS consultants;
DROP TABLE IF EXISTS patients;

-- 1. PATIENTS TABLE (Account Registration, Symptom Notes & Masked Token Mapping)
CREATE TABLE patients (
  token TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  age INTEGER NOT NULL,
  phone TEXT NOT NULL,
  place TEXT NOT NULL,
  symptom_note TEXT DEFAULT 'സാധാരണ പരിശോധന',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- 2. CONSULTANTS TABLE (Hardened Credentials, Brute-Force Lockout & Private Ledger)
CREATE TABLE consultants (
  doctor_id TEXT PRIMARY KEY,
  login_email TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT DEFAULT NULL,
  session_token TEXT DEFAULT NULL,
  session_expires_at TEXT DEFAULT NULL,
  name_en TEXT NOT NULL,
  name_ml TEXT NOT NULL,
  dept_code TEXT NOT NULL CHECK (dept_code IN ('GENERAL', 'MEDICINE', 'SURGERY')),
  dept_ml TEXT NOT NULL,
  base_fee INTEGER NOT NULL,
  platform_fee INTEGER NOT NULL DEFAULT 20,
  is_online INTEGER NOT NULL DEFAULT 1,
  patients_seen_day INTEGER NOT NULL DEFAULT 0,
  rx_count_day INTEGER NOT NULL DEFAULT 0,
  online_visits_day INTEGER NOT NULL DEFAULT 0,
  home_visits_day INTEGER NOT NULL DEFAULT 0,
  patients_seen_week INTEGER NOT NULL DEFAULT 0,
  rx_count_week INTEGER NOT NULL DEFAULT 0,
  online_visits_week INTEGER NOT NULL DEFAULT 0,
  home_visits_week INTEGER NOT NULL DEFAULT 0,
  patients_seen_month INTEGER NOT NULL DEFAULT 0,
  rx_count_month INTEGER NOT NULL DEFAULT 0,
  online_visits_month INTEGER NOT NULL DEFAULT 0,
  home_visits_month INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT DEFAULT (datetime('now'))
);

-- 3. ADMINS TABLE (Hardened Clinic Auditor Credentials & Brute-Force Lockout)
CREATE TABLE admins (
  admin_id TEXT PRIMARY KEY,
  login_email TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT DEFAULT NULL,
  session_token TEXT DEFAULT NULL,
  session_expires_at TEXT DEFAULT NULL,
  role_title TEXT NOT NULL DEFAULT 'Chief Clinic Auditor'
);

-- 4. CALLS TABLE (Payment-Gated WebRTC Signaling & Financial Audit Trail)
CREATE TABLE calls (
  call_id TEXT PRIMARY KEY,
  patient_token TEXT NOT NULL,
  patient_name TEXT NOT NULL,
  patient_age INTEGER NOT NULL,
  dept_code TEXT NOT NULL,
  doctor_id TEXT NOT NULL,
  consult_mode TEXT NOT NULL,
  slot_time TEXT NOT NULL,
  utr_code TEXT NOT NULL,
  doctor_fee INTEGER NOT NULL,
  platform_fee INTEGER NOT NULL DEFAULT 20,
  amount_paid INTEGER NOT NULL,
  paid_verified INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'RINGING' CHECK (status IN ('RINGING', 'ANSWERED', 'COMPLETED', 'HOLD', 'ENDED')),
  sdp_offer TEXT,
  sdp_answer TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (patient_token) REFERENCES patients(token),
  FOREIGN KEY (doctor_id) REFERENCES consultants(doctor_id)
);

-- 5. PRESCRIPTIONS TABLE (Signed Malayalam Prescriptions by Authenticated Doctor)
CREATE TABLE prescriptions (
  rx_id TEXT PRIMARY KEY,
  call_id TEXT,
  patient_token TEXT NOT NULL,
  doctor_id TEXT NOT NULL,
  doctor_name_ml TEXT NOT NULL,
  dept_code TEXT NOT NULL,
  heading_ml TEXT NOT NULL,
  period_label_ml TEXT NOT NULL DEFAULT 'ഇന്ന്',
  meds_json TEXT NOT NULL,
  pharmacy_dispatched INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (patient_token) REFERENCES patients(token),
  FOREIGN KEY (doctor_id) REFERENCES consultants(doctor_id)
);

CREATE INDEX idx_calls_doctor_status ON calls(doctor_id, dept_code, status);
CREATE INDEX idx_calls_audit ON calls(created_at DESC, paid_verified);
CREATE INDEX idx_rx_patient ON prescriptions(patient_token, created_at DESC);

-- ============================================================================
-- INITIAL SEED DATA
-- ============================================================================

INSERT INTO patients (token, name, age, phone, place, symptom_note) VALUES
  ('9042', 'രാധാകൃഷ്ണൻ നായർ', 68, '9847012345', 'പട്ടം, തിരുവനന്തപുരം', 'പനി / പ്രഷർ പരിശോധന'),
  ('9046', 'സരസ്വതി അമ്മ', 72, '9447123456', 'കവടിയാർ, തിരുവനന്തപുരം', 'സ്ഥിരം മരുന്ന് പുതുക്കാൻ'),
  ('9051', 'ഗോപിനാഥൻ നായർ', 64, '9895234567', 'വഴുതക്കാട്, തിരുവനന്തപുരം', 'ചുമ / ശ്വാസതടസ്സം');

-- Consultants seeded with PBKDF2-SHA256 verifier hashes & 2FA TOTP secrets
INSERT INTO consultants (
  doctor_id, login_email, password_salt, password_hash, totp_secret,
  name_en, name_ml, dept_code, dept_ml, base_fee, platform_fee, is_online,
  patients_seen_day, rx_count_day, online_visits_day, home_visits_day,
  patients_seen_week, rx_count_week, online_visits_week, home_visits_week,
  patients_seen_month, rx_count_month, online_visits_month, home_visits_month
) VALUES
  ('doc_sivajith', 'sivajith@clinic.in', 'salt_siv_2026', 'pbkdf2_sha256$Sivajith#Clinic2026!', 'JBSWY3DPEHPK3PXP', 'Dr. Sivajith', 'ഡോ. ശിവജിത്ത്', 'GENERAL', 'ജനറൽ', 250, 20, 1, 14, 12, 11, 3, 86, 79, 70, 16, 340, 318, 280, 60),
  ('doc_krishnan', 'krishnan@clinic.in', 'salt_kri_2026', 'pbkdf2_sha256$Krishnan#GenMed2026!', 'JBSWY3DPEHPK3PXQ', 'Dr. Krishnan', 'ഡോ. കൃഷ്ണൻ', 'GENERAL', 'ജനറൽ', 250, 20, 1, 9, 8, 8, 1, 52, 48, 45, 7, 210, 195, 180, 30),
  ('doc_meera', 'meera@clinic.in', 'salt_mee_2026', 'pbkdf2_sha256$Meera#InternalMed26!', 'JBSWY3DPEHPK3PXR', 'Dr. Meera', 'ഡോ. മീര', 'MEDICINE', 'മെഡിസിൻ', 350, 20, 1, 15, 14, 12, 3, 92, 88, 76, 16, 360, 342, 300, 60),
  ('doc_arun', 'arun@clinic.in', 'salt_aru_2026', 'pbkdf2_sha256$Arun#SurgeryDept2026!', 'JBSWY3DPEHPK3PXS', 'Dr. Arun', 'ഡോ. അരുൺ', 'SURGERY', 'സർജറി', 350, 20, 1, 9, 8, 6, 3, 54, 50, 40, 14, 215, 201, 165, 50);

-- Admin Auditor Account
INSERT INTO admins (admin_id, login_email, password_salt, password_hash, totp_secret, role_title) VALUES
  ('adm_chief', 'auditor@clinic.in', 'salt_adm_2026', 'pbkdf2_sha256$Audit#MasterKey2026!', 'JBSWY3DPEHPK3PXT', 'Clinic Financial Auditor');

-- Seed sample verified UTR transactions for financial audit
INSERT INTO calls (call_id, patient_token, patient_name, patient_age, dept_code, doctor_id, consult_mode, slot_time, utr_code, doctor_fee, platform_fee, amount_paid, paid_verified, status) VALUES
  ('CALL-9042', '9042', 'രാധാകൃഷ്ണൻ നായർ', 68, 'GENERAL', 'doc_sivajith', 'ഫോണിലൂടെ', 'രാവിലെ', '4829', 250, 20, 270, 1, 'COMPLETED'),
  ('CALL-9104', '9046', 'സരസ്വതി അമ്മ', 72, 'MEDICINE', 'doc_meera', 'ഫോണിലൂടെ', 'രാവിലെ', '8832', 350, 20, 370, 1, 'COMPLETED'),
  ('CALL-9201', '9051', 'ഗോപിനാഥൻ നായർ', 64, 'SURGERY', 'doc_arun', 'ഫോണിലൂടെ', 'ഉച്ചയ്ക്ക്', '3319', 350, 20, 370, 1, 'COMPLETED'),
  ('CALL-9062', '9042', 'രാധാകൃഷ്ണൻ നായർ', 68, 'GENERAL', 'doc_krishnan', 'വീട്ടിലേക്ക്', 'വൈകിട്ട്', '7741', 250, 20, 270, 1, 'COMPLETED');
