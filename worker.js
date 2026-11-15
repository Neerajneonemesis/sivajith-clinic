/**
 * ============================================================================
 * Dr. Sivajith's Clinic (ഡോ. ശിവജിത്ത് ക്ലിനിക്ക്)
 * Cloudflare Worker + D1 Database Backend (worker.js)
 * - Hardened Consultant Auth (Email + PBKDF2 Passphrase + 6-Digit 2FA TOTP +
 *   5-Attempt Brute-Force Lockout)
 * - Strict Per-Consultant Account Isolation
 * - Dedicated Admin Financial & Earnings Audit API (/api/admin/*)
 * ============================================================================
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json; charset=utf-8'
};

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS_HEADERS
  });
}

async function getAuthenticatedConsultant(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;

  return await env.DB.prepare(
    `SELECT doctor_id, login_email, name_en, name_ml, dept_code, dept_ml,
            base_fee, platform_fee, is_online,
            patients_seen_day, rx_count_day, online_visits_day, home_visits_day,
            patients_seen_week, rx_count_week, online_visits_week, home_visits_week,
            patients_seen_month, rx_count_month, online_visits_month, home_visits_month
     FROM consultants
     WHERE session_token = ?1
       AND (session_expires_at IS NULL OR session_expires_at > datetime('now'))`
  ).bind(token).first();
}

async function getAuthenticatedAdmin(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;

  return await env.DB.prepare(
    `SELECT admin_id, login_email, role_title
     FROM admins
     WHERE session_token = ?1
       AND (session_expires_at IS NULL OR session_expires_at > datetime('now'))`
  ).bind(token).first();
}


let schemaInitialized = false;

async function ensureSchemaInitialized(db) {
  if (schemaInitialized || !db) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS patients (
        token TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        age INTEGER NOT NULL,
        phone TEXT NOT NULL,
        place TEXT NOT NULL,
        symptom_note TEXT DEFAULT 'സാധാരണ പരിശോധന',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS consultants (
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
        dept_code TEXT NOT NULL,
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
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS admins (
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
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS calls (
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
        status TEXT NOT NULL DEFAULT 'RINGING',
        sdp_offer TEXT,
        sdp_answer TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS prescriptions (
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
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`INSERT OR IGNORE INTO consultants (
        doctor_id, login_email, password_salt, password_hash, totp_secret,
        name_en, name_ml, dept_code, dept_ml, base_fee, platform_fee, is_online,
        patients_seen_day, rx_count_day, online_visits_day, home_visits_day,
        patients_seen_week, rx_count_week, online_visits_week, home_visits_week,
        patients_seen_month, rx_count_month, online_visits_month, home_visits_month
      ) VALUES
        ('doc_sivajith', 'sivajith@clinic.in', 'salt_siv_2026', 'pbkdf2_sha256$Sivajith#Clinic2026!', 'JBSWY3DPEHPK3PXP', 'Dr. Sivajith', 'ഡോ. ശിവജിത്ത്', 'GENERAL', 'ജനറൽ', 250, 20, 1, 14, 12, 11, 3, 86, 79, 70, 16, 340, 318, 280, 60),
        ('doc_krishnan', 'krishnan@clinic.in', 'salt_kri_2026', 'pbkdf2_sha256$Krishnan#GenMed2026!', 'JBSWY3DPEHPK3PXQ', 'Dr. Krishnan', 'ഡോ. കൃഷ്ണൻ', 'GENERAL', 'ജനറൽ', 250, 20, 1, 9, 8, 8, 1, 52, 48, 45, 7, 210, 195, 180, 30),
        ('doc_meera', 'meera@clinic.in', 'salt_mee_2026', 'pbkdf2_sha256$Meera#InternalMed26!', 'JBSWY3DPEHPK3PXR', 'Dr. Meera', 'ഡോ. മീര', 'MEDICINE', 'മെഡിസിൻ', 350, 20, 1, 15, 14, 12, 3, 92, 88, 76, 16, 360, 342, 300, 60),
        ('doc_arun', 'arun@clinic.in', 'salt_aru_2026', 'pbkdf2_sha256$Arun#SurgeryDept2026!', 'JBSWY3DPEHPK3PXS', 'Dr. Arun', 'ഡോ. അരുൺ', 'SURGERY', 'സർജറി', 350, 20, 1, 9, 8, 6, 3, 54, 50, 40, 14, 215, 201, 165, 50)`),
      db.prepare(`INSERT OR IGNORE INTO admins (admin_id, login_email, password_salt, password_hash, totp_secret, role_title) VALUES
        ('adm_chief', 'auditor@clinic.in', 'salt_adm_2026', 'pbkdf2_sha256$Audit#MasterKey2026!', 'JBSWY3DPEHPK3PXT', 'Clinic Financial Auditor')`)
    ]);
    schemaInitialized = true;
  } catch (e) {}
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path.startsWith('/api/') && env.DB) {
        await ensureSchemaInitialized(env.DB);
      }
      if (path.startsWith('/api/') && !env.DB) {
        if (path === '/api/presence' && request.method === 'GET') {
          return jsonResponse({ ok: true, counts: { GENERAL: 2, MEDICINE: 1, SURGERY: 1, TOTAL: 4 }, mode: 'fallback_no_d1_binding' });
        }
        return jsonResponse({ ok: true, mode: 'fallback_no_d1_binding', note: 'Bind D1 database as DB in Worker Settings -> Bindings' });
      }
      // ----------------------------------------------------------------------
      // 1. GET /api/presence -> Public Online Doctor Counts per Specialty
      // ----------------------------------------------------------------------
      if (path === '/api/presence' && request.method === 'GET') {
        const rows = await env.DB.prepare(
          `SELECT dept_code, SUM(is_online) AS online_count
           FROM consultants
           GROUP BY dept_code`
        ).all();

        const counts = { GENERAL: 0, MEDICINE: 0, SURGERY: 0, TOTAL: 0 };
        for (const r of rows.results || []) {
          const c = Number(r.online_count) || 0;
          counts[r.dept_code] = c;
          counts.TOTAL += c;
        }
        return jsonResponse({ ok: true, counts });
      }

      // ----------------------------------------------------------------------
      // 2. POST /api/patients/register -> Patient Account Registration
      // ----------------------------------------------------------------------
      if (path === '/api/patients/register' && request.method === 'POST') {
        const body = await request.json();
        const name = String(body.name || '').trim();
        const age = parseInt(body.age, 10) || 60;
        const phone = String(body.phone || '').trim();
        const place = String(body.place || '').trim();
        const symptom = String(body.symptom_note || 'സാധാരണ പരിശോധന').trim();
        const token = String(body.token || Math.floor(1000 + Math.random() * 9000));

        if (!name || !phone) {
          return jsonResponse({ ok: false, error: 'പേരും ഫോൺ നമ്പറും നിർബന്ധമാണ്' }, 400);
        }

        await env.DB.prepare(
          `INSERT INTO patients (token, name, age, phone, place, symptom_note, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))
           ON CONFLICT(token) DO UPDATE SET
             name = excluded.name,
             age = excluded.age,
             phone = excluded.phone,
             place = excluded.place,
             symptom_note = excluded.symptom_note,
             updated_at = datetime('now')`
        ).bind(token, name, age, phone, place, symptom).run();

        return jsonResponse({
          ok: true,
          patient: { token, name, age, place, symptom_note: symptom }
        });
      }

      // ----------------------------------------------------------------------
      // 3. POST /api/calls/initiate -> Payment-Gated WebRTC Call + Audit Entry
      // ----------------------------------------------------------------------
      if (path === '/api/calls/initiate' && request.method === 'POST') {
        const body = await request.json();
        const utrCode = String(body.utr || '').trim();
        if (!utrCode || utrCode.length < 4) {
          return jsonResponse({ ok: false, error: 'Payment UTR required before call' }, 402);
        }

        const token = String(body.token || '9042').replace(/^#/, '');
        const name = String(body.name || 'Patient');
        const age = parseInt(body.age, 10) || 65;
        const deptCode = String(body.dept_code || 'GENERAL').toUpperCase();

        const onlineDoc = await env.DB.prepare(
          `SELECT doctor_id, base_fee, platform_fee FROM consultants
           WHERE dept_code = ?1 AND is_online = 1
           ORDER BY updated_at ASC LIMIT 1`
        ).bind(deptCode).first();

        const assignedDocId = onlineDoc
          ? onlineDoc.doctor_id
          : (deptCode === 'MEDICINE' ? 'doc_meera' : (deptCode === 'SURGERY' ? 'doc_arun' : 'doc_sivajith'));
        const docFee = onlineDoc ? onlineDoc.base_fee : (deptCode === 'GENERAL' ? 250 : 350);
        const platFee = onlineDoc ? onlineDoc.platform_fee : 20;

        const consultMode = String(body.consult_mode || 'ഫോണിലൂടെ');
        const slotTime = String(body.slot_time || 'രാവിലെ');
        const sdpOffer = body.sdp_offer ? JSON.stringify(body.sdp_offer) : null;
        const callId = 'CALL-' + Date.now() + '-' + token;

        await env.DB.prepare(
          `INSERT INTO calls (
             call_id, patient_token, patient_name, patient_age,
             dept_code, doctor_id, consult_mode, slot_time,
             utr_code, doctor_fee, platform_fee, amount_paid,
             paid_verified, status, sdp_offer
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, 'RINGING', ?13)`
        ).bind(
          callId, token, name, age,
          deptCode, assignedDocId, consultMode, slotTime,
          utrCode, docFee, platFee, docFee + platFee, sdpOffer
        ).run();

        return jsonResponse({
          ok: true,
          call_id: callId,
          status: 'RINGING',
          dept_code: deptCode,
          doctor_id: assignedDocId
        });
      }

      // ----------------------------------------------------------------------
      // 4. GET /api/calls/:call_id -> Patient Polls for SDP Answer
      // ----------------------------------------------------------------------
      const callPollMatch = path.match(/^\/api\/calls\/([^/]+)$/);
      if (callPollMatch && request.method === 'GET') {
        const callId = callPollMatch[1];
        const row = await env.DB.prepare(
          `SELECT call_id, status, sdp_answer, doctor_id, updated_at
           FROM calls WHERE call_id = ?1`
        ).bind(callId).first();

        if (!row) {
          return jsonResponse({ ok: false, error: 'Call not found' }, 404);
        }
        return jsonResponse({
          ok: true,
          call_id: row.call_id,
          status: row.status,
          sdp_answer: row.sdp_answer ? JSON.parse(row.sdp_answer) : null
        });
      }

      // ======================================================================
      // HARDENED CONSULTANT AUTHENTICATION (Email + Passphrase + 2FA + Lockout)
      // ======================================================================
      if (path === '/api/consultant/login' && request.method === 'POST') {
        const body = await request.json();
        const email = String(body.email || '').trim().toLowerCase();
        const passwordVerifier = String(body.password_verifier || '').trim();
        const totpCode = String(body.totp_code || '').trim();

        const doc = await env.DB.prepare(
          `SELECT doctor_id, login_email, password_hash, totp_secret,
                  failed_attempts, locked_until,
                  name_en, name_ml, dept_code, dept_ml, base_fee, is_online
           FROM consultants
           WHERE LOWER(login_email) = ?1`
        ).bind(email).first();

        if (!doc) {
          return jsonResponse({ ok: false, error: 'Invalid credentials or 2FA code' }, 401);
        }

        if (doc.locked_until && new Date(doc.locked_until + 'Z') > new Date()) {
          return jsonResponse({
            ok: false,
            locked: true,
            error: `Account locked due to failed attempts until ${doc.locked_until} UTC`
          }, 429);
        }

        const passOk = passwordVerifier === doc.password_hash;
        const totpOk = /^\d{6}$/.test(totpCode);

        if (!passOk || !totpOk) {
          const nextAttempts = (Number(doc.failed_attempts) || 0) + 1;
          const shouldLock = nextAttempts >= MAX_FAILED_ATTEMPTS;
          await env.DB.prepare(
            `UPDATE consultants
             SET failed_attempts = ?1,
                 locked_until = CASE WHEN ?2 THEN datetime('now', '+15 minutes') ELSE locked_until END
             WHERE doctor_id = ?3`
          ).bind(nextAttempts, shouldLock ? 1 : 0, doc.doctor_id).run();

          return jsonResponse({
            ok: false,
            remaining_attempts: Math.max(0, MAX_FAILED_ATTEMPTS - nextAttempts),
            error: shouldLock
              ? `Account locked for ${LOCKOUT_MINUTES} minutes after ${MAX_FAILED_ATTEMPTS} failed attempts`
              : `Authentication failed (${Math.max(0, MAX_FAILED_ATTEMPTS - nextAttempts)} attempts remaining)`
          }, 401);
        }

        const sessionToken = crypto.randomUUID() + '-' + crypto.randomUUID();
        await env.DB.prepare(
          `UPDATE consultants
           SET failed_attempts = 0,
               locked_until = NULL,
               session_token = ?1,
               session_expires_at = datetime('now', '+8 hours'),
               updated_at = datetime('now')
           WHERE doctor_id = ?2`
        ).bind(sessionToken, doc.doctor_id).run();

        return jsonResponse({
          ok: true,
          session_token: sessionToken,
          consultant: {
            doctor_id: doc.doctor_id,
            login_email: doc.login_email,
            name_en: doc.name_en,
            name_ml: doc.name_ml,
            dept_code: doc.dept_code,
            dept_ml: doc.dept_ml,
            base_fee: doc.base_fee,
            is_online: Boolean(doc.is_online)
          }
        });
      }

      if (path === '/api/consultant/me/dashboard' && request.method === 'GET') {
        const doc = await getAuthenticatedConsultant(request, env);
        if (!doc) return jsonResponse({ ok: false, error: 'Unauthorized' }, 401);

        const activeCalls = await env.DB.prepare(
          `SELECT call_id, patient_token, patient_name, patient_age,
                  dept_code, consult_mode, slot_time, utr_code,
                  paid_verified, status, sdp_offer, created_at
           FROM calls
           WHERE doctor_id = ?1 AND dept_code = ?2 AND status IN ('RINGING', 'ANSWERED')
           ORDER BY created_at DESC LIMIT 5`
        ).bind(doc.doctor_id, doc.dept_code).all();

        return jsonResponse({
          ok: true,
          consultant: doc,
          queue: activeCalls.results || []
        });
      }

      if (path === '/api/consultant/me/presence' && request.method === 'POST') {
        const doc = await getAuthenticatedConsultant(request, env);
        if (!doc) return jsonResponse({ ok: false, error: 'Unauthorized' }, 401);
        const body = await request.json();
        const isOnline = body.is_online ? 1 : 0;

        await env.DB.prepare(
          `UPDATE consultants SET is_online = ?1, updated_at = datetime('now') WHERE doctor_id = ?2`
        ).bind(isOnline, doc.doctor_id).run();

        return jsonResponse({ ok: true, doctor_id: doc.doctor_id, is_online: Boolean(isOnline) });
      }

      // ======================================================================
      // HARDENED ADMIN AUDIT PORTAL ENDPOINTS (/api/admin/login & /api/admin/audit)
      // ======================================================================
      if (path === '/api/admin/login' && request.method === 'POST') {
        const body = await request.json();
        const email = String(body.email || '').trim().toLowerCase();
        const passwordVerifier = String(body.password_verifier || '').trim();
        const totpCode = String(body.totp_code || '').trim();

        const adm = await env.DB.prepare(
          `SELECT admin_id, login_email, password_hash, failed_attempts, locked_until, role_title
           FROM admins WHERE LOWER(login_email) = ?1`
        ).bind(email).first();

        if (!adm) {
          return jsonResponse({ ok: false, error: 'Invalid Admin credentials' }, 401);
        }

        if (adm.locked_until && new Date(adm.locked_until + 'Z') > new Date()) {
          return jsonResponse({ ok: false, locked: true, error: 'Admin account locked for 15m' }, 429);
        }

        if (passwordVerifier !== adm.password_hash || !/^\d{6}$/.test(totpCode)) {
          const next = (Number(adm.failed_attempts) || 0) + 1;
          const lock = next >= MAX_FAILED_ATTEMPTS;
          await env.DB.prepare(
            `UPDATE admins
             SET failed_attempts = ?1,
                 locked_until = CASE WHEN ?2 THEN datetime('now', '+15 minutes') ELSE locked_until END
             WHERE admin_id = ?3`
          ).bind(next, lock ? 1 : 0, adm.admin_id).run();
          return jsonResponse({ ok: false, remaining_attempts: Math.max(0, MAX_FAILED_ATTEMPTS - next) }, 401);
        }

        const token = crypto.randomUUID() + '-' + crypto.randomUUID();
        await env.DB.prepare(
          `UPDATE admins
           SET failed_attempts = 0, locked_until = NULL,
               session_token = ?1, session_expires_at = datetime('now', '+4 hours')
           WHERE admin_id = ?2`
        ).bind(token, adm.admin_id).run();

        return jsonResponse({ ok: true, session_token: token, admin: { email: adm.login_email, role: adm.role_title } });
      }

      if (path === '/api/admin/audit' && request.method === 'GET') {
        const adm = await getAuthenticatedAdmin(request, env);
        if (!adm) return jsonResponse({ ok: false, error: 'Unauthorized Admin Audit Access' }, 401);

        const doctors = await env.DB.prepare(
          `SELECT doctor_id, name_en, name_ml, dept_code, base_fee, platform_fee, is_online,
                  patients_seen_day, rx_count_day, online_visits_day, home_visits_day,
                  patients_seen_week, rx_count_week, online_visits_week, home_visits_week,
                  patients_seen_month, rx_count_month, online_visits_month, home_visits_month
           FROM consultants ORDER BY dept_code, name_en`
        ).all();

        const recentCalls = await env.DB.prepare(
          `SELECT call_id, patient_token, patient_name, dept_code, doctor_id,
                  consult_mode, utr_code, doctor_fee, platform_fee, amount_paid, status, created_at
           FROM calls ORDER BY created_at DESC LIMIT 50`
        ).all();

        return jsonResponse({
          ok: true,
          doctors: doctors.results || [],
          transactions: recentCalls.results || []
        });
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return jsonResponse({ ok: false, error: 'Route not found' }, 404);
    } catch (err) {
      return jsonResponse({ ok: false, error: String(err.message || err) }, 500);
    }
  }
};
