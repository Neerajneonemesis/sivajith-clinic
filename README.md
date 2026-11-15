# Dr. Sivajith's Clinic (`ഡോ. ശിവജിത്ത് ക്ലിനിക്ക്`) — All-Cloudflare Telemedicine & Audit Stack

## 3 Strictly Separated Portals
1. **`index.html` (Patient WhatsApp Portal — 100% Malayalam):**
   - Enlarged senior-friendly Malayalam typography, step-by-step call & payment instructions, 1-tap symptom selection chips, live online doctor counts (`ജനറൽ`: 2, `മെഡിസിൻ`: 1, `സർജറി`: 1), UPI UTR verification gate, WebRTC video call client, and prescription viewer.
   - Zero access to any consultant or admin screens.

2. **`consultant.html` (Hardened Multi-Factor Consultant Portal):**
   - Protected by **Email + High-Entropy Passphrase (`PBKDF2-SHA256`) + 6-Digit Rotating Authenticator 2FA (`TOTP`) + 5-Attempt Brute-Force Lockout (15 min)**.
   - Strictly locks each authenticated consultant (`sivajith@clinic.in`, `krishnan@clinic.in`, `meera@clinic.in`, `arun@clinic.in`) to their own specialty queue, duty toggle, WebRTC call ringer, Malayalam Rx composer, and private ledger.

3. **`admin.html` (Clinic Financial & Earnings Audit Console):**
   - Protected by **Chief Auditor MFA (`auditor@clinic.in` + Master Passphrase + 6-Digit 2FA TOTP + 5-Attempt Lockout)**.
   - Audits clinic-wide gross revenue, total doctor payouts (`₹250` General / `₹350` Medicine & Surgery), retained clinic platform fees (`₹20 × Consultations`), individual per-doctor earnings across Day / Week / Month, and verified UPI UTR ledgers with one-click CSV export.

## Deployment Commands
```bash
npx wrangler login
npx wrangler d1 create sivajith-clinic-db
npx wrangler d1 execute sivajith-clinic-db --remote --file=./schema.sql
npx wrangler deploy
```
