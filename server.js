require('dotenv').config();

const express = require('express');
const app = express();
app.use(express.json());

// ---- Okta Inline Hook header auth (validate every request) ----
const AUTH_HEADER_KEY = process.env.AUTH_HEADER_KEY || 'Authorization';
const AUTH_HEADER_VALUE = process.env.AUTH_HEADER_VALUE;

// Optional health probe for external reachability
app.get('/health', (req, res) => {
  console.log('[HEALTH]', new Date().toISOString());
  res.status(200).send('ok');
});

app.use((req, res, next) => {
  const incoming = req.headers[AUTH_HEADER_KEY.toLowerCase()];
  if (!AUTH_HEADER_VALUE || incoming !== AUTH_HEADER_VALUE) {
    return res.status(401).send('Unauthorized'); // reject non-Okta callers
  }
  next();
});

// ---- Vonage Messages API (JWT auth with Application ID + private key) ----
const { Auth } = require('@vonage/auth');
const { Messages, SMS } = require('@vonage/messages');

const messagesAuth = new Auth({
  applicationId: process.env.VONAGE_APPLICATION_ID,
  privateKey: process.env.VONAGE_PRIVATE_KEY,
});
const messagesClient = new Messages(messagesAuth);


app.post('/verify', (req, res) => {
  const started = process.hrtime.bigint();

  try {
    const mp        = req.body?.data?.messageProfile || {};
    const phoneE164 = String(mp.phoneNumber || '');         // e.g., +15551234567
    const delivery  = String(mp.deliveryChannel || 'SMS');  // Okta -> 'SMS' | 'VOICE'
    const otp       = String(mp.otpCode || '');             // <-- Okta’s code

    // Log exactly what Okta expects the user to enter
    console.log(`[VERIFY] ${delivery} to ${phoneE164} | otpCode: ${otp}`);

    // Prepare SMS text and numbers for Messages API (E.164 WITHOUT '+')
    const to   = phoneE164.replace(/^\+/, '');
    const from = String(process.env.VERIFICATION_NUMBER || '').replace(/^\+/, '');
    const text = `${process.env.VERIFICATION_TEXT || 'Your verification code is:'} ${otp}`;

    // ---- Return to Okta IMMEDIATELY (under a few ms) ----
    res.status(200).json({
      commands: [{ type: 'com.okta.telephony.action', value: [{ status: 'ALLOW' }] }]
    });

    const responded = Number(process.hrtime.bigint() - started) / 1e6;
    console.log(`[VERIFY] responded to Okta in ${responded.toFixed(1)} ms`);

    // ---- Fire-and-forget: send SMS after responding ----
    // Do NOT await; just log success/failure.
    messagesClient
      .send(new SMS({ to, from, text }))
      .then(() => console.log(`[VERIFY/Messages] SMS sent to ${to}`))
      .catch(err => {
        const msg = err?.response || err?.message || err;
        console.error('[VERIFY/Messages] SMS send failed:', msg);
      });

  } catch (e) {
    // If something blows up before we respond, try to return a failure (Okta may skip the hook).
    console.error('[VERIFY] handler error before respond:', e?.response || e);
    try {
      res.status(500).json({ error: 'SMS_SEND_FAILED' });
    } catch { /* already responded */ }
  }
});


// ---- Start the server ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));