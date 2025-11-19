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

// ---- Inline Hook endpoint (deliver Okta's OTP via SMS) ----
app.post('/verify', async (req, res) => {
  try {
    const mp = req.body?.data?.messageProfile || {};
    const phoneE164 = String(mp.phoneNumber || '');    // e.g., +15551234567
    const delivery   = String(mp.deliveryChannel || 'SMS');
    const otp        = String(mp.otpCode || '');       // Okta-generated code

    // Log the exact OTP Okta expects the user to enter (visibility for your tests)
    console.log(`[VERIFY] ${delivery} to ${phoneE164} | otpCode: ${otp}`);

    // Messages API expects E.164 WITHOUT '+' for both 'to' and 'from'
    const to   = phoneE164.replace(/^\+/, '');
    const from = String(process.env.VERIFICATION_NUMBER || '').replace(/^\+/, '');
    const text = `${process.env.VERIFICATION_TEXT || 'Your verification code is:'} ${otp}`;

    // Send SMS via Vonage Messages API (JWT auth)
    await messagesClient.send(new SMS({ to, from, text }));

    // Respond quickly to Okta with success (stay under ~3s timeout)
    return res.status(200).json({
      commands: [{ type: 'com.okta.telephony.action', value: [{ status: 'ALLOW' }] }]
    });
  } catch (e) {
    console.error('[VERIFY/Messages] error:', e?.response || e);
    // Okta may skip your hook on non-200; during debug this is ok—watch System Log
    return res.status(500).json({ error: 'SMS_SEND_FAILED' });
  }
});

// ---- Start the server ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));