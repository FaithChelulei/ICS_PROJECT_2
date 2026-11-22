const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./routes/authRoutes');
const childRecordsRoutes = require('./routes/childRecordsRoutes');
const adminRoutes = require('./routes/adminRoutes');
const riskResponseRoutes = require('./routes/riskResponseRoutes');
const auditorRoutes = require('./routes/auditorRoutes');
const educatorRoutes = require('./routes/educatorRoutes');
const userManagementRoutes = require('./routes/userManagementRoutes');
const encryptionRoutes = require('./routes/encryptionRoutes');
const retentionRoutes = require('./routes/retentionRoutes');
const systemSettingsRoutes = require('./routes/systemSettingsRoutes');

const app = express();

// Behind a hosting proxy (Azure App Service ends HTTPS in front of the app),
// every request arrives from the proxy's own address. TRUST_PROXY=1 tells
// Express to take the visitor's address from the one proxy hop in front, so
// sign-in rate limits and the audit log count each visitor separately.
// Azure can append the visitor's port ("1.2.3.4:51234"); it is removed, or
// each new connection would look like a new visitor to the rate limits.
// Not set on a laptop, where there is no proxy (a forged header is ignored).
if (process.env.TRUST_PROXY) {
  app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
  app.use((req, _res, next) => {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string') {
      req.headers['x-forwarded-for'] = xff.split(',').map((part) => {
        const p = part.trim();
        const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(p);
        if (v4) return v4[1];
        const v6 = /^\[([0-9a-fA-F:.]+)\](?::\d+)?$/.exec(p);
        return v6 ? v6[1] : p;
      }).join(', ');
    }
    next();
  });
}

// Security headers (CSP, no-sniff, etc.) -- API-only, so helmet's
// defaults are safe here; nothing in this app serves HTML it needs to
// relax CSP for.
//
// HSTS is held back outside production: browsers apply it to the whole
// host on EVERY port, so sending it from https://localhost:4000 would force
// every other project on this machine's localhost onto HTTPS for a year.
// TLS itself is still enforced -- see server.js.
app.use(helmet({ strictTransportSecurity: process.env.NODE_ENV === 'production' ? undefined : false }));

// CORS is locked to the one real frontend origin instead of allowing
// every origin (the previous app.use(cors()) with no options). Falls back
// to the Vite dev server's default so local dev keeps working if
// FRONTEND_ORIGIN isn't set.
// Content-Disposition is exposed so the website can read a download's file
// name (reports, "Download my data"); without it every file was "report".
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'https://localhost:5173', exposedHeaders: ['Content-Disposition'] }));

app.use(express.json());

// Every query parameter this API reads is a single piece of text. Express
// turns ?a=1&a=2 into an array and ?a[b]=1 into an object, which would
// otherwise reach a database query and fail as a 500. Refuse them once,
// here, with a clear 400.
app.use((req, res, next) => {
  const bad = Object.entries(req.query).find(([, v]) => typeof v !== 'string');
  if (bad) {
    return res.status(400).json({ error: `Query parameter "${bad[0]}" must appear once, as plain text` });
  }
  next();
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/auth', authRoutes);
app.use('/children', childRecordsRoutes);
app.use('/admin', adminRoutes);
app.use('/admin/users', userManagementRoutes);
app.use('/admin/encryption', encryptionRoutes);
app.use('/admin/retention', retentionRoutes);
app.use('/admin/settings', systemSettingsRoutes);
app.use('/risk-response', riskResponseRoutes);
app.use('/auditor', auditorRoutes);
app.use('/educator', educatorRoutes);

app.use((err, req, res, next) => {
  // Body-parser errors (malformed JSON, etc.) carry their own 4xx status —
  // surface that honestly instead of masking every error as a scary 500.
  if (err.status && err.status < 500) {
    return res.status(err.status).json({ error: err.message || 'Bad request' });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
