const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./routes/authRoutes');
const childRecordsRoutes = require('./routes/childRecordsRoutes');
const adminRoutes = require('./routes/adminRoutes');
const riskResponseRoutes = require('./routes/riskResponseRoutes');
const auditorRoutes = require('./routes/auditorRoutes');
const userManagementRoutes = require('./routes/userManagementRoutes');
const encryptionRoutes = require('./routes/encryptionRoutes');

const app = express();

// Security headers (CSP, no-sniff, etc.) -- API-only, so helmet's
// defaults are safe here; nothing in this app serves HTML it needs to
// relax CSP for.
app.use(helmet());

// CORS is locked to the one real frontend origin instead of allowing
// every origin (the previous app.use(cors()) with no options). Falls back
// to the Vite dev server's default so local dev keeps working if
// FRONTEND_ORIGIN isn't set.
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173' }));

app.use(express.json());

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/auth', authRoutes);
app.use('/children', childRecordsRoutes);
app.use('/admin', adminRoutes);
app.use('/admin/users', userManagementRoutes);
app.use('/admin/encryption', encryptionRoutes);
app.use('/risk-response', riskResponseRoutes);
app.use('/auditor', auditorRoutes);

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
