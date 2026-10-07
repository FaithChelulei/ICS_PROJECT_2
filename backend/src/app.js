const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/authRoutes');
const childRecordsRoutes = require('./routes/childRecordsRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/auth', authRoutes);
app.use('/children', childRecordsRoutes);
app.use('/admin', adminRoutes);
// The risk-response routes and the audit-log *read* routes (for the
// Security Auditor dashboard) land here next.

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
