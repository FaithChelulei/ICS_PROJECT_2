// Turns a report ({ title, columns, rows, meta }) into a downloadable CSV or
// PDF. Report CONTENT lives in controllers/reportsController.js; this file
// only knows about layout.
//
//   columns: [{ key, label, width }]  width = relative share of the PDF row
//   rows:    plain objects, values already formatted as strings
//   meta:    lines printed under the PDF title (period, filters, author)
const PDFDocument = require('pdfkit');

// CSV / formula injection: a cell starting with = + - @ (or tab/CR) is run
// as a formula by Excel/Sheets. Audit details contain user-supplied text
// (emails, usernames), so neutralise those with a leading apostrophe.
function csvCell(value) {
  let s = value == null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv({ columns, rows }) {
  const lines = [columns.map((c) => csvCell(c.label)).join(',')];
  for (const row of rows) lines.push(columns.map((c) => csvCell(row[c.key])).join(','));
  // BOM so Excel opens it as UTF-8 (names, em-dashes) instead of ANSI.
  return `﻿${lines.join('\r\n')}\r\n`;
}

const FONT_SIZE = 8;
const PAD = 4;

// Streams an A4 landscape PDF to `stream`: title block, then a table whose
// header row repeats on every page, then "Page x of y" footers.
function writePdf({ title, columns, rows, meta }, stream) {
  const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 36, bufferPages: true });
  doc.pipe(stream);

  const left = doc.page.margins.left;
  const tableWidth = doc.page.width - left - doc.page.margins.right;
  const totalShare = columns.reduce((sum, c) => sum + c.width, 0);
  const widths = columns.map((c) => (c.width / totalShare) * tableWidth);
  const bottom = () => doc.page.height - doc.page.margins.bottom;

  doc.font('Helvetica-Bold').fontSize(16).fillColor('#1f2937').text(title);
  doc.font('Helvetica').fontSize(9).fillColor('#4b5563');
  for (const line of meta) doc.text(line);
  doc.moveDown(0.8);

  function rowHeight(cells, font) {
    doc.font(font).fontSize(FONT_SIZE);
    return Math.max(...cells.map((text, i) => doc.heightOfString(text, { width: widths[i] - 2 * PAD }))) + 2 * PAD;
  }

  function drawRow(cells, { font, fill }) {
    const h = rowHeight(cells, font);
    const y = doc.y;
    if (fill) doc.rect(left, y, tableWidth, h).fill(fill);
    doc.font(font).fontSize(FONT_SIZE).fillColor('#111827');
    let x = left;
    cells.forEach((text, i) => {
      doc.text(text, x + PAD, y + PAD, { width: widths[i] - 2 * PAD });
      x += widths[i];
    });
    doc.moveTo(left, y + h).lineTo(left + tableWidth, y + h).lineWidth(0.5).strokeColor('#e5e7eb').stroke();
    doc.x = left;
    doc.y = y + h;
  }

  const header = columns.map((c) => c.label);
  const drawHeader = () => drawRow(header, { font: 'Helvetica-Bold', fill: '#f3f4f6' });
  drawHeader();

  if (rows.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor('#6b7280').text('No records in this period.', left, doc.y + 8);
  }
  rows.forEach((row, i) => {
    const cells = columns.map((c) => (row[c.key] == null ? '' : String(row[c.key])));
    if (doc.y + rowHeight(cells, 'Helvetica') > bottom()) {
      doc.addPage();
      drawHeader();
    }
    drawRow(cells, { font: 'Helvetica', fill: i % 2 ? '#fafafa' : null });
  });

  // Footers go in the bottom margin; pdfkit would start a new page for text
  // written below the margin, so lift it while writing.
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    const margin = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;
    doc.font('Helvetica').fontSize(8).fillColor('#6b7280')
      .text(`${title} - page ${i + 1} of ${range.count}`, left, doc.page.height - 24, { width: tableWidth, align: 'right' });
    doc.page.margins.bottom = margin;
  }
  doc.end();
}

// "Download my data" (KDPA s.26) as a document a parent can read: A4
// portrait, one section per subject, plain tables. `file` is the same object
// the JSON download returns (childRecordsController.exportMyData).
function writeMyDataPdf(file, stream) {
  const doc = new PDFDocument({ size: 'A4', margin: 48, bufferPages: true });
  doc.pipe(stream);
  const left = doc.page.margins.left;
  const width = doc.page.width - left - doc.page.margins.right;
  const bottom = () => doc.page.height - doc.page.margins.bottom;
  const date = (d) => (d ? new Date(d).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '');
  const day = (d) => (d ? new Date(d).toLocaleDateString('en-GB', { dateStyle: 'medium' }) : '');
  const ensure = (h) => { if (doc.y + h > bottom()) doc.addPage(); };

  const heading = (text) => {
    ensure(60);
    doc.moveDown(0.8);
    doc.font('Helvetica-Bold').fontSize(13).fillColor('#155242').text(text, left, doc.y, { width });
    doc.moveTo(left, doc.y + 2).lineTo(left + width, doc.y + 2).lineWidth(0.8).strokeColor('#A9D0BC').stroke();
    doc.moveDown(0.5);
  };
  const sub = (text) => {
    ensure(40);
    doc.moveDown(0.4);
    doc.font('Helvetica-Bold').fontSize(10.5).fillColor('#211C16').text(text, left, doc.y, { width });
    doc.moveDown(0.2);
  };
  const pairs = (list) => {
    for (const [k, v] of list) {
      if (v === null || v === undefined || v === '') continue;
      ensure(16);
      const y = doc.y;
      doc.font('Helvetica').fontSize(9.5).fillColor('#6b7280').text(k, left, y, { width: 150 });
      doc.font('Helvetica').fontSize(9.5).fillColor('#111827').text(String(v), left + 155, y, { width: width - 155 });
      doc.y = Math.max(doc.y, y + 13);
    }
  };
  const note = (text) => {
    ensure(20);
    doc.font('Helvetica-Oblique').fontSize(9).fillColor('#6b7280').text(text, left, doc.y, { width });
    doc.moveDown(0.3);
  };
  const table = (columns, rows) => {
    const share = columns.reduce((s, c) => s + c.width, 0);
    const w = columns.map((c) => (c.width / share) * width);
    const P = 3;
    const height = (cells, font) => {
      doc.font(font).fontSize(8.5);
      return Math.max(...cells.map((t, i) => doc.heightOfString(t, { width: w[i] - 2 * P }))) + 2 * P;
    };
    const row = (cells, font, fill) => {
      const h = height(cells, font);
      if (doc.y + h > bottom()) { doc.addPage(); if (font !== 'Helvetica-Bold') row(columns.map((c) => c.label), 'Helvetica-Bold', '#EBF4F0'); }
      const y = doc.y;
      if (fill) doc.rect(left, y, width, h).fill(fill);
      doc.font(font).fontSize(8.5).fillColor('#111827');
      let x = left;
      cells.forEach((t, i) => { doc.text(t, x + P, y + P, { width: w[i] - 2 * P }); x += w[i]; });
      doc.moveTo(left, y + h).lineTo(left + width, y + h).lineWidth(0.4).strokeColor('#e5e7eb').stroke();
      doc.x = left;
      doc.y = y + h;
    };
    row(columns.map((c) => c.label), 'Helvetica-Bold', '#EBF4F0');
    rows.forEach((r, i) => row(columns.map((c) => (r[c.key] == null ? '' : String(r[c.key]))), 'Helvetica', i % 2 ? '#fafafa' : null));
    doc.moveDown(0.4);
  };

  // Title block
  doc.rect(0, 0, doc.page.width, 92).fill('#EBF4F0');
  doc.font('Helvetica-Bold').fontSize(20).fillColor('#155242').text('ChildGuard: your data', left, 30, { width });
  doc.font('Helvetica').fontSize(9.5).fillColor('#374151').text(`Prepared ${date(file.exportedAt)}`, left, 58, { width });
  doc.y = 110;
  doc.font('Helvetica').fontSize(10).fillColor('#111827')
    .text('This document lists everything ChildGuard holds about you and your children, as the Kenya Data Protection Act (section 26) entitles you to see. Keep it private: it contains your children\'s details.', left, doc.y, { width });

  heading('Your account');
  const a = file.account || {};
  pairs([['Name', a.full_name], ['Username', a.username], ['Email', a.email], ['Role', a.role], ['Account created', date(a.created_at)]]);

  heading(`Your children (${file.children.length})`);
  if (!file.children.length) note('You have not registered any children.');
  for (const c of file.children) {
    sub(c.fullName || `Child profile ${c.childProfileId}`);
    pairs([
      ['Date of birth', c.dateOfBirth],
      ['Family background', c.familyBackground],
      ['Registered', date(c.createdAt)],
      ['Archived', c.archivedAt ? `${date(c.archivedAt)}${c.archiveReason ? ` (${c.archiveReason})` : ''}` : 'No'],
      ['Identity anonymised', c.identityAnonymisedAt ? date(c.identityAnonymisedAt) : null],
    ]);
    doc.moveDown(0.3);
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#374151').text('Consent history', left, doc.y);
    doc.moveDown(0.2);
    const scope = { profile_identity: 'Profile and identity', developmental_records: 'Developmental and health records' };
    table([{ key: 'at', label: 'When', width: 2 }, { key: 'scope', label: 'For', width: 3 }, { key: 'given', label: 'Decision', width: 1.5 }],
      c.consentHistory.map((h) => ({ at: date(h.at), scope: scope[h.scope] || h.scope, given: h.given ? 'Granted' : 'Withdrawn' })));
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#374151').text('Developmental and health records', left, doc.y);
    doc.moveDown(0.2);
    if (typeof c.developmentalRecords === 'string') note(c.developmentalRecords);
    else if (!c.developmentalRecords.length) note('No records yet.');
    else {
      table([{ key: 'd', label: 'Date', width: 1.3 }, { key: 'm', label: 'Milestone', width: 2.2 }, { key: 'h', label: 'Health', width: 2 },
        { key: 's', label: 'Score (0-10)', width: 1 }, { key: 'n', label: 'Notes', width: 3 }],
      c.developmentalRecords.map((r) => ({ d: day(r.createdAt), m: r.milestone, h: r.healthIndicator, s: r.assessmentScore, n: r.progressNotes })));
    }
  }

  heading('Educators who asked to see your children');
  const shares = file.sharedWithTeachers || [];
  if (!shares.length) note('No educator has asked to see your children’s records.');
  else {
    const st = { pending: 'Waiting for your decision', granted: 'Has access', refused: 'Refused', revoked: 'Access taken back', expired: 'Period ended' };
    table([{ key: 't', label: 'Educator', width: 2 }, { key: 'c', label: 'Child', width: 2 }, { key: 'r', label: 'Their reason', width: 3 },
      { key: 's', label: 'Status', width: 1.6 }, { key: 'u', label: 'Until', width: 1.3 }],
    shares.map((s) => ({ t: s.teacher, c: s.child, r: s.reason, s: st[s.status] || s.status, u: s.status === 'granted' ? day(s.until) : '' })));
  }

  heading('Automatic security checks on your sessions');
  if (!file.automatedFlagsOnYourSessions.length) note('None of your sessions has been flagged.');
  else {
    note('ChildGuard checks each action for unusual behaviour. These of your actions were flagged; each was reviewed by a person.');
    const resp = { pending: 'No reply', confirmed_benign: 'You said: this was me', not_me: 'You said: this was NOT me' };
    table([{ key: 'at', label: 'When', width: 2 }, { key: 'a', label: 'Action', width: 2.5 }, { key: 's', label: 'Score / limit', width: 1.3 },
      { key: 'o', label: 'Your reply', width: 2 }, { key: 'r', label: 'Review', width: 1.3 }],
    file.automatedFlagsOnYourSessions.map((f) => ({ at: date(f.created_at), a: String(f.action_type).replace(/_/g, ' '),
      s: `${Number(f.combined_score).toFixed(2)} / ${Number(f.role_threshold).toFixed(2)}`, o: resp[f.owner_response] || f.owner_response || '', r: f.auditor_status || '' })));
  }

  heading('Your recent activity');
  const acts = file.yourActivity || [];
  const counts = {};
  for (const r of acts) counts[r.action_type] = (counts[r.action_type] || 0) + 1;
  note(`ChildGuard keeps a record of each action (${acts.length} in total). The ${Math.min(60, acts.length)} most recent are listed below; device names and network addresses are cleared automatically after the monitoring period.`);
  table([{ key: 'k', label: 'Action', width: 3 }, { key: 'n', label: 'Times', width: 1 }],
    Object.entries(counts).sort((x, y) => y[1] - x[1]).map(([k, n]) => ({ k: k.replace(/_/g, ' '), n })));
  table([{ key: 'at', label: 'When', width: 2 }, { key: 'a', label: 'Action', width: 2.6 }, { key: 'c', label: 'Child profile', width: 1 }, { key: 'dev', label: 'Device', width: 2 }],
    acts.slice(0, 60).map((r) => ({ at: date(r.requested_at), a: String(r.action_type).replace(/_/g, ' '), c: r.child_profile_id || '', dev: r.device || '' })));

  heading('Your rights');
  note(file.note);
  note('You can correct your child\'s details on the child\'s page, withdraw or give consent at any time under Consent, and ask the centre to archive a profile. Questions about this document go to the centre\'s data protection contact.');

  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    const m = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;
    doc.font('Helvetica').fontSize(8).fillColor('#6b7280')
      .text(`ChildGuard: your data - page ${i + 1} of ${range.count}`, left, doc.page.height - 30, { width, align: 'right' });
    doc.page.margins.bottom = m;
  }
  doc.end();
}

module.exports = { toCsv, writePdf, writeMyDataPdf };
