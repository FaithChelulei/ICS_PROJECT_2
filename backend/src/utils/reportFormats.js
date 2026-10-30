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

module.exports = { toCsv, writePdf };
