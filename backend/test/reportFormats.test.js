// Unit tests for the report CSV/PDF writers -- `npm test`.
const test = require('node:test');
const assert = require('node:assert');
const { PassThrough } = require('stream');
const { toCsv, writePdf } = require('../src/utils/reportFormats');

const columns = [
  { key: 'a', label: 'A', width: 1 },
  { key: 'b', label: 'B', width: 1 },
];

test('CSV starts with a UTF-8 BOM and a header row', () => {
  const csv = toCsv({ columns, rows: [] });
  assert.strictEqual(csv, '﻿A,B\r\n');
});

test('CSV quotes commas, quotes and newlines', () => {
  const csv = toCsv({ columns, rows: [{ a: 'x, y', b: 'say "hi"\nbye' }] });
  assert.strictEqual(csv.split('\r\n')[1], '"x, y","say ""hi""\nbye"');
});

test('CSV neutralises spreadsheet formulas (= + - @)', () => {
  const csv = toCsv({ columns, rows: [{ a: '=HYPERLINK("http://evil")', b: '@SUM(1)' }, { a: '+1', b: '-2' }] });
  const [, row1, row2] = csv.split('\r\n');
  assert.strictEqual(row1, `"'=HYPERLINK(""http://evil"")",'@SUM(1)`);
  assert.strictEqual(row2, "'+1,'-2");
});

test('CSV leaves ordinary values and empty cells alone', () => {
  const csv = toCsv({ columns, rows: [{ a: 'view_audit_log', b: null }] });
  assert.strictEqual(csv.split('\r\n')[1], 'view_audit_log,');
});

test('PDF renders a multi-page table', async () => {
  const rows = Array.from({ length: 120 }, (_, i) => ({ a: `row ${i}`, b: 'x'.repeat(i % 7 ? 10 : 300) }));
  const out = new PassThrough();
  const chunks = [];
  out.on('data', (c) => chunks.push(c));
  const done = new Promise((resolve) => out.on('end', resolve));
  writePdf({ title: 'Test Report', columns, rows, meta: ['line one'] }, out);
  await done;
  const pdf = Buffer.concat(chunks).toString('latin1');
  assert.ok(pdf.startsWith('%PDF-'));
  const pages = (pdf.match(/\/Type \/Page\b/g) || []).length;
  assert.ok(pages > 1, `expected several pages, got ${pages}`);
});
