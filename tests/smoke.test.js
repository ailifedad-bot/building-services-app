const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const html = fs.readFileSync('index.html', 'utf8');
const js = fs.readFileSync('app.js', 'utf8');
const css = fs.readFileSync('style.css', 'utf8');

test('application JavaScript parses', () => {
  assert.doesNotThrow(() => new Function(js));
});

test('HTML loads the local stylesheet and application script', () => {
  assert.match(html, /href=["']\.\/style\.css["']/);
  assert.match(html, /src=["']\.\/app\.js["']/);
  assert.ok(css.length > 500);
});

test('all JavaScript element lookups exist in the HTML', () => {
  const ids = new Set([...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m => m[1]));
  const lookups = [...js.matchAll(/\$\(['"]([^'"]+)['"]\)/g)].map(m => m[1]);
  const missing = [...new Set(lookups.filter(id => !ids.has(id)))];
  assert.deepEqual(missing, []);
});

test('request lifecycle supports decline and reassignment', () => {
  for (const token of ["r.status='rejected'", 'function reassign(id)', "r.status='progress'", "r.status='done'"]) {
    assert.ok(js.includes(token), 'missing workflow behavior: ' + token);
  }
});

test('technician actions check assignment ownership', () => {
  assert.match(js, /function accept\(id\)[\s\S]*?t\.phone!==current\.phone/);
  assert.match(js, /function finish\(id\)[\s\S]*?t\.phone!==current\.phone/);
});

test('demo limitations are disclosed', () => {
  assert.match(html, /بدون امنیت واقعی/);
  assert.match(js, /localStorage/);
});