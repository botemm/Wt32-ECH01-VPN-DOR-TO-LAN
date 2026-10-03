const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

test('every direct UI selector points to one element in the setup page', () => {
  const js = fs.readFileSync('main/web/app.js', 'utf8');
  const html = fs.readFileSync('main/web/index.html', 'utf8');
  const ids = [...js.matchAll(/\$\('([^']+)'\)/g)].map(x => x[1]);
  const htmlIds = [...html.matchAll(/\bid="([^"]+)"/g)].map(x => x[1]);
  assert.equal(new Set(htmlIds).size, htmlIds.length, 'duplicate HTML id');
  for (const id of new Set(ids)) assert.ok(htmlIds.includes(id), `missing HTML id: ${id}`);
  for (const peer of ['wt32', 'client1', 'client2']) assert.ok(htmlIds.includes('peer-' + peer));
});
