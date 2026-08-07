// Extracts the .xls blob the dashboard would download and writes it to disk.
// Usage: node tools/extract_xls.js <dashboard.html> <output.xls>
'use strict';
const fs = require('fs');
const file = process.argv[2];
const out = process.argv[3] || '/tmp/report.xls';
const html = fs.readFileSync(file, 'utf8');
const js = html.split('<script>\n')[1].split('\n</script>')[0];

const elements = {};
function makeEl() {
  const s = { innerHTML: '', textContent: '', style: {}, dataset: {}, className: '' };
  return new Proxy(s, {
    get(t, p) {
      if (p in t) return t[p];
      if (p === 'classList') return { toggle() {}, add() {}, remove() {} };
      if (p === 'addEventListener') return function () {};
      if (p === 'appendChild') return function () {};
      if (p === 'querySelectorAll') return [];
      if (p === 'click') return function () {};
      return function () {};
    },
    set(t, p, v) { t[p] = v; return true; }
  });
}
global.document = {
  getElementById: (id) => (elements[id] || (elements[id] = makeEl())),
  querySelectorAll: () => [],
  querySelector: () => makeEl(),
  createElement: () => makeEl(),
};
global.window = global;
global.URL = { createObjectURL: () => 'blob:x' };
global.navigator = { userAgent: 'node' };
global.print = () => {};
global.Blob = function (parts) { fs.writeFileSync(out, parts.join('')); };

new Function(js + '\nexportExcel();')();
console.log('written ' + out);
