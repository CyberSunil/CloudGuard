// Minimal DOM shim to smoke-test the dashboard JS at runtime (no browser needed).
// Usage: node tools/dash_smoke_test.js <path-to-dashboard.html>
const fs = require('fs');

const elements = {};
function makeEl() {
  const store = { innerHTML: '', textContent: '', style: {}, dataset: {}, className: '' };
  return new Proxy(store, {
    get(t, p) {
      if (p in t) return t[p];
      if (p === 'classList') return { toggle() {}, add() {}, remove() {} };
      if (p === 'addEventListener') return function () {};
      if (p === 'appendChild') return function () {};
      if (p === 'querySelectorAll') return [];
      return function () {};
    },
    set(t, p, v) { t[p] = v; return true; }
  });
}

global.document = {
  getElementById: (id) => (elements[id] || (elements[id] = makeEl())),
  querySelectorAll: () => [],
  createElement: () => makeEl(),
};
global.window = global;
global.URL = { createObjectURL: () => 'blob:x' };
global.navigator = { userAgent: 'node' };
global.Blob = function () {};

const file = process.argv[2];
if (!file) { console.error('usage: node dash_smoke_test.js <dashboard.html>'); process.exit(1); }
const html = fs.readFileSync(file, 'utf8');
const js = html.split('<script>\n')[1].split('\n</script>')[0];
try {
  new Function(js)();
  console.log('DASH_RUNTIME_OK');
} catch (e) {
  console.error('DASH_RUNTIME_FAIL:', e.message);
  process.exit(1);
}
