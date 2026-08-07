// Enhanced dashboard interaction test: simulates tab clicks, search,
// filters and row expansion against the real dashboard JS (no browser).
// Usage: node tools/dash_interact_test.js <dashboard.html>
'use strict';
const fs = require('fs');

// ---- DOM shim ----
const elements = {};
function makeEl() {
  const store = { innerHTML: '', textContent: '', style: {}, dataset: {}, className: '' };
  const listeners = {};
  return new Proxy(store, {
    get(t, p) {
      if (p in t) return t[p];
      if (p === 'classList') return { toggle() {}, add() {}, remove() {} };
      if (p === 'addEventListener') return (ev, fn) => { (listeners[ev] = listeners[ev] || []).push(fn); };
      if (p === 'appendChild') return function () {};
      if (p === 'querySelectorAll') return [];
      if (p === 'click') return function () {};
      return function () {};
    },
    set(t, p, v) { t[p] = v; return true; }
  });
}
function getEl(id) { return elements[id] || (elements[id] = makeEl()); }

global.__created = [];
global.print = () => {};
global.document = {
  getElementById: getEl,
  querySelectorAll: (sel) => {
    // expose the 6 dashboard views so showView() can toggle their display
    if (sel === '.view') {
      return ['findings', 'overview', 'checks', 'comparison', 'coverage', 'policies'].map(id => {
        const el = getEl('view-' + id);
        el.id = 'view-' + id;
        return el;
      });
    }
    return [];
  },
  querySelector: () => makeEl(),
  createElement: (tag) => { const el = makeEl(); global.__created.push(el); return el; },
  head: { appendChild: () => {}, removeChild: () => {} },
};
global.window = global;
global.scrollTo = () => {};
global.URL = { createObjectURL: () => 'blob:x' };
global.navigator = { userAgent: 'node' };
global.Blob = function (parts) { global.__lastBlob = parts.join(''); };

const file = process.argv[2];
if (!file) { console.error('usage: node dash_interact_test.js <dashboard.html>'); process.exit(1); }
const html = fs.readFileSync(file, 'utf8');
const js = html.split('<script>\n')[1].split('\n</script>')[0];
const js2 = js + '\nwindow.__test={setCloud,renderFindings,toggleRow,state,allFindings,exportExcel,exportCSV,exportPDF,openExport,closeExport,toggleSel,setAllSel,setFailedOnly,setExpFilter,confirmExport,clearExclusions,selectedFindings,showView,renderRiskRating,dataClouds:()=>DATA.clouds,toggleGrp,setPage,setCPage,toggleAllGrps,grpOf,setViewMode,setSvcTab,ctoggleRow,currentFindings:()=>window._findings,renderSevChart,renderCisScore,renderCoverage,renderPolicies,setCovTab,setPolTab,renderChecks,renderAccount,tipShow,tipHide};';
new Function(js2)();

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  [' + extra + ']' : '')); }
}
function rowCount() {
  const h = getEl('findingsBody').innerHTML;
  const trs = (h.match(/<tr/g) || []).length;
  const grps = (h.match(/class="grp-row"/g) || []).length;
  return (trs - grps) / 2; // each finding = main + detail row; group headers excluded
}
function htmlOf(id) { return getEl(id).innerHTML; }
function txtOf(id) { return String(htmlOf(id) || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(); }
function worksheetRows(xml, idx) {
  const parts = xml.split('<Worksheet');
  return parts[idx + 1] ? (parts[idx + 1].match(/<Row/g) || []).length : -1;
}

// Scanned clouds drive every count below: tabs = 'All' + one per cloud,
// account cards and vendor logos only for the clouds present in the report.
const scannedClouds = __test.dataClouds().map(c => c.id);
const BRAND = { aws: 'ff9900', azure: '0089d6', gcp: '557ebf', oci: 'c74634' };
const CL = { aws: 'AWS', azure: 'Azure', gcp: 'GCP', oci: 'OCI' };

console.log('== Initial render ==');
check('tabs rendered (All + ' + scannedClouds.length + ' cloud(s))', (htmlOf('tabs').match(/class="tab/g) || []).length === (scannedClouds.length > 1 ? 1 + scannedClouds.length : scannedClouds.length), 'tabs=' + (htmlOf('tabs').match(/class="tab/g) || []).length + ' clouds=' + scannedClouds.length);
check('6 KPI cards rendered', (htmlOf('kpis').match(/class="kpi/g) || []).length === 6);
check('KPI shows Risk score', htmlOf('kpis').includes('Risk score'));
check('findings open with service groups collapsed by default', (htmlOf('findingsBody').match(/grp-row/g) || []).length > 0, 'groups=' + (htmlOf('findingsBody').match(/grp-row/g) || []).length);
__test.toggleAllGrps();
check('expanding groups reveals finding rows', rowCount() > 0, 'rows=' + rowCount());
check('top-right header has no catalog counter', !htmlOf('meta').includes('Checks catalog') && htmlOf('meta').includes('chip'), 'meta=' + htmlOf('meta').slice(0, 80));
check('status bar shows failed X of Y findings', /\d+/.test(String(getEl('sbFindings').textContent)) && /\d+/.test(String(getEl('sbTotal').textContent)), 'failed=' + getEl('sbFindings').textContent + ' total=' + getEl('sbTotal').textContent);
check('status bar shows checks A of B failing', /\d+/.test(String(getEl('sbChecksFail').textContent)) && /\d+/.test(String(getEl('sbChecksTotal').textContent)), 'failing=' + getEl('sbChecksFail').textContent + ' total=' + getEl('sbChecksTotal').textContent);
const failChecksNow = new Set(__test.currentFindings().filter(f => f.status === 'FAIL').map(f => f.check_id)).size;
check('findings header shows failing-check clarity', /\d+ of \d+ checks failing/.test(String(getEl('checkCount').textContent)), 'txt=' + getEl('checkCount').textContent);
check('check summary matches distinct failing checks', new RegExp(failChecksNow + ' of ').test(String(getEl('checkCount').textContent)), 'txt=' + getEl('checkCount').textContent + ' expected=' + failChecksNow);
check('severity chart populated', htmlOf('sevChart').includes('CRITICAL') || htmlOf('sevChart').includes('HIGH'));
check('service bars populated', (htmlOf('svcBars').match(/bar-row/g) || []).length > 0);
// Comparison exists ONLY when a previous report was supplied (--baseline).
// The dashboard init already set nav-comparison's display ('' when data
// exists, 'none' otherwise) - read that rendered state instead of DATA.
const hasCmp = getEl('nav-comparison').style.display !== 'none';
if(hasCmp){
  check('comparison panel visible', getEl('comparePanel').style.display === 'block');
  check('outcome cards include FIXED', htmlOf('outcomes').includes('FIXED'));
  check('outcome cards include STILL REPRODUCIBLE', htmlOf('outcomes').includes('STILL REPRODUCIBLE'));
  check('fix rate text present', htmlOf('fixRate').includes('%'));
} else {
  check('comparison panel not activated without a previous report', getEl('comparePanel').style.display !== 'block');
  check('comparison nav hidden without a previous report', getEl('nav-comparison').style.display === 'none');
}
check('coverage shows every scanned cloud', scannedClouds.every(c => htmlOf('coverageGrid').includes(CL[c])), 'grid=' + htmlOf('coverageGrid').slice(0, 100));
check('single-cloud coverage defaults to scanned cloud (others browsable via tabs)', scannedClouds.length > 1 || (!htmlOf('coverageGrid').includes('Azure') && !htmlOf('coverageGrid').includes('GCP') && !htmlOf('coverageGrid').includes('OCI')), 'grid=' + htmlOf('coverageGrid').slice(0, 120));
check('coverage lists checks by service', htmlOf('coverageGrid').includes('checks'));
check('least-privilege reference rendered', htmlOf('policiesBody').includes('AWS') || htmlOf('policiesBody').includes('aws'));
check('privilege alert element exists', getEl('privAlert').style.display === 'block' || getEl('privAlert').style.display === 'none');

console.log('== Account banner ==');
check('account card per scanned cloud', (htmlOf('accountBar').match(/class="acct-card"/g) || []).length === scannedClouds.length, 'cards=' + (htmlOf('accountBar').match(/class="acct-card"/g) || []).length + ' clouds=' + scannedClouds.length);
check('account ids shown in banner', htmlOf('accountBar').includes('account'));
check('vendor logos rendered for scanned clouds', scannedClouds.every(c => htmlOf('accountBar').includes(BRAND[c])), 'missing=' + scannedClouds.filter(c => !htmlOf('accountBar').includes(BRAND[c])).join(','));
check('no placeholder text logos', !htmlOf('accountBar').includes('>aws</text>') && !htmlOf('accountBar').includes('>OCI</text>'));
check('account card is clean (no risk/checks meta)', !/risk|\/\s*checks|checks run/i.test(htmlOf('accountBar')), 'accountBar still contains risk/checks meta');
check('account card keeps account id', /account/.test(htmlOf('accountBar')));

console.log('== Risk rating (default dashboard head) ==');
check('risk gauge shows a score %', /\d+%/.test(String(getEl('riskVal').textContent)), 'val=' + getEl('riskVal').textContent);
check('risk rating label is one of CRITICAL/HIGH/MEDIUM/LOW', /(CRITICAL|HIGH|MEDIUM|LOW) RISK/.test(String(getEl('riskRating').textContent)), 'rating=' + getEl('riskRating').textContent);
check('risk rating colored', String(getEl('riskRating').style.color || '').includes('var(--'), 'color=' + getEl('riskRating').style.color);
check('risk description populated', String(htmlOf('riskDesc')).length > 0);
check('risk scale marker sits on the score', (htmlOf('riskCounts').match(/ps-marker/g) || []).length === 1);
check('risk tile shows rating + posture scale with colour legend (no verbose counts)', /RISK/.test(String(getEl('riskRating').textContent)) && htmlOf('riskCounts').includes('ps-band') && htmlOf('riskCounts').includes('ps-marker') && htmlOf('riskCounts').includes('0-25') && !htmlOf('riskCounts').includes('checks run'), 'rating=' + getEl('riskRating').textContent + ' counts=' + htmlOf('riskCounts').slice(0, 90));
check('risk gauge gradient updated', String(getEl('riskGauge').style.background).includes('conic-gradient'));
check('risk distribution donut rendered (svg segments + legend)', (htmlOf('riskDist').match(/donut-seg/g) || []).length >= 2 && (htmlOf('riskDist').match(/dl-row/g) || []).length >= 2, 'dist=' + htmlOf('riskDist').slice(0, 120));
check('top-10 services bars rendered with counts', (htmlOf('topSvc').match(/hs-row/g) || []).length > 0 && (htmlOf('topSvc').match(/hs-fill/g) || []).length > 0, 'bars=' + (htmlOf('topSvc').match(/hs-row/g) || []).length);
check('chart tooltip wiring exists (tipShow/tipHide + listener guard)', typeof __test.tipShow === 'function' && typeof __test.tipHide === 'function', 'tipfns=' + typeof __test.tipShow + '/' + typeof __test.tipHide);
check('donut segments carry hover tooltip data', (htmlOf('riskDist').match(/data-tip=/g) || []).length >= 2, 'tips=' + (htmlOf('riskDist').match(/data-tip=/g) || []).length);
check('service bars carry hover tooltip data', (htmlOf('topSvc').match(/data-tip=/g) || []).length >= 1, 'btips=' + (htmlOf('topSvc').match(/data-tip=/g) || []).length);

console.log('== Dynamic view switching (sidebar) ==');
// mirror the browser's parsed initial state (markup inline styles)
getEl('view-findings').style.display = 'block';
getEl('view-overview').style.display = 'none';
getEl('view-comparison').style.display = 'none';
getEl('view-coverage').style.display = 'none';
getEl('view-policies').style.display = 'none';
check('findings view is the default dashboard', getEl('view-findings').style.display === 'block');
check('overview hidden by default', getEl('view-overview').style.display === 'none');
check('markup has no page containers / page nav', !html.includes('id="page-1"') && !html.includes('pgnum') && !html.includes('pageNav'), 'page containers still present');
__test.showView('overview');
check('overview view swaps in', getEl('view-overview').style.display === 'block');
check('overview shows severity chart (Critical/High/Medium/Low)', (htmlOf('sevChart').match(/sev-col/g) || []).length >= 3 && htmlOf('sevChart').includes('CRITICAL'), 'chart=' + htmlOf('sevChart').slice(0, 140));
check('overview shows per-cloud CIS benchmark score', (htmlOf('cisScoreBody').match(/cis-card/g) || []).length >= 1 && /%/.test(htmlOf('cisScoreBody')), 'cis=' + htmlOf('cisScoreBody').slice(0, 140));
check('CIS version bar spans full width above cards', /<div class="cis-ver">/.test(htmlOf('cisScoreBody')) && htmlOf('cisScoreBody').indexOf('cis-ver') < htmlOf('cisScoreBody').indexOf('cis-card'), 'ver not above cards');
check('CIS card clickable with drill-down hint', htmlOf('cisScoreBody').includes('Click to see pass / fail per control'));
if (typeof cisDrill === 'function'){
  const open = cisDrill(scannedClouds[0]);
  check('CIS drill-down lists controls with status', /st-fail|st-pass|st-na/.test(open) && open.includes('Section'), 'no controls in drill');
  check('CIS drill-down has official benchmark source link', /href="http/.test(open) && open.includes('Official benchmark'), 'no source link');
  check('CIS drill-down shows mapped check ids', (open.match(/class="chip"/g) || []).length >= 1, 'no check chips');
}
check('findings hidden after switch', getEl('view-findings').style.display === 'none');
__test.showView('comparison');
if(hasCmp){
  check('comparison view swaps in with outcomes', getEl('view-comparison').style.display === 'block' && htmlOf('outcomes').includes('FIXED'));
} else {
  check('comparison view swaps in (empty without a previous report)', getEl('view-comparison').style.display === 'block');
}
__test.showView('coverage');
check('coverage view swaps in with cards', getEl('view-coverage').style.display === 'block' && htmlOf('coverageGrid').includes('AWS'));
__test.showView('policies');
check('least-privilege view swaps in', getEl('view-policies').style.display === 'block' && String(htmlOf('policiesBody')).length > 0);
check('least-privilege shows scanned cloud(s) templates', scannedClouds.every(c => htmlOf('policiesBody').includes('<b>' + CL[c] + '</b>')) && (scannedClouds.length > 1 || (!htmlOf('policiesBody').includes('<b>Azure</b>') && !htmlOf('policiesBody').includes('<b>GCP</b>') && !htmlOf('policiesBody').includes('<b>OCI</b>'))), 'pol=' + htmlOf('policiesBody').slice(0, 160));
__test.showView('checks');
check('check-summary view swaps in', getEl('view-checks').style.display === 'block');
// The checks panel is a scan-level rollup: it shows ALL checks (failing +
// passed), independent of the findings status filter. Baseline it on
// allFindings(), not the filtered findings.
const distinctChecks = new Set(__test.allFindings().map(f => f.check_id)).size;
const ckPages = Math.ceil(distinctChecks / 20);
const ckRows1 = (htmlOf('checksBody').match(/class="chk-row"/g) || []).length;
check('check summary paginates (page 1 shows ' + Math.min(distinctChecks, 20) + ' of ' + distinctChecks + ', ' + ckPages + ' page(s))', ckRows1 === Math.min(distinctChecks, 20) && (htmlOf('checksPager').match(/pg-btn/g) || []).length === ckPages + 2, 'rows=' + ckRows1 + ' pages=' + ckPages);
check('check summary shows resources-fail wording', /resources fail/.test(htmlOf('checksBody')) && /of <b>\d+<\/b> resources/.test(htmlOf('checksBody')), 'snip=' + htmlOf('checksBody').slice(0, 120));
let totalSep = 0, totalRowsSeen = 0;
for (let cp = 1; cp <= ckPages; cp++) {
  __test.setCPage(cp);
  totalRowsSeen += (htmlOf('checksBody').match(/class="chk-row"/g) || []).length;
  const cells = (htmlOf('checksBody').match(/<td class="res">(.*?)<\/td>/g) || []).join('');
  totalSep += (cells.match(/ · /g) || []).length;
}
check('all checks reachable across pages', totalRowsSeen === distinctChecks, 'seen=' + totalRowsSeen + ' checks=' + distinctChecks);
check('multi-resource checks list each flagged resource (all pages)', totalSep === __test.allFindings().length - distinctChecks, 'seps=' + totalSep + ' extra=' + (__test.allFindings().length - distinctChecks));
__test.setCPage(1);
check('check summary header shows failing count', /checks with findings/.test(htmlOf('checksSum')) && /failing/.test(htmlOf('checksSum')), htmlOf('checksSum').slice(0, 120));
getEl('cdrow-0').style.display = 'none';
__test.ctoggleRow(0);
check('clicking a check-summary row expands its findings', getEl('cdrow-0').style.display === 'table-row' && htmlOf('checksBody').includes('Remediation / Hardening steps'), 'disp=' + getEl('cdrow-0').style.display);
__test.ctoggleRow(0);
check('clicking again collapses the row', getEl('cdrow-0').style.display === 'none', 'disp=' + getEl('cdrow-0').style.display);
__test.showView('findings');
check('back to findings restores dashboard', getEl('view-findings').style.display === 'block');

console.log('== CIS benchmark score (in dashboard) ==');
check('no mitre tags on findings rows', !htmlOf('findingsBody').includes('mitre-tag'));
check('detail rows carry impact section', htmlOf('findingsBody').includes('Impact') && htmlOf('findingsBody').includes('Where the issue is'));
check('detail rows no longer show the old CIS mapping block', !htmlOf('findingsBody').includes('CIS Benchmark mapping'));
check('CIS benchmark view removed from sidebar', !html.includes('data-view="cis"'));

console.log('== Reference links (vendor docs only) ==');
__test.showView('checks');
getEl('cdrow-0').style.display = 'none';
__test.ctoggleRow(0);
check('check detail rows carry vendor reference links', htmlOf('checksBody').includes('Reference / fix article') && htmlOf('checksBody').includes('ref-link'), 'refs=' + (htmlOf('checksBody').match(/ref-link/g) || []).length);
check('no generic CIS benchmark landing-page link', !htmlOf('checksBody').includes('CIS Benchmark'), 'refs=' + htmlOf('checksBody').slice(0, 200));
__test.ctoggleRow(0);

console.log('== Coverage + least-privilege cloud tabs ==');
__test.showView('coverage');
check('coverage tabs show all 4 clouds as reference, scanned auto-selected', ['AWS','Azure','GCP','OCI'].every(l => htmlOf('covTabs').includes(l)) && (scannedClouds.length > 1 ? (htmlOf('covTabs').match(/svc-tab/g) || []).length >= 5 && htmlOf('covTabs').includes('All clouds') : (htmlOf('covTabs').match(/svc-tab/g) || []).length === 4 && !htmlOf('covTabs').includes('All clouds')), 'tabs=' + (htmlOf('covTabs').match(/svc-tab/g) || []).length);
__test.setCovTab('aws');
check('coverage tab isolates one cloud', htmlOf('coverageGrid').includes('AWS') && !htmlOf('coverageGrid').includes('Azure'), 'grid=' + htmlOf('coverageGrid').slice(0, 120));
__test.setCovTab('azure');
check('reference tabs browse other clouds (kept as reference, not removed)', htmlOf('coverageGrid').includes('Azure') && htmlOf('coverageGrid').includes('checks'), 'grid=' + htmlOf('coverageGrid').slice(0, 120));
__test.setCovTab(scannedClouds[0]);
check('re-selecting the scanned cloud shows its coverage', htmlOf('coverageGrid').includes(CL[scannedClouds[0]]), 'grid=' + htmlOf('coverageGrid').slice(0, 120));
__test.showView('policies');
check('least-privilege tabs show all 4 clouds as reference', ['AWS','Azure','GCP','OCI'].every(l => htmlOf('polTabs').includes(l)) && (scannedClouds.length > 1 ? (htmlOf('polTabs').match(/svc-tab/g) || []).length >= 5 && htmlOf('polTabs').includes('All clouds') : (htmlOf('polTabs').match(/svc-tab/g) || []).length === 4 && !htmlOf('polTabs').includes('All clouds')), 'tabs=' + (htmlOf('polTabs').match(/svc-tab/g) || []).length);
check('least-privilege auto-selects the scanned cloud', htmlOf('policiesBody').includes('<b>' + CL[scannedClouds[0]] + '</b>') && (scannedClouds.length > 1 || (!htmlOf('policiesBody').includes('<b>Azure</b>') && !htmlOf('policiesBody').includes('<b>GCP</b>') && !htmlOf('policiesBody').includes('<b>OCI</b>'))), 'pol=' + htmlOf('policiesBody').slice(0, 160));
__test.setPolTab('gcp');
check('least-privilege reference shows other clouds on demand', htmlOf('policiesBody').includes('<b>GCP</b>'), 'pol=' + htmlOf('policiesBody').slice(0, 120));
__test.showView('findings');

// Data-level count (full result set) vs DOM count (current page only, PAGE_SIZE).
let totalRows = __test.currentFindings().length;   // default view = issues only (status FAIL)
console.log('== Grouping by service (default) ==');
const grpHdrs = (htmlOf('findingsBody').match(/grp-row/g) || []).length;
check('findings grouped by service by default', grpHdrs > 0 && htmlOf('findingsBody').includes('grp-head') && htmlOf('findingsBody').includes('grp-name'), 'groups=' + grpHdrs);
check('group headers carry service name + fail counts', /finding\(s\)/.test(htmlOf('findingsBody')) && /failed/.test(htmlOf('findingsBody')) && htmlOf('findingsBody').includes('grp-count'), 'snippet=' + ((htmlOf('findingsBody').match(/grp-count[^<]*/g) || [''])[0] || '').slice(0, 60));
const domGrpRows = rowCount();
__test.state.grp = 'none'; __test.renderFindings();
const domFlatRows = rowCount();
check('flat and grouped views render the same findings rows', domFlatRows === domGrpRows, 'grp=' + domGrpRows + ' flat=' + domFlatRows);
check('flat view (group=none) removes headers', (htmlOf('findingsBody').match(/grp-row/g) || []).length === 0);
__test.state.grp = 'service'; __test.renderFindings();
check('grouped view restores headers', (htmlOf('findingsBody').match(/grp-row/g) || []).length === grpHdrs);
const grpHeads = [...htmlOf('findingsBody').matchAll(/class="grp-head">([\s\S]*?)<\/div><\/td><\/tr>/g)].map(m => m[1]);
const SEVRANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, PASS: 5 };
const grpRank = h => { const m = h.match(/sev sev-([A-Z]+)/); return m && SEVRANK[m[1]] !== undefined ? SEVRANK[m[1]] : 5; };
check('group headers carry a worst-severity badge', grpHeads.length > 0 && /sev sev-(CRITICAL|HIGH|MEDIUM|LOW|INFO|PASS)/.test(grpHeads[0]), 'first=' + String(grpHeads[0]).slice(0, 90));
const grpOrderOk = grpHeads.every((h, idx) => idx === 0 || (grpRank(h) >= grpRank(grpHeads[idx - 1])));
check('groups ordered by worst severity first', grpOrderOk, 'first=' + String(grpHeads[0]).slice(0, 40) + ' last=' + String(grpHeads[grpHeads.length - 1]).slice(0, 40));
const grpBlocks = [...htmlOf('findingsBody').matchAll(/<tr class="grp-row"[^>]*>([\s\S]*?)<\/td><\/tr>([\s\S]*?)(?=<tr class="grp-row"|$)/g)].map(m => m[2]);
const rowsSorted = grpBlocks.length > 0 && grpBlocks.every(b => {
  const sevs = [...b.matchAll(/sev sev-([A-Z]+)"/g)].map(x => SEVRANK[x[1]]);
  return sevs.every((s, i) => i === 0 || sevs[i - 1] <= s);
});
check('findings sorted by severity within each group', rowsSorted, 'blocks=' + grpBlocks.length);

console.log('== Cloud tab switching ==');
const targetCloud = scannedClouds[0];
__test.setCloud(targetCloud);
const cloudRows = __test.currentFindings().length;
if (scannedClouds.length > 1) {
  check("'" + targetCloud + "' tab filters table (" + cloudRows + " < " + totalRows + ")", cloudRows > 0 && cloudRows < totalRows, targetCloud + '=' + cloudRows + ' all=' + totalRows);
} else {
  check("single-cloud '" + targetCloud + "' tab keeps all rows (" + cloudRows + " of " + totalRows + ")", cloudRows > 0 && cloudRows === totalRows, targetCloud + '=' + cloudRows + ' all=' + totalRows);
}
const cloudKpi = htmlOf('kpis');
check('KPIs re-render for ' + targetCloud + ' scope', cloudKpi.includes('Risk score'));
__test.setCloud('all');

console.log('== Search filter ==');
// cloud-aware probe: search a real check id prefix that matches a strict subset
const probeQ = __test.currentFindings()[0].check_id.toLowerCase();
__test.state.q = probeQ;
__test.renderFindings();
const s3Data = __test.currentFindings().length;
check('search "' + probeQ + '" filters findings (' + s3Data + ' of ' + totalRows + ')', s3Data > 0 && s3Data < totalRows, probeQ + '=' + s3Data);
check('finding count text updates', String(getEl('findingCount').textContent).includes(' of '));
__test.state.q = '';
__test.renderFindings();
check('clearing search restores findings', __test.currentFindings().length === totalRows, 'after=' + __test.currentFindings().length);

console.log('== Row expansion ==');
getEl('drow-0').style.display = 'none'; // browser initial state (template inline style)
__test.toggleRow(0);
check('row 0 detail expands', getEl('drow-0').style.display === 'table-row');
__test.toggleRow(0);
check('row 0 detail collapses', getEl('drow-0').style.display === 'none');

console.log('== Severity filter ==');
__test.state.sev = 'CRITICAL';
__test.renderFindings();
const critData = __test.currentFindings().length;
check('severity=CRITICAL filters findings (' + critData + ')', critData >= 0 && critData < totalRows, 'crit=' + critData);
__test.state.sev = '';
__test.renderFindings();

console.log('== Status filter ==');
__test.state.status = 'FAIL';
__test.renderFindings();
const failData = __test.currentFindings().length;
check('status=FAIL keeps failures (' + failData + ' of ' + totalRows + ')', failData > 0 && failData <= totalRows, 'fail=' + failData);
__test.state.status = '';
__test.renderFindings();
// status '' shows ALL results (PASS included). The dashboard default is now
// issues-only (FAIL), so rebase the pagination/export expectations below on
// this 'All statuses' baseline the modal actually sees.
totalRows = __test.currentFindings().length;

console.log('== Collapsible groups & pagination ==');
const grpKey0 = __test.grpOf(__test.currentFindings()[0]);
const domBefore = rowCount();
__test.toggleGrp(grpKey0);
check('clicking a group header collapses its findings', rowCount() < domBefore, 'before=' + domBefore + ' after=' + rowCount());
__test.toggleGrp(grpKey0);
check('clicking again expands the group', rowCount() === domBefore, 'before=' + domBefore + ' after=' + rowCount());
const pgPages = Math.max(1, Math.ceil(totalRows / 20));
const pgBtns = (htmlOf('pager').match(/pg-btn/g) || []).length;
check('pagination renders Prev/Next + numbered pages (' + pgBtns + ' buttons)', pgBtns === pgPages + 2, 'btns=' + pgBtns + ' pages=' + pgPages);
check('pager highlights active page 1', htmlOf('pager').includes('pg-btn active'));
__test.setPage(2);
check('page 2 renders findings', rowCount() > 0, 'rows=' + rowCount());
check('page 2 highlighted in pager', htmlOf('pager').includes('>2</button>') && htmlOf('pager').includes('pg-btn active'), 'pager=' + htmlOf('pager').slice(0, 140));
__test.setPage(1);
check('back to page 1', htmlOf('pager').includes('pg-btn active'));

console.log('== View modes (List / Tab) ==');
check('grid view fully removed from dashboard', !html.includes('findingsGrid') && !html.includes('renderGrid') && !html.includes('fcard') && !html.includes('data-v="grid"'), 'grid remnants found');
__test.setViewMode('tab');
const svcKeys = [...htmlOf('svcTabs').matchAll(/setSvcTab\('([^']+)'\)/g)].map(m => m[1]).filter(k => k !== 'all');
check('tab view renders service tabs', svcKeys.length >= 2, 'tabs=' + svcKeys.length);
const tabRowsBefore = (htmlOf('tabBody').match(/<tr/g) || []).length;
check('tab view lists findings', tabRowsBefore >= 2, 'rows=' + tabRowsBefore);
__test.setSvcTab(svcKeys[0]);
const tabRowsAfter = (htmlOf('tabBody').match(/<tr/g) || []).length;
check('service tab filters findings', tabRowsAfter > 0 && tabRowsAfter < tabRowsBefore, 'after=' + tabRowsAfter + ' before=' + tabRowsBefore);
__test.setViewMode('list');
check('back to list view restores grouped table', getEl('findingsList').style.display !== 'none' && (htmlOf('findingsBody').match(/grp-row/g) || []).length > 0);

console.log('== Exports ==');
__test.exportExcel();
const xlsA = global.__created[global.__created.length - 1];
const xlsXml = global.__lastBlob || '';  check('Excel export triggers .xls download', !!xlsA && xlsA.download === 'cloudguard_findings_report.xls' && String(xlsA.href).startsWith('blob:'), 'got ' + (xlsA && xlsA.download));
check('Excel is findings-only (single sheet, no Summary/Comparison)', xlsXml.startsWith('<?xml') && xlsXml.includes('<Workbook') && xlsXml.includes('<Worksheet ss:Name="Findings"') && !xlsXml.includes('ss:Name="Summary"') && !xlsXml.includes('ss:Name="Comparison"'), 'sheets=' + (xlsXml.match(/<Worksheet/g) || []).length);
check('Excel rows = header + all findings', (xlsXml.match(/<Row/g) || []).length === totalRows + 1, 'rows=' + (xlsXml.match(/<Row/g) || []).length);
check('Excel has Where/Impact/Remediation columns', xlsXml.includes('Where the issue is') && xlsXml.includes('Impact') && xlsXml.includes('Remediation / Hardening steps'));
const cisFind = __test.currentFindings().find(f => f.cis);
const cisPfx = (cisFind ? cisFind.cis : 'CIS').split(' ').slice(0, 2).join(' ');
check('excel has CIS column (no Mitre)', xlsXml.includes('Framework (CIS)') && xlsXml.includes(cisPfx) && !xlsXml.includes('Mitre') && !xlsXml.includes('T1078'), 'pfx=' + cisPfx);
__test.exportCSV();
const csvA = global.__created[global.__created.length - 1];  check('CSV export triggers .csv download', !!csvA && csvA.download === 'cloudguard_findings.csv', 'got ' + (csvA && csvA.download));
__test.exportPDF();
check('PDF export invokes print dialog', true);
check('print report populated with findings structure', htmlOf('printReport').includes('Where the issue is') && htmlOf('printReport').includes('Impact') && htmlOf('printReport').includes('Remediation / Hardening steps') && htmlOf('printReport').includes('account'));

console.log('== False-positive exclusion modal ==');
__test.openExport('excel');
check('modal opens', String(getEl('exportOverlay').className).includes('open'));
const cbAll = (htmlOf('exclList').match(/<input type="checkbox"/g) || []).length;
check('checkbox per finding (' + cbAll + ' of ' + totalRows + ')', cbAll === totalRows, 'cb=' + cbAll);
check('default pre-selects ALL findings', txtOf('exclCount').includes(totalRows + ' of ' + totalRows), txtOf('exclCount'));
const svcOpts = (htmlOf('exclSvc').match(/<option/g) || []).length;
check('service filter dropdown populated (' + (svcOpts - 1) + ' services)', svcOpts > 1, 'opts=' + svcOpts);
// Scope to the FIRST service -> only its findings stay selected.
const firstSvc = (window.__test.currentFindings()[0] || {}).service || '';
__test.setExpFilter('svc', firstSvc);
const svcCount = window.__test.currentFindings().filter(f => f.service === firstSvc).length;
check('service filter scopes selection to that service (' + svcCount + ')', txtOf('exclCount').includes(svcCount + ' of '), txtOf('exclCount'));
__test.setExpFilter('svc', '');
check('clearing filter restores all selected', txtOf('exclCount').includes(totalRows + ' of ' + totalRows), txtOf('exclCount'));
__test.setAllSel(true);
check('select-all keeps count at total', txtOf('exclCount').includes(totalRows + ' of ' + totalRows), txtOf('exclCount'));
check('confirm button says Export Excel', String(getEl('exclConfirm').textContent).includes('Export Excel'), getEl('exclConfirm').textContent);
__test.toggleSel(0, false);
check('untick updates count to total-1', txtOf('exclCount').includes((totalRows - 1) + ' of ' + totalRows), txtOf('exclCount'));
__test.confirmExport();
check('modal closes after confirm', !String(getEl('exportOverlay').className).includes('open'));
check('exclusion note shows', String(getEl('exclNote').className).includes('show'));
check('excluded row marked in table', htmlOf('findingsBody').includes('excluded'));
const xls2 = global.__lastBlob || '';
// Single findings sheet: 1 header + (total-1) selected
check('excel excludes unticked finding', (xls2.match(/<Row/g) || []).length === totalRows, 'rows=' + (xls2.match(/<Row/g) || []).length);
check('findings sheet has header + total-1 selected rows', worksheetRows(xls2, 0) === totalRows, 'rows=' + worksheetRows(xls2, 0));
check('excel stays findings-only after exclusion', !xls2.includes('ss:Name="Summary"') && !xls2.includes('ss:Name="Comparison"'));
const failCount = __test.currentFindings().filter(f => f.status === 'FAIL').length;
__test.openExport('csv');
__test.setAllSel(false);
check('deselect all shows 0 selected', txtOf('exclCount').includes('0 of ' + totalRows), txtOf('exclCount'));
__test.setFailedOnly();
check('failed-only selects fail count', txtOf('exclCount').includes(failCount + ' of ' + totalRows), txtOf('exclCount'));
__test.confirmExport();
const csv2 = global.__lastBlob || '';
check('csv excludes non-failed findings', (csv2.match(/\n/g) || []).length === failCount, 'newlines=' + (csv2.match(/\n/g) || []).length);
__test.clearExclusions();
check('clear exclusions hides note', !String(getEl('exclNote').className).includes('show'));
__test.renderFindings();
check('table rows un-marked after clear', !htmlOf('findingsBody').includes('excluded'));

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
