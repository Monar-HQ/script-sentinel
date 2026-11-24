'use strict';
const $ = id => document.getElementById(id);
const incoming = new URLSearchParams(location.hash.slice(1)).get('token');
if (incoming) { sessionStorage.setItem('scriptsentinel-token', incoming); history.replaceState(null, '', location.pathname); }
const token = sessionStorage.getItem('scriptsentinel-token') || '';
let report = null, proposal = null, proposalId = null;
const el = (tag, text, cls) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (cls) node.className = cls; return node; };
function notice(text, kind = '') { const node = $('notice'); node.hidden = false; node.textContent = text; node.className = kind; }
async function api(path, data) {
  const response = await fetch('/api/' + path, { method: data === undefined ? 'GET' : 'POST', headers: {Authorization: 'Bearer ' + token, ...(data === undefined ? {} : {'Content-Type': 'application/json'})}, ...(data === undefined ? {} : {body: JSON.stringify(data)}) });
  const value = await response.json(); if (!response.ok) throw new Error(value.error || 'Request failed'); return value;
}
async function task(message, action) {
  notice(message, 'busy'); document.querySelectorAll('button').forEach(button => button.disabled = true);
  try { await action(); notice('Operation complete. Evidence saved locally.'); }
  catch (error) { notice(error.message, 'error'); }
  finally { document.querySelectorAll('button').forEach(button => button.disabled = false); }
}
function view(name) {
  document.querySelectorAll('.view').forEach(section => section.hidden = section.id !== name);
  document.querySelectorAll('[data-view]').forEach(button => { if (button.dataset.view === name) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current'); });
  $('breadcrumb').textContent = 'Workspace / ' + ({overview:'Overview',inventory:'Script inventory',monitor:'Baseline & monitoring',patch:'Patch review',research:'Research library',activity:'Activity ledger'}[name]);
  if (name === 'activity') loadEvents().catch(error => notice(error.message, 'error'));
  if (name === 'research') loadResearch().catch(error => notice(error.message, 'error'));
}
document.querySelectorAll('[data-view]').forEach(button => button.onclick = () => view(button.dataset.view));
function badge(text) { const node = el('span', text, 'badge'); node.dataset.severity = text; return node; }
function allFindings(value) {
  return [...value.csp.findings.map(f => ({...f, source:'Content Security Policy'})), ...value.scripts.flatMap(s => [...(s.scan?.findings || []).map(f => ({...f,title:f.name,source:s.url || 'Inline script'})), ...(s.integrity?.issues || []).map(f => ({...f,title:f.type,description:f.message,source:s.url}))])];
}
function renderReport(value, demo) {
  value = {...value, scripts:value.scripts.map(s => ({...s, kind:s.kind || s.type, integrity:s.integrity || s.integrity_audit, scan:s.scan || s.scanner_audit}))};
  report = value; $('empty').hidden = true; $('report').hidden = false;
  $('run-label').textContent = (demo ? 'Synthetic demo · ' : 'Workspace · ') + new Date(value.timestamp).toLocaleString();
  $('report-title').textContent = demo ? 'Synthetic checkout results' : 'Workspace audit results';
  $('risk').textContent = value.overall_risk + ' POSTURE'; $('risk').dataset.severity = value.overall_risk;
  $('script-count').textContent = value.scripts.length;
  $('unavailable-count').textContent = value.scripts.filter(s => s.error).length;
  $('csp-grade').textContent = value.csp.grade + ' / ' + value.csp.score;
  $('findings').replaceChildren();
  const findings = allFindings(value);
  const priority = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
  findings.sort((a,b) => (priority[a.severity] ?? 5) - (priority[b.severity] ?? 5));
  for (const finding of findings) {
    const row = el('article', null, 'finding'), body = el('div'); row.append(badge(finding.severity));
    body.append(el('h3', finding.title), el('p', finding.description));
    const detail = el('details'); detail.append(el('summary', 'Evidence & next action'), el('p', 'Source: ' + finding.source), el('p', 'Rule: ' + (finding.rule_id || finding.type)), el('p', finding.recommendation || 'Review this capability in its application context. This signal alone does not prove compromise.'));
    body.append(detail); row.append(body); $('findings').append(row);
  }
  if (!findings.length) $('findings').append(el('p', 'No configured rule matched. This is limited analysis coverage, not proof that the application is secure.'));
  if (value.error) $('findings').prepend(el('p', 'Analysis incomplete: ' + value.error));
  renderScripts();
}
function renderScripts() {
  if (!report) return;
  const query = $('search').value.toLowerCase(); $('scripts').replaceChildren();
  const rows = report.scripts.filter(s => JSON.stringify(s).toLowerCase().includes(query));
  for (const script of rows) {
    const row = el('tr'), source = el('td', script.url || 'Inline script #' + (script.index + 1));
    source.append(el('small', script.error || script.analysis_note || (script.integrity?.calculated.sha256 ? 'SHA-256 ' + script.integrity.calculated.sha256.slice(0,24) + '…' : (script.length || 0) + ' characters')));
    row.append(source, el('td', script.kind), el('td', script.error ? 'Unavailable' : script.integrity?.status || 'Not applicable'), el('td', (script.scan?.findings || []).map(f => f.rule_id).join(', ') || 'No rule matched'));
    $('scripts').append(row);
  }
  if (!rows.length) { const row = el('tr'), cell = el('td', 'No matching scripts.'); cell.colSpan = 4; row.append(cell); $('scripts').append(row); }
}
async function audit(demo = false) { await task('Collecting script, integrity, AST and CSP evidence…', async () => {const result = await api(demo ? 'demo' : 'audit', {}); renderReport(result.report, demo); view('overview');}); }
$('audit').onclick = () => audit(); $('demo').onclick = () => audit(true); $('inventory-audit').onclick = () => audit(); $('search').oninput = renderScripts;
function download(name, data) { const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)], {type:'application/json'})); const a = el('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
$('download-report').onclick = () => report && download('scriptsentinel-report.json', report);
$('baseline-form').onsubmit = event => { event.preventDefault(); task('Recording your reviewed baseline…', async () => { await api('baseline', {reviewer:$('reviewer').value,provenance:$('provenance').value,approve:$('baseline-approved').checked}); $('baseline-status').textContent = 'Reviewed baseline saved. Existing baselines are never silently replaced.'; }); };
$('compare').onclick = () => task('Comparing local bytes with the reviewed baseline…', async () => { const result = await api('monitor', {}); $('drift').textContent = result.changed ? result.changes.map(c => c.kind.toUpperCase() + '  ' + c.file).join('\n') : 'No local changes detected against the reviewed baseline.'; });
$('proposal-form').onsubmit = event => {event.preventDefault(); task('Preparing a deterministic SRI diff…', async () => {const result = await api('propose',{file:$('html-file').value,baseline:$('baseline-file').value}); proposal = result.proposal; proposalId = result.id; $('proposal-result').hidden = false; $('diff').textContent = proposal.diff; $('validation').textContent = 'Validation has not run.';});};
$('download-proposal').onclick = () => proposal && download('scriptsentinel-proposal.json', proposal);
$('validate').onclick = () => task('Verifying staged bytes in a temporary copy…', async () => {const result = await api('validate',{id:proposalId,baseline:$('baseline-file').value}); $('validation').textContent = 'PASSED\n' + result.checks.join('\n') + '\n\nApplication tests: ' + result.application_tests;});
async function loadResearch() {
  const pack = await api('research'); $('research-content').replaceChildren();
  const intro = el('div',null,'research-item'); intro.append(el('strong','OPTIMJACK'),el('p','CVE-2026-132224 · CNA CVSS 4.0: 7.1 High. Verified ' + pack.verified_on + '. Historical lab evidence is separately attributed.')); $('research-content').append(intro);
  for (const source of pack.sources) { const row = el('article',null,'research-item'), body = el('div'); row.append(el('small',source.status)); body.append(el('p',source.supports)); if (source.url.startsWith('https://')) { const link = el('a',source.url); link.href = source.url; link.target='_blank';link.rel='noopener noreferrer';body.append(link); } row.append(body); $('research-content').append(row); }
}
async function loadEvents() { const events = await api('events'); $('events').replaceChildren(); for (const event of events) {const row = el('article',null,'activity-row'), details=el('details'); row.append(el('time',new Date(event.time).toLocaleString()),el('strong',event.kind)); details.append(el('summary','Inspect evidence #' + event.id),el('pre',JSON.stringify(event.data,null,2)));row.append(details);$('events').append(row);} if(!events.length) $('events').append(el('p','Your first audit, reviewed baseline or comparison will start the ledger.')); }
$('refresh-activity').onclick = () => task('Loading local evidence…',loadEvents);
api('status').then(status => {$('workspace').textContent=status.workspace;$('workspace').title=status.workspace;$('version').textContent=status.version + ' · ' + status.mode;$('baseline-status').textContent=status.baseline?'A baseline already exists. Compare it or review it in your workspace.':'No baseline approved yet.';}).catch(error => notice(error.message,'error'));
