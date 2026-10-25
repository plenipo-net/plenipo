/** The live dashboard page. Self-contained: no external scripts, fonts or styles. */
import { BASE_CSS } from './layout.js';

const CSS = `
body{--svc:var(--accent)}
.wrap{max-width:1500px;margin:0 auto;padding:18px 22px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.kpi .n{font-size:28px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.kpi .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.kpi.allow .n{color:var(--allow)} .kpi.deny .n{color:var(--deny)}
.cols{display:grid;grid-template-columns:minmax(330px,1.05fr) minmax(420px,1.45fr) minmax(300px,1fr);gap:16px;align-items:start}
.col>div{max-height:calc(100vh - 205px);overflow-y:auto;padding-right:4px;scrollbar-width:thin}
.col h2{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin:0 0 10px;font-weight:650}
.m{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--allow);border-radius:9px;padding:11px 13px;margin-bottom:10px}
.m.revoked{border-left-color:var(--deny);opacity:.78} .m.suspended{border-left-color:var(--warn)}
.m.child{margin-left:22px}
.m .who{font-weight:650}
.m .scope{font-size:13px;color:var(--muted);margin:3px 0 6px}
.bar{height:8px;background:var(--soft);border-radius:99px;overflow:hidden;margin-top:4px}
.bar>i{display:block;height:100%;background:var(--accent);border-radius:99px;transition:width .4s}
.bar.hot>i{background:var(--deny)}
.barl{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.d{display:grid;grid-template-columns:62px 92px 1fr;gap:4px 10px;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:9px 12px;margin-bottom:8px;animation:in .35s ease}
.d .t{font-family:var(--mono);font-size:12px;color:var(--muted);padding-top:2px}
.d .what{font-size:14px;overflow-wrap:anywhere}
.d .why{grid-column:3;font-size:12.5px;color:var(--muted)}
.d .code{font-family:var(--mono);font-size:12.5px;font-weight:650;color:var(--deny)}
.pill{font-family:var(--mono);font-size:11.5px;background:var(--soft);border-radius:5px;padding:0 6px;color:var(--muted)}
.s{overflow-wrap:anywhere;font-size:13.5px;padding:7px 10px;border-left:3px solid var(--line);margin-bottom:6px;background:var(--panel);border-radius:0 7px 7px 0;animation:in .35s ease}
.s.platform{border-left-color:var(--platform)} .s.wallet{border-left-color:var(--wallet)} .s.pid{border-left-color:var(--pid)}
.s.bank{border-left-color:var(--bank)} .s.agent{border-left-color:var(--agent)}
.s.scenario{background:var(--soft);font-weight:650}
.s.pass{color:var(--allow)} .s.fail{color:var(--deny)}
.s .src{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-right:6px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--muted);margin-right:5px}
.dot.up{background:var(--allow)} .dot.down{background:var(--deny)}
.empty{color:var(--muted);font-size:13.5px;padding:10px 2px}
@keyframes in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
@media (max-width:1100px){.cols{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.col>div{max-height:none}}
`;

const SCRIPT = `
const $ = (s) => document.querySelector(s);
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') el.className = v; else if (k === 'style') el.style.cssText = v; else el.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) el.append(k instanceof Node ? k : String(k));
  return el;
}
const eur = (c) => '€ ' + (c / 100).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const time = (ts) => (ts || '').slice(11, 19);
const short = (id) => (id || '').slice(0, 8);
const state = { mandates: new Map(), order: [], decisions: [], story: [], allow: 0, deny: 0, unresolved: [] };

function person(m) { return m.person || ''; }
function upsertMandate(e, fields) {
  const cur = state.mandates.get(e.mandate_id) || { id: e.mandate_id, state: 'active', usage: null };
  Object.assign(cur, fields);
  if (!state.mandates.has(e.mandate_id)) { state.mandates.set(e.mandate_id, cur); state.order.push(e.mandate_id); }
}
function story(e, text, extra) {
  state.story.unshift({ e, text, extra: extra || '' });
  if (state.story.length > 200) state.story.pop();
}

function apply(e) {
  const src = e.source, t = e.type;
  if (src === 'platform') {
    if (t === 'mandate_requested') story(e, e.agent + ' asks for a mandate: ' + (e.purpose || e.scope));
    if (t === 'mandate_approved') { upsertMandate(e, { person: e.person, agent: e.agent, depth: 0, mandate: e.mandate, scope: e.scope, state: 'active' }); story(e, e.person + ' approved the mandate for ' + e.agent + ' with the PID'); }
    if (t === 'mandate_delegated') { upsertMandate(e, { person: e.person, agent: e.agent, depth: e.depth, parent: e.parent_id, mandate: e.mandate, scope: e.scope, state: 'active' }); story(e, e.parent_agent + ' delegated a narrower mandate to ' + e.agent); }
    if (t === 'delegation_refused') story(e, 'Platform refused a delegation that would widen authority', 'fail');
    if (t === 'mandate_rejected') story(e, 'Wallet response rejected: ' + e.code, 'fail');
    if (t === 'mandate_refused') story(e, 'The person refused the mandate in the wallet');
    for (const [k, s] of [['mandate_revoked', 'revoked'], ['mandate_suspended', 'suspended'], ['mandate_reinstated', 'active']]) {
      if (t === k) { upsertMandate(e, { state: s }); story(e, 'Mandate ' + short(e.mandate_id) + ' (' + (e.agent || '') + ') ' + s + ' in the status list', s === 'active' ? '' : 'fail'); }
    }
  } else if (src === 'wallet') {
    if (t === 'request_received') story(e, 'Wallet received a request from ' + e.client_id);
    if (t === 'consent_approved') story(e, e.person + ' tapped Approve');
    if (t === 'consent_refused') story(e, e.person + ' tapped Refuse');
  } else if (src === 'pid') {
    if (t === 'pid_revoked') story(e, 'PID provider revoked the PID of ' + e.person, 'fail');
    if (t === 'pid_suspended') story(e, 'PID provider suspended the PID of ' + e.person, 'fail');
    if (t === 'pid_reinstated') story(e, 'PID provider reinstated the PID of ' + e.person);
  } else if (src === 'bank') {
    if (t === 'decision') { state.decisions.unshift(e); if (state.decisions.length > 300) state.decisions.pop(); if (e.decision === 'ALLOW') state.allow++; else state.deny++; }
    if (t === 'ledger') for (const u of e.usage || []) { const m = state.mandates.get(u.mandate_id); if (m) m.usage = u; else upsertMandate({ mandate_id: u.mandate_id }, { usage: u, depth: u.depth, agent: 'mandate ' + short(u.mandate_id) }); }
    if (t === 'payment_executed') story(e, 'Bank paid ' + eur(e.amount.value) + ' to ' + e.payee + ' for ' + e.person + ' · balance ' + eur(e.balance_after));
    if (t === 'card_blocked') story(e, 'Bank blocked the card of ' + e.person);
    if (t === 'clock_changed') story(e, 'Bank clock moved by ' + e.offset_seconds + ' s');
    if (t === 'note') story(e, e.text);
    if (t === 'payment_unknown_outcome') story(e, 'Core banking timed out paying ' + eur(e.amount.value) + ' to ' + e.payee + ': outcome unknown, the reservation stays pending', 'fail');
    if (t === 'reservations') { state.unresolved = e.unresolved || []; if (e.swept) story(e, 'Ledger sweep: ' + e.swept + ' reservation(s) left pending past their TTL now count as spent until reconciled', 'fail'); }
    if (t === 'account_refilled') story(e, 'Play money: the account of ' + e.person + ' is back to ' + eur(e.balance_after));
    if (t === 'reservation_reconciled') story(e, 'Reservation ' + short(e.reservation) + ' reconciled as ' + e.outcome + ' (' + e.state + ')');
  } else if (src === 'agent') {
    if (t === 'scenario_start') story(e, '▶ ' + e.title, 'scenario');
    if (t === 'scenario_result') story(e, (e.pass ? 'PASS ' : 'FAIL ') + e.title + (e.observed ? ' · ' + e.observed : ''), e.pass ? 'pass' : 'fail');
    if (t === 'llm_text') story(e, '🤖 ' + e.text);
    if (t === 'session_started') story(e, e.text, 'scenario');
    if (t === 'session_closed') story(e, 'The remote agent session ended (' + e.reason + ')');
    if (t === 'tool_result' && e.decision === 'DENY') story(e, 'The bank refused ' + e.tool + ': ' + (e.why || e.code), 'fail');
    if (t === 'tool_call') story(e, 'Agent calls ' + e.tool + ' ' + JSON.stringify(e.args || {}));
    if (t === 'note') story(e, e.text);
  }
}

function renderMandates() {
  const box = $('#mandates'); box.replaceChildren();
  const ids = state.order.filter((id) => state.mandates.get(id).mandate || state.mandates.get(id).usage);
  if (!ids.length) { box.append(h('div', { class: 'empty' }, 'No mandates yet. Approve one in the wallet.')); return; }
  const roots = ids.filter((id) => !state.mandates.get(id).parent || !state.mandates.has(state.mandates.get(id).parent));
  const render = (id) => {
    const m = state.mandates.get(id);
    const parent = m.parent && state.mandates.get(m.parent);
    const eff = parent && parent.state !== 'active' ? parent.state : m.state;
    const lim = (m.mandate && m.mandate.limits) || {};
    const u = m.usage;
    const total = lim.total !== undefined ? lim.total : u && u.total;
    const spent = u ? u.spent : 0;
    const pct = total ? Math.min(100, Math.round((spent / total) * 100)) : 0;
    const el = h('div', { class: 'm ' + eff + (m.depth ? ' child' : '') },
      h('div', { class: 'row' }, h('span', { class: 'who' }, m.agent || 'agent'), m.person ? h('span', { class: 'muted' }, 'for ' + m.person) : null,
        h('span', { class: 'badge ' + (eff === 'active' ? 'b-allow' : eff === 'suspended' ? 'b-warn' : 'b-deny'), style: 'margin-left:auto' }, eff)),
      h('div', { class: 'scope' }, (m.depth ? 'depth ' + m.depth + ' · ' : 'root · ') + (m.scope || ''), ' ', h('span', { class: 'pill' }, short(m.id))),
      total ? [h('div', { class: 'barl' }, h('span', {}, 'spent ' + eur(spent)), h('span', {}, 'of ' + eur(total) + (lim.per_operation ? ' · max ' + eur(lim.per_operation) + '/op' : ''))),
        h('div', { class: 'bar' + (pct >= 85 ? ' hot' : '') }, h('i', { style: 'width:' + pct + '%' }))] : null,
      m.mandate ? h('div', { class: 'barl', style: 'margin-top:5px' }, h('span', {}, 'expires ' + new Date(m.mandate.exp * 1000).toISOString().slice(0, 16).replace('T', ' '))) : null);
    box.append(el);
    for (const cid of ids.filter((x) => state.mandates.get(x).parent === id)) render(cid);
  };
  roots.reverse().forEach(render);
}

function renderDecisions() {
  const box = $('#decisions'); box.replaceChildren();
  if (!state.decisions.length) { box.append(h('div', { class: 'empty' }, 'Every call an agent makes to the bank appears here with the verifier\\'s answer.')); return; }
  for (const d of state.decisions.slice(0, 80)) {
    const allow = d.decision === 'ALLOW';
    const amount = d.amount && d.amount.value ? eur(d.amount.value) : '';
    const path = (d.mandate_path || []).map(short).join(' → ');
    box.append(h('div', { class: 'd' },
      h('div', { class: 't' }, time(d.ts)),
      h('div', {}, h('span', { class: 'badge ' + (allow ? 'b-allow' : 'b-deny') }, allow ? 'ALLOW' : 'DENY')),
      h('div', { class: 'what' }, h('strong', {}, d.tool), ' ', h('span', { class: 'pill' }, d.channel), ' ', d.counterparty ? '→ ' + d.counterparty + ' ' : '', amount ? h('strong', {}, amount) : '', allow && d.person ? h('span', { class: 'muted' }, ' for ' + d.person) : ''),
      h('div', { class: 'why' }, allow ? 'chain ' + (path || '?') + (d.depth ? ' (depth ' + d.depth + ')' : '') + (d.amount ? '' : ' · moves no money, nothing reserved') : [h('span', { class: 'code' }, d.code), ' ', d.reason])));
  }
}

function renderStory() {
  const box = $('#story'); box.replaceChildren();
  if (!state.story.length) { box.append(h('div', { class: 'empty' }, 'Waiting for the first event.')); return; }
  for (const s of state.story.slice(0, 120)) {
    box.append(h('div', { class: 's ' + s.e.source + ' ' + s.extra }, h('span', { class: 'src' }, s.e.source), h('span', { class: 'mono muted' }, time(s.e.ts) + ' '), s.text));
  }
}

function renderUnresolved() {
  const box = $('#unresolved'); box.replaceChildren();
  if (!state.unresolved.length) { box.style.display = 'none'; return; }
  box.style.display = '';
  box.append(h('strong', {}, 'Unresolved reservations: '), state.unresolved.length + ' (outcome unknown, counted as spent until reconciled) ',
    ...state.unresolved.slice(0, 6).map((r) => h('span', { class: 'pill', style: 'margin-left:6px' }, short(r.id) + ' ' + eur(r.amount.value))));
}

function renderKpis() {
  const active = [...state.mandates.values()].filter((m) => m.state === 'active' && m.mandate).length;
  $('#k-mandates').textContent = active;
  $('#k-calls').textContent = state.allow + state.deny;
  $('#k-allow').textContent = state.allow;
  $('#k-deny').textContent = state.deny;
  const spent = [...state.mandates.values()].filter((m) => !m.depth && m.usage).reduce((a, m) => a + m.usage.spent, 0);
  $('#k-spent').textContent = eur(spent);
}

let scheduled = false;
function render() { if (scheduled) return; scheduled = true; requestAnimationFrame(() => { scheduled = false; renderKpis(); renderUnresolved(); renderMandates(); renderDecisions(); renderStory(); }); }

async function config() {
  try {
    const c = await (await fetch('/api/config')).json();
    if (window.__boot && c.boot !== window.__boot) location.reload();
    window.__boot = c.boot;
    const nav = $('#links'); nav.replaceChildren();
    for (const [name, l] of Object.entries(c.links)) nav.append(h('a', { href: l.url, target: '_blank', title: c.health[name] === false ? 'not responding' : 'up' }, h('span', { class: 'dot ' + (c.health[name] === false ? 'down' : c.health[name] ? 'up' : '') }), l.label));
  } catch {}
}
config(); setInterval(config, 3000);
// /demo/<code> shows one hosted MCP session only.
const parts = location.pathname.split('/');
const demo = parts[1] === 'demo' && parts[2] ? parts[2].toUpperCase() : '';
if (demo) { document.title = 'Plenipo Sandbox · session ' + demo; $('.sub').textContent = 'One remote agent session, demo code ' + demo + '. Every step, live.'; }
const es = new EventSource(demo ? '/api/demo/' + encodeURIComponent(demo) + '/stream' : '/stream');
es.onmessage = (m) => { try { apply(JSON.parse(m.data)); render(); } catch (e) { console.error(e); } };
render();
`;

export const DASHBOARD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Plenipo Sandbox · live</title><style>${BASE_CSS}${CSS}</style></head><body>
<header class="top"><span class="chip"></span><div><h1>Plenipo Sandbox</h1><div class="sub">A person's EUDI wallet authorises an AI agent; the bank verifies every call. Live.</div></div><nav id="links"></nav></header>
<div class="wrap">
<div class="kpis">
<div class="kpi"><div class="n" id="k-mandates">0</div><div class="l">Active mandates</div></div>
<div class="kpi"><div class="n" id="k-calls">0</div><div class="l">Agent calls verified</div></div>
<div class="kpi allow"><div class="n" id="k-allow">0</div><div class="l">Allowed</div></div>
<div class="kpi deny"><div class="n" id="k-deny">0</div><div class="l">Denied</div></div>
<div class="kpi"><div class="n" id="k-spent">€ 0.00</div><div class="l">Spent under mandates</div></div>
</div>
<div id="unresolved" class="notice" style="display:none;margin-bottom:14px"></div>
<div class="cols">
<section class="col"><h2>Mandates and chains</h2><div id="mandates"></div></section>
<section class="col"><h2>Bank decisions</h2><div id="decisions"></div></section>
<section class="col"><h2>What is happening</h2><div id="story"></div></section>
</div></div>
<script>${SCRIPT}</script></body></html>`;
