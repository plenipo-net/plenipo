/**
 * The page of the MCP audit log at /admin/mcp-audit. It carries no data: it asks for the audit token,
 * keeps it in the tab's sessionStorage and reads the JSON endpoints with it. Everything the log holds came
 * from the network, so it is written with textContent, never as HTML.
 */
export function auditPage(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Plenipo MCP audit</title>
<style>
  :root { --ink:#16202a; --quiet:#5b6875; --line:#dfe4ea; --bg:#ffffff; --tint:#f4f7fa; --accent:#1f5fbf; --deny:#b3261e; --ok:#1e7a46; }
  @media (prefers-color-scheme: dark) { :root { --ink:#e8edf2; --quiet:#9aa7b4; --line:#2c3640; --bg:#12171c; --tint:#1a2128; --accent:#7fb0ff; --deny:#ff8a80; --ok:#7bd8a1; } }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  body { margin:0; font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color:var(--ink); background:var(--bg); }
  main { max-width:1200px; margin:0 auto; padding:20px 16px 48px; }
  h1 { font-size:20px; margin:0 0 4px; }
  h2 { font-size:15px; margin:28px 0 8px; }
  .quiet { color:var(--quiet); }
  .bar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:12px 0; }
  input, select, button { font:inherit; padding:6px 10px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--ink); }
  button { cursor:pointer; }
  .tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:8px; }
  .tile { background:var(--tint); border-radius:8px; padding:10px 12px; }
  .tile b { display:block; font-size:22px; }
  .scroll { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { font-weight:600; color:var(--quiet); white-space:nowrap; }
  td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
  .tag { display:inline-block; padding:1px 6px; border-radius:4px; background:var(--tint); font-size:12px; }
  .used { color:var(--ok); } .deny { color:var(--deny); }
  code { font-size:12px; }
  #err { color:var(--deny); }
</style>
</head>
<body>
<main>
  <h1>Plenipo MCP audit</h1>
  <div class="quiet" id="where"></div>
  <div class="bar" id="login">
    <input id="token" type="password" placeholder="Audit token" autocomplete="off" size="36">
    <button id="save">Open</button>
  </div>
  <div class="bar" id="controls" hidden>
    <label>From <input id="from" type="date"></label>
    <label>To <input id="to" type="date"></label>
    <button id="reload">Reload</button>
    <label><input id="auto" type="checkbox" checked> refresh every 30 s</label>
    <button id="forget">Forget token</button>
  </div>
  <div id="err"></div>
  <section id="data" hidden>
    <div class="tiles" id="tiles"></div>
    <h2>Clients</h2>
    <div class="scroll"><table id="clients"></table></div>
    <h2>Recent sessions</h2>
    <p class="quiet">used: called a tool · listed: listed the tools only, as a registry check does · connected: neither</p>
    <div class="scroll"><table id="sessions"></table></div>
    <h2>Tools</h2>
    <div class="scroll"><table id="tools"></table></div>
    <h2>By day</h2>
    <div class="scroll"><table id="days"></table></div>
    <h2>Refused requests and other paths</h2>
    <div class="scroll"><table id="rejects"></table></div>
    <div class="scroll"><table id="probes"></table></div>
    <h2>Raw log</h2>
    <p class="quiet">One JSON object per line, one file per UTC day: <span id="raw"></span></p>
  </section>
</main>
<script>
(function () {
  var KEY = 'plenipo-mcp-audit-token';
  var $ = function (id) { return document.getElementById(id); };
  var token = '';
  try { token = sessionStorage.getItem(KEY) || ''; } catch (e) {}
  var timer;

  function el(tag, text, cls) { var e = document.createElement(tag); if (text != null) e.textContent = String(text); if (cls) e.className = cls; return e; }
  function when(ts) { if (!ts) return ''; var d = new Date(ts); return d.toLocaleString(); }
  function table(id, head, rows, numeric) {
    var t = $(id); t.textContent = '';
    var tr = el('tr'); head.forEach(function (h, i) { tr.appendChild(el('th', h, numeric && numeric.indexOf(i) >= 0 ? 'num' : '')); }); t.appendChild(tr);
    if (!rows.length) { var r = el('tr'); var c = el('td', 'Nothing in this period', 'quiet'); c.colSpan = head.length; r.appendChild(c); t.appendChild(r); return; }
    rows.forEach(function (row) {
      var r = el('tr');
      row.forEach(function (v, i) {
        var td = el('td', null, numeric && numeric.indexOf(i) >= 0 ? 'num' : '');
        if (v && v.nodeType) td.appendChild(v); else td.textContent = v == null ? '' : String(v);
        r.appendChild(td);
      });
      t.appendChild(r);
    });
  }
  function api(path) {
    return fetch(path, { headers: { authorization: 'Bearer ' + token } }).then(function (r) {
      if (r.status === 401) { forget(); throw new Error('The token was not accepted.'); }
      if (!r.ok) throw new Error('The server answered ' + r.status + '.');
      return r.json();
    });
  }
  function range() { var q = []; if ($('from').value) q.push('from=' + $('from').value); if ($('to').value) q.push('to=' + $('to').value); return q.length ? '?' + q.join('&') : ''; }

  function render(s) {
    $('where').textContent = 'From ' + s.from + ' to ' + s.to + ' (UTC days) · ' + (s.persistent ? 'stored on disk' : 'in memory only: lost at restart');
    var tiles = $('tiles'); tiles.textContent = '';
    [['Sessions', s.totals.sessions], ['Sessions that called a tool', s.totals.used_sessions], ['Tool calls', s.totals.tool_calls], ['Distinct callers', s.totals.callers], ['Refused', s.totals.rejects], ['Other paths', s.totals.probes]]
      .forEach(function (t) { var d = el('div', null, 'tile'); d.appendChild(el('b', t[1])); d.appendChild(el('span', t[0], 'quiet')); tiles.appendChild(d); });
    table('clients', ['Client', 'User agent', 'Sessions', 'Used', 'Tool calls', 'Callers', 'First seen', 'Last seen'],
      s.clients.map(function (c) { return [c.client, c.ua || '', c.sessions, c.used_sessions, c.tool_calls, c.callers, when(c.first), when(c.last)]; }), [2, 3, 4, 5]);
    table('sessions', ['Session', 'Client', 'Kind', 'Methods', 'Tools', 'Demo', 'Address', 'Started', 'Last', 'Closed'],
      s.sessions.map(function (x) {
        var kind = el('span', x.kind, 'tag ' + (x.kind === 'used' ? 'used' : ''));
        var methods = Object.keys(x.methods).map(function (k) { return k + ' ' + x.methods[k]; }).join(', ');
        return [el('code', x.sid), x.client || '', kind, methods, x.tools.join(', '), x.demo || '', x.ip || x.ip_hash || '', when(x.started), when(x.last), x.closed || ''];
      }));
    table('tools', ['Tool', 'Calls', 'Allow', 'Deny', 'Error', 'Other ok'],
      Object.keys(s.tools).sort(function (a, b) { return s.tools[b].calls - s.tools[a].calls; }).map(function (k) { var t = s.tools[k]; return [k, t.calls, t.allow, t.deny, t.error, t.ok]; }), [1, 2, 3, 4, 5]);
    table('days', ['Day', 'Sessions', 'Used', 'Tool calls', 'Refused', 'Other paths'],
      s.by_day.map(function (d) { return [d.day, d.sessions, d.used_sessions, d.tool_calls, d.rejects, d.probes]; }), [1, 2, 3, 4, 5]);
    table('rejects', ['Refusal', 'Count'], Object.keys(s.rejects).map(function (k) { return [k, s.rejects[k]]; }), [1]);
    table('probes', ['Request', 'Count', 'Last'], s.probes.map(function (p) { return [p.path, p.count, when(p.last)]; }), [1]);
    var raw = $('raw'); raw.textContent = '';
    s.by_day.forEach(function (d, i) {
      var a = el('a', d.day); a.href = '#'; a.onclick = function (ev) { ev.preventDefault(); download(d.day); };
      if (i) raw.appendChild(document.createTextNode(' · '));
      raw.appendChild(a);
    });
  }
  function download(day) {
    fetch('/admin/mcp-audit/raw/' + day, { headers: { authorization: 'Bearer ' + token } }).then(function (r) {
      if (!r.ok) throw new Error(r.status === 404 ? 'No log for ' + day + '.' : 'The server answered ' + r.status + '.');
      return r.blob();
    }).then(function (b) {
      var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'plenipo-mcp-' + day + '.jsonl'; a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    }).catch(function (e) { $('err').textContent = e.message; });
  }
  function load() {
    if (!token) return;
    $('err').textContent = '';
    api('/admin/mcp-audit/summary' + range()).then(function (s) { $('data').hidden = false; render(s); }).catch(function (e) { $('err').textContent = e.message; });
  }
  function show() {
    $('login').hidden = !!token; $('controls').hidden = !token;
    clearInterval(timer);
    if (token) { load(); timer = setInterval(function () { if ($('auto').checked) load(); }, 30000); }
    else { $('data').hidden = true; }
  }
  function forget() { token = ''; try { sessionStorage.removeItem(KEY); } catch (e) {} show(); }
  $('save').onclick = function () { token = $('token').value.trim(); $('token').value = ''; try { sessionStorage.setItem(KEY, token); } catch (e) {} show(); };
  $('token').onkeydown = function (e) { if (e.key === 'Enter') $('save').click(); };
  $('reload').onclick = load; $('forget').onclick = forget;
  $('from').onchange = load; $('to').onchange = load;
  show();
})();
</script>
</body>
</html>`;
}
