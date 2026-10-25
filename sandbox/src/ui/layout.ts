/** Shared page shell and styles for the sandbox web pages. No external assets: everything is inline. */
import { escapeHtml } from '../http.js';

export const BASE_CSS = `
:root{
  --bg:#f6f4ef;--panel:#ffffff;--ink:#1b2430;--muted:#5d6878;--line:#e3dfd6;--soft:#efece5;
  --allow:#0f7b5a;--allow-bg:#e3f4ec;--deny:#b42335;--deny-bg:#fbe7ea;--warn:#9a6200;--warn-bg:#fdf1db;
  --accent:#23408e;--pid:#475569;--wallet:#4338ca;--platform:#b45309;--bank:#0f766e;--agent:#7c3aed;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme: dark){:root{
  --bg:#12161c;--panel:#1a2029;--ink:#e7ebf0;--muted:#9aa5b4;--line:#2a323d;--soft:#212833;
  --allow:#4fd1a1;--allow-bg:#123428;--deny:#ff7a8a;--deny-bg:#3a1820;--warn:#f6c25b;--warn-bg:#3a2c10;
  --accent:#8fb0ff;--pid:#a3b1c4;--wallet:#a5a1ff;--platform:#f2b25c;--bank:#5fd4c4;--agent:#c4a5ff;
}}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 var(--sans)}
a{color:var(--accent)}
header.top{display:flex;align-items:center;gap:14px;padding:14px 24px;border-bottom:1px solid var(--line);background:var(--panel)}
header.top .chip{width:12px;height:12px;border-radius:3px;background:var(--svc,var(--accent))}
header.top h1{font-size:17px;margin:0;font-weight:650;letter-spacing:.2px}
header.top .sub{color:var(--muted);font-size:13px}
header.top nav{margin-left:auto;display:flex;gap:14px;font-size:13px}
main{max-width:1100px;margin:0 auto;padding:24px}
.grid{display:grid;gap:16px}
.cols-2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.card h2{font-size:15px;margin:0 0 10px;font-weight:650}
.card h3{font-size:13px;margin:14px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;font-weight:600}
.muted{color:var(--muted)}
.mono{font-family:var(--mono);font-size:12.5px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:650;letter-spacing:.3px;border:1px solid transparent}
.b-allow{background:var(--allow-bg);color:var(--allow)}
.b-deny{background:var(--deny-bg);color:var(--deny)}
.b-warn{background:var(--warn-bg);color:var(--warn)}
.b-neutral{background:var(--soft);color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
button,.btn{font:inherit;font-size:14px;padding:8px 16px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer;text-decoration:none;display:inline-block}
button.primary,.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{border-color:var(--deny);color:var(--deny)}
button.small{padding:3px 10px;font-size:12.5px}
input,select,textarea{font:inherit;padding:7px 9px;border-radius:7px;border:1px solid var(--line);background:var(--bg);color:var(--ink);width:100%}
label{font-size:13px;color:var(--muted);display:block;margin:8px 0 3px}
dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}
dl.kv dt{color:var(--muted);font-size:13px}
dl.kv dd{margin:0}
ul.plain{list-style:none;padding:0;margin:0}
ul.plain li{padding:4px 0}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.notice{padding:10px 14px;border-radius:8px;background:var(--warn-bg);color:var(--warn);font-size:13.5px}
.ok{padding:10px 14px;border-radius:8px;background:var(--allow-bg);color:var(--allow)}
.err{padding:10px 14px;border-radius:8px;background:var(--deny-bg);color:var(--deny)}
code{font-family:var(--mono);font-size:12.5px;background:var(--soft);padding:1px 5px;border-radius:4px;word-break:break-all}
`;

export const SERVICE_COLORS: Record<string, string> = {
  pid: 'var(--pid)',
  wallet: 'var(--wallet)',
  platform: 'var(--platform)',
  bank: 'var(--bank)',
  dashboard: 'var(--accent)',
};

export function page(opts: {
  title: string;
  service: keyof typeof SERVICE_COLORS;
  subtitle?: string;
  body: string;
  nav?: Array<[string, string]>;
  head?: string;
}): string {
  const nav = (opts.nav ?? []).map(([label, href]) => `<a href="${escapeHtml(href)}">${escapeHtml(label)}</a>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(opts.title)}</title><style>${BASE_CSS}</style>${opts.head ?? ''}</head>
<body style="--svc:${SERVICE_COLORS[opts.service]}">
<header class="top"><span class="chip"></span><div><h1>${escapeHtml(opts.title)}</h1>${
    opts.subtitle ? `<div class="sub">${escapeHtml(opts.subtitle)}</div>` : ''
  }</div><nav>${nav}</nav></header>
<main>${opts.body}</main></body></html>`;
}

/** Reloads the page every few seconds, except while the person is typing in a form. */
export function autoRefresh(seconds: number): string {
  return `<script>setInterval(function(){var a=document.activeElement;if(!a||['INPUT','SELECT','TEXTAREA'].indexOf(a.tagName)<0)location.reload()},${seconds * 1000})</script>`;
}
