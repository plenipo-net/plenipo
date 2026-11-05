/**
 * The audit log of the hosted MCP gateway: who connects, with which client, what they list and call, and
 * what the gateway refused. Registries and directories that list the endpoint probe it (initialize and
 * tools/list, often on a schedule), people connect through Claude and other clients, scanners try other
 * paths; this log tells them apart.
 *
 * One JSON object per line, in a file per UTC day under `dir` (a persistent volume on the hosted sandbox),
 * kept for `retentionDays`; the last events also stay in memory, which is all there is without `dir`.
 * Nothing secret is written: session ids are cut to eight characters, the endpoint's path token never
 * appears, tool arguments are reduced to their names, and client addresses are truncated (IPv4 /24,
 * IPv6 /48) unless `ipMode` says otherwise, with a keyed hash that tells repeat callers apart. The hash
 * key is random and kept in the directory, so it is not derivable from any token.
 *
 * Everything in an event comes from the network, so the log is bounded: strings and lists are clipped,
 * refusals and probes are counted rather than written past a rate, each day's file has a size cap, and
 * reading never holds more than one day's lines and the requested number of events.
 *
 * An optional webhook hears about new clients and about the first tool call of each session.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { appendFile, mkdir, readdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

export type IpMode = 'truncate' | 'full' | 'none';

export type AuditEventType =
  /** A client opened a session: client name and version, protocol version. */
  | 'initialize'
  /** A JSON-RPC request on a session, other than tools/call (tools/list, ping, resources/list...). */
  | 'rpc'
  /** A tool call and its outcome. */
  | 'tool'
  /** A GET (notification stream) or DELETE (end of session) on a session. */
  | 'stream'
  /** The gateway closed a session. */
  | 'session_closed'
  /** A request to the MCP endpoint that the gateway refused (no session, rate limit, full...). */
  | 'reject'
  /** A request to any other path on the gateway host, or to the endpoint without its token. */
  | 'probe'
  /** Refusals and probes over the rate, counted and not written one by one. */
  | 'dropped';

export interface AuditEvent {
  ts: string;
  ev: AuditEventType;
  /** First eight characters of the MCP session id. */
  sid?: string;
  ip?: string;
  ip_hash?: string;
  ua?: string;
  [key: string]: unknown;
}

export interface Caller {
  ip?: string;
  ip_hash?: string;
  ua?: string;
}

export interface McpAuditOptions {
  /** Directory of the daily files. Without it the log lives in memory only. */
  dir?: string;
  /** Days of files to keep (default 90, at least 1). */
  retentionDays?: number;
  /** How client addresses are stored (default `truncate`). */
  ipMode?: IpMode;
  /** Key of the address hash. Default: a random key kept in `dir` (per process without `dir`). */
  hashKey?: string;
  /** POSTed for new clients and first tool calls. */
  webhookUrl?: string;
  /**
   * `json` (default): { text, content, event }, which Slack (text) and Discord (content) webhooks read;
   * `text`: the line alone as text/plain, for ntfy and the like.
   */
  webhookFormat?: 'json' | 'text';
  /** Webhook calls per hour at most, for each of the two kinds (default 30). */
  webhooksPerHour?: number;
  /** Events kept in memory (default 5000). */
  memoryEvents?: number;
  /** Refusals and probes written per minute at most, together (default 300); the rest are counted. */
  noisePerMinute?: number;
  /** Bytes written to one day's file at most (default 20 MB). */
  maxDayBytes?: number;
  log?: (line: string) => void;
  now?: () => number;
}

export interface SessionSummary {
  sid: string;
  client?: string;
  ua?: string;
  ip?: string;
  ip_hash?: string;
  started: string;
  last: string;
  /** `used`: called a tool; `listed`: listed tools without calling one (what a registry check does); `connected`: neither. */
  kind: 'used' | 'listed' | 'connected';
  methods: Record<string, number>;
  tools: string[];
  demo?: string;
  closed?: string;
}

export interface AuditSummary {
  from: string;
  to: string;
  persistent: boolean;
  totals: { sessions: number; used_sessions: number; tool_calls: number; rejects: number; probes: number; dropped: number; callers: number };
  by_day: Array<{ day: string; sessions: number; used_sessions: number; tool_calls: number; rejects: number; probes: number }>;
  clients: Array<{ client: string; ua?: string; sessions: number; used_sessions: number; tool_calls: number; callers: number; first: string; last: string }>;
  tools: Record<string, { calls: number; allow: number; deny: number; error: number; ok: number }>;
  rejects: Record<string, number>;
  probes: Array<{ path: string; count: number; last: string }>;
  sessions: SessionSummary[];
}

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const FILE_RE = /^mcp-(\d{4}-\d{2}-\d{2})\.jsonl$/;
const KEY_FILE = '.hash-key';
const MAX_SPAN_DAYS = 92;
/** Sessions and callers a summary tracks at most: beyond that it counts but does not itemise. */
const MAX_TRACKED = 20_000;

const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const addDays = (day: string, n: number) => dayOf(Date.parse(`${day}T00:00:00Z`) + n * 86_400_000);
/** Maps keyed by what clients send: no prototype to reach through `__proto__`. */
const dict = <T>() => Object.create(null) as Record<string, T>;

/** IPv4 to its /24, IPv6 to its /48; an IPv4-mapped IPv6 address counts as IPv4. */
export function truncateIp(ip: string): string {
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/i.exec(ip);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0`;
  if (ip.includes(':')) {
    const [head] = ip.split('::');
    const groups = head.split(':').filter(Boolean).slice(0, 3);
    return `${groups.join(':')}::/48`;
  }
  return 'unknown';
}

/** Keeps a string printable and short: whatever a client sends is written to disk and shown on a page. */
export function clip(s: unknown, max = 200): string | undefined {
  if (typeof s !== 'string' || !s) return undefined;
  const clean = s.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

/** Bounds an event whatever its fields: strings to 200 characters, lists to 20 short items, one level of objects. */
function bound(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return clip(value) ?? '';
  if (typeof value === 'number' || typeof value === 'boolean' || value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => (typeof v === 'string' ? (clip(v, 60) ?? '') : depth < 1 ? bound(v, depth + 1) : null));
  if (typeof value === 'object' && depth < 2) {
    const out = dict<unknown>();
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, 30)) out[clip(k, 40) ?? '?'] = bound(v, depth + 1);
    return out;
  }
  return null;
}

/** For a chat webhook: no mentions, no markup. */
function defuse(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/@/g, '@​');
}

export class McpAudit {
  private readonly ring: AuditEvent[] = [];
  private readonly memoryEvents: number;
  private readonly retentionDays: number;
  private readonly ipMode: IpMode;
  private hashKey: Buffer;
  private readonly log: (line: string) => void;
  private readonly now: () => number;
  private writing: Promise<void> = Promise.resolve();
  private dirReady = false;
  private fileBroken = false;
  private day = { name: '', bytes: -1, capped: false };
  private noise = { start: 0, n: 0, dropped: 0 };
  /** Client signatures already announced, with the time: a new client is announced again after a day. */
  private readonly announced = new Map<string, number>();
  /** Client name per open session, for the first-tool-call message. */
  private readonly sessionClient = new Map<string, string>();
  private readonly toolSeen = new Set<string>();
  private readonly hooks = { client: { start: 0, n: 0, warned: false }, tool: { start: 0, n: 0, warned: false } };

  constructor(private readonly opts: McpAuditOptions = {}) {
    this.memoryEvents = opts.memoryEvents ?? 5000;
    const r = Number(opts.retentionDays ?? 90);
    this.retentionDays = Number.isFinite(r) && r >= 1 ? Math.floor(r) : 90;
    this.ipMode = opts.ipMode ?? 'truncate';
    this.hashKey = opts.hashKey ? createHash('sha256').update(`plenipo-mcp-audit|${opts.hashKey}`).digest() : randomBytes(32);
    this.log = opts.log ?? (() => {});
    this.now = opts.now ?? Date.now;
  }

  /** Loads the hash key kept in the directory, or creates it, so that hashes match across restarts. */
  async init(): Promise<void> {
    if (this.opts.hashKey || !this.opts.dir) return;
    const file = join(this.opts.dir, KEY_FILE);
    try {
      const hex = (await readFile(file, 'utf8')).trim();
      if (/^[0-9a-f]{64}$/.test(hex)) {
        this.hashKey = Buffer.from(hex, 'hex');
        return;
      }
    } catch {
      // Not there yet.
    }
    try {
      await mkdir(this.opts.dir, { recursive: true });
      await writeFile(file, this.hashKey.toString('hex'), { mode: 0o600 });
    } catch (e) {
      this.log(`audit: cannot keep the hash key in ${this.opts.dir} (${(e as Error).message}); hashes change at restart`);
    }
  }

  /** Whether events are written to disk. */
  get persistent(): boolean {
    return Boolean(this.opts.dir) && !this.fileBroken;
  }

  /** The caller fields of an event, as the log stores them. */
  caller(ip: string | undefined, ua: unknown): Caller {
    const c: Caller = {};
    if (ip && ip !== 'unknown' && this.ipMode !== 'none') {
      c.ip = this.ipMode === 'full' ? clip(ip, 60) : truncateIp(ip);
    }
    if (ip && ip !== 'unknown') c.ip_hash = createHmac('sha256', this.hashKey).update(ip).digest('hex').slice(0, 12);
    const agent = clip(ua);
    if (agent) c.ua = agent;
    return c;
  }

  /** Records an event. Refusals and probes over the rate are counted instead; returns undefined then. */
  record(event: { ev: AuditEventType; [key: string]: unknown }): AuditEvent | undefined {
    const now = this.now();
    if (event.ev === 'reject' || event.ev === 'probe') {
      if (now - this.noise.start >= 60_000) {
        const dropped = this.noise.dropped;
        this.noise = { start: now, n: 0, dropped: 0 };
        if (dropped) this.write({ ts: new Date(now).toISOString(), ev: 'dropped', count: dropped });
      }
      if (++this.noise.n > (this.opts.noisePerMinute ?? 300)) {
        this.noise.dropped++;
        return undefined;
      }
    }
    const e = { ...(bound(event) as object), ts: new Date(now).toISOString() } as AuditEvent;
    e.ev = event.ev;
    this.write(e);
    this.notify(e);
    return e;
  }

  private write(e: AuditEvent): void {
    this.ring.push(e);
    if (this.ring.length > this.memoryEvents) this.ring.splice(0, this.ring.length - this.memoryEvents);
    if (!this.opts.dir || this.fileBroken) return;
    const dir = this.opts.dir;
    const line = `${JSON.stringify(e)}\n`;
    const name = `mcp-${e.ts.slice(0, 10)}.jsonl`;
    this.writing = this.writing
      .then(async () => {
        if (!this.dirReady) {
          await mkdir(dir, { recursive: true });
          this.dirReady = true;
        }
        if (this.day.name !== name) {
          const size = await stat(join(dir, name)).then(
            (s) => s.size,
            () => 0,
          );
          this.day = { name, bytes: size, capped: false };
        }
        const max = this.opts.maxDayBytes ?? 20_000_000;
        if (this.day.bytes + line.length > max) {
          if (!this.day.capped) {
            this.day.capped = true;
            this.log(`audit: ${name} reached ${max} bytes; further events of the day stay in memory only`);
          }
          return;
        }
        this.day.bytes += Buffer.byteLength(line);
        await appendFile(join(dir, name), line);
      })
      .catch((err: Error) => {
        this.fileBroken = true;
        this.log(`audit: cannot write to ${dir} (${err.message}); keeping the log in memory only`);
      });
  }

  /** Waits for the pending writes. */
  async flush(): Promise<void> {
    await this.writing;
  }

  /** Deletes the daily files older than the retention period. */
  async sweep(): Promise<number> {
    if (!this.opts.dir) return 0;
    const oldest = addDays(dayOf(this.now()), -(this.retentionDays - 1));
    let removed = 0;
    let names: string[];
    try {
      names = await readdir(this.opts.dir);
    } catch {
      return 0;
    }
    for (const name of names) {
      const m = FILE_RE.exec(name);
      if (m && m[1] < oldest) {
        await unlink(join(this.opts.dir, name)).catch(() => {});
        removed++;
      }
    }
    if (removed) this.log(`audit: removed ${removed} daily file(s) older than ${oldest}`);
    return removed;
  }

  /** The normalised range of days: `to` defaults to today, `from` to six days before `to`. */
  range(from?: string, to?: string): { from: string; to: string } {
    const today = dayOf(this.now());
    let t = to && DAY_RE.test(to) ? to : today;
    if (t > today) t = today;
    let f = from && DAY_RE.test(from) ? from : addDays(t, -6);
    if (f > t) f = t;
    if (f < addDays(t, -(MAX_SPAN_DAYS - 1))) f = addDays(t, -(MAX_SPAN_DAYS - 1));
    return { from: f, to: t };
  }

  /** Events of a range of days, oldest first, read line by line. */
  async *each(from: string, to: string): AsyncGenerator<AuditEvent> {
    await this.flush();
    if (!this.persistent) {
      for (const e of [...this.ring]) if (e.ts.slice(0, 10) >= from && e.ts.slice(0, 10) <= to) yield e;
      return;
    }
    for (let d = from; d <= to; d = addDays(d, 1)) {
      const file = join(this.opts.dir!, `mcp-${d}.jsonl`);
      const exists = await stat(file).then(
        () => true,
        () => false,
      );
      if (!exists) continue;
      const lines = createInterface({ input: createReadStream(file, 'utf8'), crlfDelay: Infinity });
      for await (const line of lines) {
        if (!line || line.length > 16_384) continue;
        try {
          yield JSON.parse(line) as AuditEvent;
        } catch {
          // A line cut by a crash: skip it.
        }
      }
    }
  }

  /** One day's file as written, or undefined. */
  async raw(day: string): Promise<string | undefined> {
    if (!DAY_RE.test(day)) return undefined;
    await this.flush();
    if (!this.persistent) {
      const lines = this.ring.filter((e) => e.ts.startsWith(day)).map((e) => JSON.stringify(e));
      return lines.length ? `${lines.join('\n')}\n` : undefined;
    }
    return readFile(join(this.opts.dir!, `mcp-${day}.jsonl`), 'utf8').catch(() => undefined);
  }

  /** Events newest first, filtered; only the newest `limit` are held. */
  async events(q: { from?: string; to?: string; ev?: string; sid?: string; limit?: number } = {}) {
    const { from, to } = this.range(q.from, q.to);
    const limit = Math.min(Math.max(Math.trunc(q.limit ?? 500) || 500, 1), 5000);
    const types = q.ev ? new Set(q.ev.split(',')) : undefined;
    const kept: AuditEvent[] = [];
    let total = 0;
    for await (const e of this.each(from, to)) {
      if ((types && !types.has(e.ev)) || (q.sid && e.sid !== q.sid)) continue;
      total++;
      kept.push(e);
      if (kept.length > limit) kept.shift();
    }
    return { from, to, persistent: this.persistent, total, events: kept.reverse() };
  }

  async summary(q: { from?: string; to?: string } = {}): Promise<AuditSummary> {
    const { from, to } = this.range(q.from, q.to);
    const days = new Map<string, AuditSummary['by_day'][number]>();
    for (let d = from; d <= to; d = addDays(d, 1)) days.set(d, { day: d, sessions: 0, used_sessions: 0, tool_calls: 0, rejects: 0, probes: 0 });
    const sessions = new Map<string, SessionSummary>();
    const tools = dict<AuditSummary['tools'][string]>();
    const rejects = dict<number>();
    const probes = new Map<string, { path: string; count: number; last: string }>();
    const callers = new Set<string>();
    let dropped = 0;

    for await (const e of this.each(from, to)) {
      const day = days.get(String(e.ts).slice(0, 10));
      if (typeof e.ip_hash === 'string' && callers.size < MAX_TRACKED) callers.add(e.ip_hash);
      if (e.ev === 'dropped') {
        dropped += Number(e.count) || 0;
        continue;
      }
      if (e.ev === 'reject') {
        if (day) day.rejects++;
        const why = String(e.reason ?? e.status ?? 'unknown');
        rejects[why] = (rejects[why] ?? 0) + 1;
        continue;
      }
      if (e.ev === 'probe') {
        if (day) day.probes++;
        const key = `${String(e.method ?? 'GET')} ${String(e.path ?? '/')}`;
        const p = probes.get(key) ?? (probes.size < MAX_TRACKED ? { path: key, count: 0, last: e.ts } : undefined);
        if (p) {
          p.count++;
          p.last = e.ts;
          probes.set(key, p);
        }
        continue;
      }
      if (typeof e.sid !== 'string') continue;
      let s = sessions.get(e.sid);
      if (!s) {
        if (sessions.size >= MAX_TRACKED) continue;
        s = { sid: e.sid, started: e.ts, last: e.ts, kind: 'connected', methods: dict<number>(), tools: [], ip: e.ip, ip_hash: e.ip_hash, ua: e.ua };
        sessions.set(e.sid, s);
      }
      s.last = e.ts;
      s.ip ??= e.ip;
      s.ip_hash ??= e.ip_hash;
      s.ua ??= e.ua;
      if (typeof e.demo === 'string') s.demo = e.demo;
      if (e.ev === 'initialize') {
        s.started = e.ts;
        s.client = clientLabel(e);
        s.methods.initialize = (s.methods.initialize ?? 0) + 1;
        if (day) day.sessions++;
      } else if (e.ev === 'rpc') {
        const m = String(e.method ?? '?');
        s.methods[m] = (s.methods[m] ?? 0) + 1;
        if (m === 'tools/list' && s.kind === 'connected') s.kind = 'listed';
      } else if (e.ev === 'tool') {
        const name = String(e.tool ?? '?');
        s.methods['tools/call'] = (s.methods['tools/call'] ?? 0) + 1;
        if (!s.tools.includes(name) && s.tools.length < 30) s.tools.push(name);
        if (s.kind !== 'used' && day) day.used_sessions++;
        s.kind = 'used';
        if (day) day.tool_calls++;
        const t = (tools[name] ??= { calls: 0, allow: 0, deny: 0, error: 0, ok: 0 });
        t.calls++;
        const d = String(e.decision ?? '');
        if (d === 'ALLOW') t.allow++;
        else if (d === 'DENY') t.deny++;
        else if (d === 'ERROR' || e.ok === false) t.error++;
        else t.ok++;
      } else if (e.ev === 'session_closed') {
        s.closed = String(e.reason ?? 'closed');
      }
    }

    const clients = new Map<string, AuditSummary['clients'][number] & { hashes: Set<string> }>();
    for (const s of sessions.values()) {
      if (!s.methods.initialize) continue;
      const key = `${s.client ?? '?'}|${s.ua ?? ''}`;
      const c = clients.get(key) ?? { client: s.client ?? '?', ua: s.ua, sessions: 0, used_sessions: 0, tool_calls: 0, callers: 0, first: s.started, last: s.last, hashes: new Set<string>() };
      c.sessions++;
      if (s.kind === 'used') c.used_sessions++;
      c.tool_calls += s.methods['tools/call'] ?? 0;
      if (s.ip_hash) c.hashes.add(s.ip_hash);
      if (s.started < c.first) c.first = s.started;
      if (s.last > c.last) c.last = s.last;
      clients.set(key, c);
    }

    const list = [...sessions.values()].filter((s) => s.methods.initialize || s.tools.length);
    return {
      from,
      to,
      persistent: this.persistent,
      totals: {
        sessions: list.filter((s) => s.methods.initialize).length,
        used_sessions: list.filter((s) => s.kind === 'used').length,
        tool_calls: [...days.values()].reduce((n, d) => n + d.tool_calls, 0),
        rejects: [...days.values()].reduce((n, d) => n + d.rejects, 0),
        probes: [...days.values()].reduce((n, d) => n + d.probes, 0),
        dropped,
        callers: callers.size,
      },
      by_day: [...days.values()].reverse(),
      clients: [...clients.values()]
        .map(({ hashes, ...c }) => ({ ...c, callers: hashes.size }))
        .sort((a, b) => b.last.localeCompare(a.last))
        .slice(0, 500),
      tools,
      rejects,
      probes: [...probes.values()].sort((a, b) => b.count - a.count).slice(0, 50),
      sessions: list.sort((a, b) => b.last.localeCompare(a.last)).slice(0, 200),
    };
  }

  private notify(e: AuditEvent): void {
    if (e.ev === 'session_closed' && e.sid) {
      this.sessionClient.delete(e.sid);
      this.toolSeen.delete(e.sid);
      return;
    }
    let text: string | undefined;
    let kind: 'client' | 'tool' = 'client';
    if (e.ev === 'initialize') {
      const client = clientLabel(e);
      if (e.sid) {
        this.sessionClient.set(e.sid, client);
        if (this.sessionClient.size > 5000) this.sessionClient.delete(this.sessionClient.keys().next().value!);
      }
      const sig = `${client}|${e.ua ?? ''}|${e.ip_hash ?? ''}`;
      const seen = this.announced.get(sig);
      const now = this.now();
      if (seen === undefined || now - seen > 86_400_000) {
        this.announced.set(sig, now);
        if (this.announced.size > 5000) this.announced.delete(this.announced.keys().next().value!);
        text = `Plenipo MCP: new client ${client}${e.ua ? ` (${e.ua})` : ''}${e.ip ? ` from ${e.ip}` : ''}`;
      }
    } else if (e.ev === 'tool' && e.sid && !this.toolSeen.has(e.sid)) {
      this.toolSeen.add(e.sid);
      if (this.toolSeen.size > 5000) this.toolSeen.delete(this.toolSeen.values().next().value!);
      kind = 'tool';
      const client = this.sessionClient.get(e.sid) ?? 'a client';
      text = `Plenipo MCP: ${client} called ${String(e.tool)}${e.decision ? ` (${String(e.decision)}${e.code ? ` ${String(e.code)}` : ''})` : ''}${e.demo ? `, demo code ${String(e.demo)}` : ''}`;
    }
    if (!text || !this.opts.webhookUrl) return;
    // Two budgets: a flood of made-up clients cannot hide the sessions that act.
    const budget = this.hooks[kind];
    const now = this.now();
    if (now - budget.start >= 3_600_000) Object.assign(budget, { start: now, n: 0, warned: false });
    if (++budget.n > (this.opts.webhooksPerHour ?? 30)) {
      if (!budget.warned) this.log(`audit: webhook limit reached this hour for ${kind} messages; events are still logged`);
      budget.warned = true;
      return;
    }
    const plain = this.opts.webhookFormat === 'text';
    const safe = defuse(text);
    void fetch(this.opts.webhookUrl, {
      method: 'POST',
      headers: plain ? { 'content-type': 'text/plain; charset=utf-8', title: 'Plenipo MCP' } : { 'content-type': 'application/json' },
      body: plain ? text.replace(/@/g, '@​') : JSON.stringify({ text: safe, content: safe, allowed_mentions: { parse: [] }, event: e }),
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    }).catch((err: Error) => this.log(`audit: webhook failed (${err.message})`));
  }
}

function clientLabel(e: AuditEvent): string {
  const c = e.client as { name?: unknown; version?: unknown } | undefined;
  if (!c || typeof c.name !== 'string' || !c.name) return 'unnamed client';
  return typeof c.version === 'string' && c.version ? `${c.name} ${c.version}` : c.name;
}
