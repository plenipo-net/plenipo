/**
 * Every service keeps an append-only log of what it decided and serves it at GET /events?since=N.
 * The dashboard polls these logs over HTTP, the same way an operator's monitoring would.
 */
import type { Request } from './http.js';

export type EventSource = 'pid' | 'wallet' | 'platform' | 'bank' | 'agent';

export interface SandboxEvent {
  seq: number;
  ts: string;
  source: EventSource;
  type: string;
  [field: string]: unknown;
}

const MAX_EVENTS = 5000;

export class EventLog {
  private readonly events: SandboxEvent[] = [];
  private seq = 0;
  private readonly listeners = new Set<(e: SandboxEvent) => void>();

  constructor(private readonly source: EventSource) {}

  append(type: string, data: Record<string, unknown> = {}): SandboxEvent {
    const e: SandboxEvent = { ...data, seq: ++this.seq, ts: new Date().toISOString(), source: this.source, type };
    this.events.push(e);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
    for (const l of this.listeners) l(e);
    return e;
  }

  since(seq: number, limit = 500): SandboxEvent[] {
    return this.events.filter((e) => e.seq > seq).slice(0, limit);
  }

  all(): SandboxEvent[] {
    return [...this.events];
  }

  subscribe(l: (e: SandboxEvent) => void): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }
}

export function eventsHandler(log: EventLog) {
  return (req: Request) => {
    const since = Number(req.query.get('since') ?? '0');
    return log.since(Number.isSafeInteger(since) && since >= 0 ? since : 0);
  };
}
