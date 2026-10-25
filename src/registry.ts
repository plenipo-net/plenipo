import { randomUUID } from 'node:crypto';
import type { Amount } from './types.js';

/** Answers whether a mandate has been revoked. Revoking a mandate denies everything delegated from it. */
export interface RevocationRegistry {
  isRevoked(mandateId: string): boolean | Promise<boolean>;
}

/** One mandate of the chain, as seen by the ledger. */
export interface LedgerEntry {
  /** Stable key of the mandate: its hash, so ids chosen by delegators cannot collide. */
  key: string;
  /** The mandate's total limit in minor units, when it has one. */
  total?: number;
}

/**
 * Tracks spending under each mandate, for `limits.total`.
 * `reserve` must be atomic: it checks every total in the chain and, only if all fit,
 * adds the amount to every entry as pending. Concurrent invocations then cannot overspend.
 */
export interface SpendingLedger {
  /** Committed plus pending spending under a mandate key, in minor units of `currency`. */
  spent(key: string, currency: string): number | Promise<number>;
  /** Returns a reservation id, or null when the amount would exceed a total. */
  reserve(entries: LedgerEntry[], amount: Amount): string | null | Promise<string | null>;
  /** Makes a reservation permanent, after the action succeeded. */
  commit(reservationId: string): void | Promise<void>;
  /** Cancels a reservation, after the action failed or was not performed. */
  release(reservationId: string): void | Promise<void>;
}

/** Single-use nonces, to prevent replay of invocations. */
export interface NonceStore {
  /**
   * Returns true the first time a nonce is consumed, false afterwards.
   * A relying party that issues nonces can also return false for nonces it never issued.
   */
  consume(nonce: string): boolean | Promise<boolean>;
  /**
   * How long a consumed nonce is remembered, in seconds, when the store forgets them. Lets a verifier
   * check that the store covers its acceptance window. Absent means unknown.
   */
  readonly retentionSeconds?: number;
}

export class InMemoryRevocationRegistry implements RevocationRegistry {
  private readonly revoked = new Set<string>();
  revoke(mandateId: string): void {
    this.revoked.add(mandateId);
  }
  isRevoked(mandateId: string): boolean {
    return this.revoked.has(mandateId);
  }
}

/**
 * In-memory ledger for development and tests. `reserve` runs synchronously, so it is atomic
 * within one Node.js process. Production needs a shared store with the same guarantee.
 */
export class InMemorySpendingLedger implements SpendingLedger {
  private readonly totals = new Map<string, number>();
  private readonly pending = new Map<string, { keys: string[]; amount: Amount }>();

  private k(key: string, currency: string): string {
    return JSON.stringify([key, currency]);
  }

  spent(key: string, currency: string): number {
    return this.totals.get(this.k(key, currency)) ?? 0;
  }

  reserve(entries: LedgerEntry[], amount: Amount): string | null {
    for (const e of entries) {
      if (e.total !== undefined && this.spent(e.key, amount.currency) + amount.value > e.total) return null;
    }
    for (const e of entries) {
      const k = this.k(e.key, amount.currency);
      this.totals.set(k, (this.totals.get(k) ?? 0) + amount.value);
    }
    const id = randomUUID();
    this.pending.set(id, { keys: entries.map((e) => e.key), amount });
    return id;
  }

  commit(reservationId: string): void {
    this.pending.delete(reservationId);
  }

  release(reservationId: string): void {
    const r = this.pending.get(reservationId);
    if (!r) return;
    this.pending.delete(reservationId);
    for (const key of r.keys) {
      const k = this.k(key, r.amount.currency);
      this.totals.set(k, (this.totals.get(k) ?? 0) - r.amount.value);
    }
  }
}

export class InMemoryNonceStore implements NonceStore {
  /** Never forgets, for the life of the process. */
  readonly retentionSeconds = Infinity;
  private readonly seen = new Set<string>();
  consume(nonce: string): boolean {
    if (typeof nonce !== 'string') return false;
    if (this.seen.has(nonce)) return false;
    this.seen.add(nonce);
    return true;
  }
}
