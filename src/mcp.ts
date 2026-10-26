import { argsHash } from './invocation.js';
import { DEFAULT_MAX_REPLAY_BYTES, type AttemptOutcome } from './idempotency.js';
import { verifyAuthorization, type VerifyOptions } from './verify.js';
import type { Amount, Decision, MandateChain } from './types.js';

/** Key under which a client puts the authorization in the MCP request `_meta`. */
export const META_KEY = 'plenipo/authorization';

/**
 * Key under which a tool handler states, in its result `_meta`, whether the action ran: `executed`,
 * `not-executed` or `unknown`. The guard settles the reservation from it and strips it from the result.
 */
export const OUTCOME_META_KEY = 'plenipo/outcome';

export type ToolOutcome = 'executed' | 'not-executed' | 'unknown';

/**
 * Key set to `true` in the `_meta` of a result that is the stored answer of an earlier attempt with the same
 * idempotency key, returned instead of running the tool again.
 */
export const REPLAY_META_KEY = 'plenipo/replay';

export interface PlenipoMeta {
  chain: MandateChain;
  invocation: string;
}

export interface GuardOptions<Args> extends Omit<VerifyOptions, 'expected' | 'now'> {
  /** Current time in seconds, or a clock read at every call. Default: the system clock at every call. */
  now?: number | (() => number);
  /** The concrete action this tool performs, e.g. `travel.book`. */
  action: string;
  /**
   * Reads the counterparty from the tool arguments, or `null` when this tool has none. Required: the
   * signed invocation is only compared with what the call really does, never trusted on its own. When the
   * function returns undefined or an empty string the call is refused; with `null`, an invocation that
   * declares a counterparty is refused.
   */
  counterparty: ((args: Args) => string | undefined) | null;
  /** Reads the amount from the tool arguments, or `null` when the tool moves no money. Same rules as `counterparty`. */
  amount: ((args: Args) => Amount | undefined) | null;
  /**
   * Called with every decision, for audit logs. If it throws, the call is refused and any reservation is
   * released: an action whose authorization could not be recorded does not run.
   */
  onDecision?: (decision: Decision, args: Args) => void;
  /**
   * Largest result kept for idempotent replays, in bytes of its JSON text. Default 65536. A larger result
   * is not kept: a retry then learns that the call already executed, without its result. `0` keeps none.
   * Stored results live in the idempotency store; keep personal data out of tool results you would not store.
   */
  maxReplayBytes?: number;
}

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean; _meta?: Record<string, unknown>; [k: string]: unknown };
type Extra = { _meta?: Record<string, unknown> } & Record<string, unknown>;
type AllowDecision = Extract<Decision, { decision: 'ALLOW' }>;
/** The wrapped tool. It receives the verified decision: principal, path of authority and the exact invocation. */
type Handler<Args> = (args: Args, extra: Extra, decision: AllowDecision) => ToolResult | Promise<ToolResult>;

function denied(code: string, reason: string): ToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: `plenipo: DENY ${code}: ${reason}` }],
    structuredContent: { plenipo: { decision: 'DENY', code, reason } },
  };
}

/** The stored result of an earlier attempt, or a plain notice when none was kept. */
function replayed(replay: { result?: string } | undefined): ToolResult {
  if (replay?.result !== undefined) {
    try {
      const r = JSON.parse(replay.result) as ToolResult;
      if (r && typeof r === 'object' && Array.isArray(r.content)) return { ...r, _meta: { ...(r._meta ?? {}), [REPLAY_META_KEY]: true } };
    } catch {
      /* not a stored tool result: fall through */
    }
  }
  return denied('ALREADY_EXECUTED', 'an earlier attempt with this idempotency key already executed; its result was not kept');
}

function storedResult(result: ToolResult, max: number): string | undefined {
  if (max <= 0) return undefined;
  try {
    const text = JSON.stringify(result);
    return text !== undefined && Buffer.byteLength(text, 'utf8') <= max ? text : undefined;
  } catch {
    return undefined;
  }
}

const ATTEMPT_OUTCOME: Record<ToolOutcome, AttemptOutcome> = { executed: 'executed', 'not-executed': 'not_executed', unknown: 'unknown' };

function validAmount(a: unknown): a is Amount {
  if (typeof a !== 'object' || a === null) return false;
  const x = a as Record<string, unknown>;
  return typeof x.value === 'number' && Number.isSafeInteger(x.value) && x.value >= 0 && typeof x.currency === 'string' && /^[A-Z]{3}$/.test(x.currency);
}

class Unmapped extends Error {}

/** What the call really does, read from its arguments. Throws Unmapped when it cannot be read. */
function deriveExpected<Args>(opts: Pick<GuardOptions<Args>, 'action' | 'counterparty' | 'amount'>, args: Args): NonNullable<VerifyOptions['expected']> {
  const expected: NonNullable<VerifyOptions['expected']> = { action: opts.action, args };
  if (opts.counterparty === null) expected.counterparty = null;
  if (opts.amount === null) expected.amount = null;
  try {
    if (opts.counterparty) {
      const c = opts.counterparty(args);
      if (typeof c !== 'string' || c.length === 0) throw new Unmapped('the tool could not read the counterparty from its arguments');
      expected.counterparty = c;
    }
    if (opts.amount) {
      const a = opts.amount(args);
      if (!validAmount(a)) throw new Unmapped('the tool could not read a valid amount from its arguments');
      expected.amount = { value: a.value, currency: a.currency };
    }
  } catch (e) {
    if (e instanceof Unmapped) throw e;
    throw new Unmapped('the tool could not read its arguments');
  }
  return expected;
}

/**
 * Wraps an MCP tool handler so that it runs only when the caller presents a valid mandate chain
 * and an invocation that matches this exact call: action, counterparty, amount and arguments.
 * Spending reserved against total limits is settled from the outcome the handler states in
 * `_meta['plenipo/outcome']`: committed when `executed`, released when `not-executed`, left pending when
 * `unknown`. Without a stated outcome a success commits and an `isError` result stays pending, because an
 * error reported after the action ran must not give the amount back. A throw also leaves it pending.
 *
 * With an idempotency store in the options, an invocation that carries `idem` runs at most once per key: a
 * retry of an executed call gets that call's stored result (marked with `_meta['plenipo/replay']`), and a
 * retry while the first outcome is unknown is refused until the service reconciles it.
 */
export function guardTool<Args>(handler: Handler<Args>, opts: GuardOptions<Args>): (args: Args, extra: Extra) => Promise<ToolResult> {
  const { action, counterparty, amount, onDecision, now: clock, maxReplayBytes, ...verifyOpts } = opts;
  // Fail at wiring time: a guard that forgot to say how it reads the counterparty or amount would
  // otherwise trust whatever the agent declares.
  if (counterparty === undefined || amount === undefined) {
    throw new Error('guardTool needs counterparty and amount: an extractor, or null when the tool has none');
  }
  if ((counterparty !== null && typeof counterparty !== 'function') || (amount !== null && typeof amount !== 'function')) {
    throw new Error('guardTool counterparty and amount must be functions or null');
  }
  const maxReplay = maxReplayBytes ?? DEFAULT_MAX_REPLAY_BYTES;
  if (!Number.isSafeInteger(maxReplay) || maxReplay < 0) throw new Error('guardTool maxReplayBytes must be a non-negative integer');
  const ledger = verifyOpts.ledger;
  const store = verifyOpts.idempotency;
  /** Ends the attempt holding the idempotency key. A store that fails leaves it in progress, then unresolved: safe side. */
  const finish = async (decision: Decision, outcome: AttemptOutcome, result?: string) => {
    if (decision.decision !== 'ALLOW' || !decision.idempotency || !store) return;
    try {
      await store.finish(decision.idempotency.key, decision.idempotency.attempt, outcome, result);
    } catch {
      /* see above */
    }
  };
  /** Before the handler runs, the action certainly has not happened: give back the reservation and the key. */
  const abandon = async (decision: Decision) => {
    const reservation = decision.decision === 'ALLOW' ? decision.reservation : undefined;
    if (reservation && ledger) await ledger.release(reservation);
    await finish(decision, 'not_executed');
  };
  return async (args, extra) => {
    const meta = (extra?._meta ?? {})[META_KEY] as PlenipoMeta | undefined;
    if (!meta?.chain || typeof meta.invocation !== 'string') {
      return denied('MALFORMED', `missing ${META_KEY} in request _meta`);
    }

    let expected: NonNullable<VerifyOptions['expected']>;
    try {
      expected = deriveExpected({ action, counterparty, amount }, args);
    } catch (e) {
      return denied('INVOCATION_MISMATCH', (e as Error).message);
    }

    const now = typeof clock === 'function' ? clock() : clock;
    const decision = await verifyAuthorization(meta.chain, meta.invocation, { ...verifyOpts, ...(now !== undefined ? { now } : {}), expected });
    const reservation = decision.decision === 'ALLOW' ? decision.reservation : undefined;
    try {
      onDecision?.(decision, args);
    } catch {
      await abandon(decision);
      return denied('INTERNAL', 'the decision could not be recorded');
    }
    if (decision.decision === 'DENY') {
      // A retry of a call that already ran gets the stored answer of that call, and the tool does not run.
      if (decision.code === 'ALREADY_EXECUTED') return replayed(decision.replay);
      return denied(decision.code, decision.reason);
    }

    // A tool without a counterparty or amount must not run an invocation that names one: the mandate
    // would have been checked against a value the call does not carry.
    if ((counterparty === null && decision.invocation.counterparty !== undefined) || (amount === null && decision.invocation.amount !== undefined)) {
      await abandon(decision);
      return denied('INVOCATION_MISMATCH', 'invocation declares a counterparty or amount that this tool does not carry');
    }

    // Settlement: release only when the tool states the action certainly did not run. A pending reservation
    // counts as spent in a shared ledger's sweep until it is reconciled, so limits fail safe. A throw is an
    // unknown outcome and leaves the reservation pending.
    // The idempotency key follows the same rule: a throw is an unknown outcome and blocks the key until
    // reconciled, so a retry cannot run the action a second time.
    let raw: ToolResult;
    try {
      raw = await handler(args, extra, decision);
    } catch (e) {
      await finish(decision, 'unknown');
      throw e;
    }
    const { result, outcome } = takeOutcome(raw);
    await finish(decision, ATTEMPT_OUTCOME[outcome], outcome === 'executed' ? storedResult(result, maxReplay) : undefined);
    if (reservation && ledger) {
      if (outcome === 'executed') await ledger.commit(reservation);
      else if (outcome === 'not-executed') await ledger.release(reservation);
    }
    return result;
  };
}

/**
 * Reads and removes the stated outcome. A value other than the three defined ones counts as `unknown`;
 * without one, a success counts as executed and an error result as unknown.
 */
function takeOutcome(raw: ToolResult): { result: ToolResult; outcome: ToolOutcome } {
  const meta = raw && typeof raw === 'object' ? raw._meta : undefined;
  if (!meta || typeof meta !== 'object' || !(OUTCOME_META_KEY in meta)) {
    return { result: raw, outcome: raw?.isError ? 'unknown' : 'executed' };
  }
  const stated = meta[OUTCOME_META_KEY];
  const outcome: ToolOutcome = stated === 'executed' || stated === 'not-executed' ? stated : 'unknown';
  const { [OUTCOME_META_KEY]: _, ...rest } = meta;
  const result: ToolResult = { ...raw };
  if (Object.keys(rest).length) result._meta = rest;
  else delete result._meta;
  return { result, outcome };
}

export { argsHash };
