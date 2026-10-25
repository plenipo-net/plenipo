/**
 * EUDI TS12 ("Electronic payments SCA implementation with wallet", v1.0.1) alignment: maps a Plenipo
 * mandate onto the `urn:eudi:sca:emandate:1` transaction data type that certified wallets render, and checks
 * that the mandate a relying party enforces is never broader than what the person was shown.
 *
 * TS12 can show validity dates, a payee, a currency, amounts and a free-text purpose. It cannot express the
 * agent key, the action names, several counterparties or the delegation depth. Those are bound by hash
 * (`reference_number` is the SHA-256 of the canonical mandate) and, by default, spelled out in the purpose
 * text, which the verifier recomputes and compares exactly.
 */
import { base64url, canonicalize, fromBase64url, mandateHash } from './encoding.js';
import { hostCovers } from './scope.js';
import { EMANDATE_TX_DATA_TYPE, type Mandate } from './types.js';

/**
 * Payee as shown by TS12 (`urn:eudi:sca:payment:1`, section 4.3.1). Everything shown must follow from what
 * is enforced: `name` equals `id`, `website` (optional) is `https://<id>` for a concrete host, and `logo`
 * is only accepted from the relying party's allow-list.
 */
export interface EmandatePayee {
  name: string;
  /** Plenipo convention: the counterparty host or host pattern, e.g. `rail.example` or `*.rail.example`. */
  id: string;
  logo?: string;
  website?: string;
}

/** The subset of `urn:eudi:sca:payment:1` Plenipo emits and accepts inside an e-mandate. */
export interface EmandatePaymentPayload {
  transaction_id: string;
  date_time?: string;
  payee: EmandatePayee;
  currency: string;
  /** Major units (e.g. 150.5 for 150.50 EUR), as TS12 requires. */
  amount: number;
  amount_estimated?: boolean;
  recurrence?: {
    start_date?: string;
    end_date?: string;
    frequency: string;
    mit_options?: { amount_variable?: boolean; max_amount?: number; total_amount?: number };
  };
}

/** `payload` of a `urn:eudi:sca:emandate:1` transaction data object (TS12 section 4.3.4). */
export interface EmandatePayload {
  transaction_id: string;
  date_time?: string;
  start_date?: string;
  end_date?: string;
  reference_number?: string;
  creditor_id?: string;
  purpose?: string;
  payment_payload?: EmandatePaymentPayload;
}

/** The transaction data object as sent to the wallet, before base64url encoding. */
export interface EmandateTransactionData {
  type: string;
  credential_ids: string[];
  transaction_data_hashes_alg?: string[];
  payload: EmandatePayload;
}

export interface EmandateMappingOptions {
  /**
   * The payee to show. By default a mandate with spending limits and exactly one counterparty shows that
   * counterparty as payee; otherwise no payment details are shown and the limits only appear in the purpose.
   */
  payee?: EmandatePayee;
  /** Builds the purpose text. The verifier must use the same function. Default `describeMandate`. */
  describe?: (mandate: Mandate) => string;
  /** Logo URLs the payee may show; see `EmandateCheckOptions.allowedPayeeLogos`. */
  allowedPayeeLogos?: string[];
}

export interface EmandateCheckOptions {
  /**
   * `exact` (default): the purpose must equal `describe(mandate)`, so actions, counterparties, limits and
   * delegation depth were shown in words. `none`: the purpose is free text, so limits and counterparties
   * must be shown as structured fields (a payment with a payee); actions and depth are then not shown, and
   * the verifier requires an action allow-list and a depth limit (`EmandateVerifyOptions`).
   */
  purposeCheck?: 'exact' | 'none';
  describe?: (mandate: Mandate) => string;
  /**
   * Exact logo URLs a payee may show (e.g. logos the relying party hosts for known counterparties). A logo
   * identifies a payee as strongly as a name, so any other logo is refused. Default none.
   */
  allowedPayeeLogos?: string[];
}

/** A reason why an e-mandate does not support a mandate. */
export interface EmandateViolation {
  /** `shape`: not a valid e-mandate; `binding`: not about this mandate; `display`: the mandate is broader than what was shown. */
  kind: 'shape' | 'binding' | 'display';
  field: string;
  message: string;
}

const TS12_MAX_ID = 36;
const TS12_MAX_REFERENCE = 50;
const TS12_MAX_PURPOSE = 1000;
const CURRENCY_RE = /^[A-Z]{3}$/;
const HOST_PATTERN_RE = /^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$/;
/** RFC 3339 date-time with an explicit offset: a bare date or a local time would be ambiguous. */
const DATE_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;

/** ISO 4217 currencies whose minor unit is not 1/100. Anything else is assumed to have two decimals. */
const MINOR_DIGITS: Record<string, number> = {
  BIF: 0, CLP: 0, DJF: 0, GNF: 0, ISK: 0, JPY: 0, KMF: 0, KRW: 0, PYG: 0, RWF: 0, UGX: 0, UYI: 0, VND: 0,
  VUV: 0, XAF: 0, XOF: 0, XPF: 0, BHD: 3, IQD: 3, JOD: 3, KWD: 3, LYD: 3, OMR: 3, TND: 3, CLF: 4, UYW: 4,
};

/**
 * ISO 4217 exponent of a currency: how many decimals its minor unit has (2 for EUR, 0 for JPY, 3 for KWD).
 * Plenipo amounts and limits are integers in this minor unit, not always cents.
 */
export function currencyMinorDigits(currency: string): number {
  return Object.prototype.hasOwnProperty.call(MINOR_DIGITS, currency) ? MINOR_DIGITS[currency] : 2;
}

/** The currencies whose ISO 4217 exponent is not 2. */
export const NON_DECIMAL_CURRENCY_EXPONENTS: Readonly<Record<string, number>> = Object.freeze({ ...MINOR_DIGITS });

const minorDigits = currencyMinorDigits;

/** Minor units (Plenipo) to a TS12 amount in major units. */
export function toMajorUnits(minor: number, currency: string): number {
  if (!Number.isSafeInteger(minor) || minor < 0) throw new RangeError('amount must be a non-negative integer in minor units');
  return Number(formatMajor(minor, currency));
}

function formatMajor(minor: number, currency: string): string {
  const d = minorDigits(currency);
  if (d === 0) return String(minor);
  const s = String(minor).padStart(d + 1, '0');
  return `${s.slice(0, -d)}.${s.slice(-d)}`;
}

/**
 * A TS12 amount in major units to minor units, exactly. Returns undefined for negative or non-finite numbers,
 * exponent notation, more decimals than the currency has, or results beyond the safe integer range: a value
 * that cannot be converted exactly must not be compared approximately.
 */
export function toMinorUnits(major: unknown, currency: string): number | undefined {
  if (typeof major !== 'number' || !Number.isFinite(major) || major < 0) return undefined;
  const text = String(major);
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m) return undefined;
  const d = minorDigits(currency);
  const frac = m[2] ?? '';
  if (frac.length > d) return undefined;
  const value = Number(m[1] + frac.padEnd(d, '0'));
  return Number.isSafeInteger(value) ? value : undefined;
}

function isoSeconds(t: number): string {
  return new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Parses an RFC 3339 date-time with offset to seconds since epoch (rounded down), rejecting impossible dates. */
export function parseDateTime(value: unknown): number | undefined {
  const ms = parseDateTimeMs(value);
  return ms === undefined ? undefined : Math.floor(ms / 1000);
}

function parseDateTimeMs(value: unknown): number | undefined {
  if (typeof value !== 'string' || value.length > 40) return undefined;
  const m = DATE_TIME_RE.exec(value);
  if (!m) return undefined;
  const [, y, mo, d, h, mi, s] = m;
  const day = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d)));
  if (day.getUTCFullYear() !== Number(y) || day.getUTCMonth() !== Number(mo) - 1 || day.getUTCDate() !== Number(d)) return undefined;
  if (Number(h) > 23 || Number(mi) > 59 || Number(s ?? 0) > 59) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}

function money(minor: number, currency: string): string {
  return `${formatMajor(minor, currency)} ${currency}`;
}

/**
 * The default purpose text: everything the mandate allows, in words, so that what TS12 cannot show as a
 * structured field is still shown. Deterministic, because the verifier recomputes it.
 */
export function describeMandate(m: Mandate): string {
  const parts: string[] = [];
  if (m.principal) {
    parts.push(`On behalf of legal person ${m.principal.euid}${m.principal.role ? ` as ${m.principal.role}` : ''}.`);
  }
  parts.push(`Mandate for an AI agent. Actions: ${m.actions.join(', ')}.`);
  parts.push(`Counterparties: ${m.counterparties ? m.counterparties.join(', ') : 'any'}.`);
  if (m.limits) {
    const l: string[] = [];
    if (m.limits.per_operation !== undefined) l.push(`${money(m.limits.per_operation, m.limits.currency)} per operation`);
    if (m.limits.total !== undefined) l.push(`${money(m.limits.total, m.limits.currency)} in total`);
    parts.push(`Limits: ${l.join(', ')}.`);
  } else {
    parts.push('Limits: none.');
  }
  parts.push(`Valid from ${isoSeconds(m.nbf)} to ${isoSeconds(m.exp)}.`);
  const depth = m.delegation?.max_depth ?? 0;
  parts.push(depth === 0 ? 'Sub-delegation: not allowed.' : `Sub-delegation: up to ${depth} level${depth > 1 ? 's' : ''}.`);
  if (m.purpose) parts.push(`Purpose: ${m.purpose}`);
  return parts.join(' ');
}

/**
 * Maps a Plenipo mandate to a TS12 e-mandate payload. Throws when the mandate cannot be shown faithfully
 * (identifier too long, purpose too long) or when the result would show less than the mandate allows.
 */
export function mandateToEmandate(mandate: Mandate, opts: EmandateMappingOptions = {}): EmandatePayload {
  if (mandate.id.length > TS12_MAX_ID) throw new Error(`mandate id longer than ${TS12_MAX_ID} characters cannot be a TS12 transaction_id`);
  const describe = opts.describe ?? describeMandate;
  const purpose = describe(mandate);
  if (purpose.length === 0 || purpose.length > TS12_MAX_PURPOSE) throw new Error(`the purpose text must be 1 to ${TS12_MAX_PURPOSE} characters`);
  const payload: EmandatePayload = {
    transaction_id: mandate.id,
    start_date: isoSeconds(mandate.nbf),
    end_date: isoSeconds(mandate.exp),
    reference_number: mandateHash(mandate),
    purpose,
  };

  const payee = opts.payee ?? defaultPayee(mandate);
  if (mandate.limits && payee) {
    const l = mandate.limits;
    const perOp = l.per_operation ?? l.total!;
    payload.payment_payload = {
      transaction_id: mandate.id,
      payee,
      currency: l.currency,
      amount: toMajorUnits(perOp, l.currency),
      amount_estimated: true,
      recurrence: {
        start_date: payload.start_date,
        end_date: payload.end_date,
        // The least restrictive TS12 frequency: Plenipo does not limit how often the agent acts.
        frequency: 'INDA',
        mit_options: {
          amount_variable: true,
          ...(l.per_operation !== undefined ? { max_amount: toMajorUnits(l.per_operation, l.currency) } : {}),
          ...(l.total !== undefined ? { total_amount: toMajorUnits(l.total, l.currency) } : {}),
        },
      },
    };
  }

  const problems = emandateViolations(payload, mandate, { describe, allowedPayeeLogos: opts.allowedPayeeLogos });
  if (problems.length) throw new Error(`the e-mandate would not cover the mandate: ${problems.map((p) => p.message).join('; ')}`);
  return payload;
}

function defaultPayee(m: Mandate): EmandatePayee | undefined {
  if (!m.counterparties || m.counterparties.length !== 1) return undefined;
  const host = m.counterparties[0].toLowerCase();
  return { name: host, id: host, ...(host.startsWith('*.') ? {} : { website: `https://${host}` }) };
}

/** Wraps an e-mandate payload as OpenID4VP transaction data, base64url of canonical JSON. */
export function encodeEmandateTransactionData(
  payload: EmandatePayload,
  opts: { credentialId?: string; type?: string } = {},
): string {
  const td: EmandateTransactionData = {
    type: opts.type ?? EMANDATE_TX_DATA_TYPE,
    credential_ids: [opts.credentialId ?? 'sca'],
    transaction_data_hashes_alg: ['sha-256'],
    payload,
  };
  return base64url(canonicalize(td));
}

/** Decodes e-mandate transaction data that was already checked to be canonical; validates the envelope. */
export function emandateEnvelopeProblems(td: Record<string, unknown>): string[] {
  const e: string[] = [];
  for (const k of Object.keys(td)) {
    if (!['type', 'credential_ids', 'transaction_data_hashes_alg', 'payload'].includes(k)) e.push(`unexpected member ${k}`);
  }
  if (!Array.isArray(td.credential_ids) || td.credential_ids.length !== 1 || typeof td.credential_ids[0] !== 'string') {
    e.push('credential_ids must name exactly one credential');
  }
  const algs = td.transaction_data_hashes_alg;
  if (algs !== undefined && (!Array.isArray(algs) || algs.length !== 1 || algs[0] !== 'sha-256')) {
    e.push('transaction_data_hashes_alg must be ["sha-256"]');
  }
  if (typeof td.payload !== 'object' || td.payload === null || Array.isArray(td.payload)) e.push('payload must be an object');
  return e;
}

/** Reads base64url canonical JSON; returns undefined when it is not. */
export function decodeCanonical(td: string): Record<string, unknown> | undefined {
  if (typeof td !== 'string' || !/^[A-Za-z0-9_-]+$/.test(td)) return undefined;
  try {
    const json = fromBase64url(td);
    const parsed = JSON.parse(json);
    if (canonicalize(parsed) !== json || typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function unknownKeys(obj: Record<string, unknown>, allowed: string[], where: string, out: EmandateViolation[]): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      // Fields Plenipo does not enforce (execution date, number of payments, minimum amounts, SEPA creditor,
      // instant transfer...) would show the person a restriction that nobody checks.
      out.push({ kind: 'display', field: `${where}${k}`, message: `${where}${k} is shown to the person but not enforced by Plenipo` });
    }
  }
}

function boundedString(x: unknown, max: number): x is string {
  return typeof x === 'string' && x.length >= 1 && x.length <= max;
}

/**
 * Checks that an e-mandate shown to the person covers `mandate`: it refers to it (transaction_id and
 * reference_number), and every limit, date and payee it shows is at least as wide as what the mandate allows.
 * An empty result means the mandate is not broader than what was approved.
 */
export function emandateViolations(payload: unknown, mandate: Mandate, opts: EmandateCheckOptions = {}): EmandateViolation[] {
  const out: EmandateViolation[] = [];
  const shape = (field: string, message: string) => out.push({ kind: 'shape', field, message });
  const binding = (field: string, message: string) => out.push({ kind: 'binding', field, message });
  const display = (field: string, message: string) => out.push({ kind: 'display', field, message });

  if (!isObject(payload)) {
    shape('payload', 'payload must be an object');
    return out;
  }
  unknownKeys(payload, ['transaction_id', 'date_time', 'start_date', 'end_date', 'reference_number', 'purpose', 'payment_payload'], '', out);

  if (!boundedString(payload.transaction_id, TS12_MAX_ID)) shape('transaction_id', `transaction_id must be a string of 1 to ${TS12_MAX_ID} characters`);
  else if (payload.transaction_id !== mandate.id) binding('transaction_id', 'transaction_id is not the mandate id');
  if (!boundedString(payload.reference_number, TS12_MAX_REFERENCE)) binding('reference_number', 'reference_number must carry the mandate hash');
  else if (payload.reference_number !== mandateHash(mandate)) binding('reference_number', 'reference_number does not match the mandate hash');
  if (payload.date_time !== undefined && parseDateTimeMs(payload.date_time) === undefined) shape('date_time', 'date_time must be a date-time with offset');

  checkWindow(payload.start_date, payload.end_date, mandate, '', out);

  if (payload.purpose !== undefined && (typeof payload.purpose !== 'string' || payload.purpose.length > TS12_MAX_PURPOSE)) {
    shape('purpose', `purpose must be a string of at most ${TS12_MAX_PURPOSE} characters`);
  } else if ((opts.purposeCheck ?? 'exact') === 'exact') {
    const expected = (opts.describe ?? describeMandate)(mandate);
    if (payload.purpose !== expected) display('purpose', 'purpose does not describe the mandate');
  } else if (payload.purpose === undefined && payload.payment_payload === undefined) {
    shape('purpose', 'purpose is required when there is no payment_payload');
  }

  if (payload.payment_payload !== undefined) checkPayment(payload.payment_payload, mandate, out, opts.allowedPayeeLogos ?? []);
  if ((opts.purposeCheck ?? 'exact') === 'none' && payload.payment_payload === undefined) {
    // The free-text purpose binds nothing: limits and counterparties must be shown as payment details, which
    // in turn are refused for a mandate without limits or open to any counterparty (checkPayment).
    display('payment_payload', "with purposeCheck 'none' the limits and the payee must be shown as payment details");
  }
  return out;
}

/** Shown start and end dates must enclose the mandate validity window. */
function checkWindow(start: unknown, end: unknown, mandate: Mandate, where: string, out: EmandateViolation[]): void {
  // Compared in milliseconds, so a fractional second shown is never rounded in the mandate's favour.
  if (start !== undefined) {
    const t = parseDateTimeMs(start);
    if (t === undefined) out.push({ kind: 'shape', field: `${where}start_date`, message: `${where}start_date must be a date-time with offset` });
    else if (mandate.nbf * 1000 < t) out.push({ kind: 'display', field: `${where}start_date`, message: `the mandate starts before the ${where}start_date shown` });
  }
  if (end !== undefined) {
    const t = parseDateTimeMs(end);
    if (t === undefined) out.push({ kind: 'shape', field: `${where}end_date`, message: `${where}end_date must be a date-time with offset` });
    else if (mandate.exp * 1000 > t) out.push({ kind: 'display', field: `${where}end_date`, message: `the mandate ends after the ${where}end_date shown` });
  }
}

function checkPayment(p: unknown, mandate: Mandate, out: EmandateViolation[], allowedLogos: string[]): void {
  const w = 'payment_payload.';
  const shape = (field: string, message: string) => out.push({ kind: 'shape', field: w + field, message });
  const display = (field: string, message: string) => out.push({ kind: 'display', field: w + field, message });
  if (!isObject(p)) {
    shape('', 'payment_payload must be an object');
    return;
  }
  unknownKeys(p, ['transaction_id', 'date_time', 'payee', 'currency', 'amount', 'amount_estimated', 'recurrence'], w, out);
  if (p.transaction_id !== mandate.id) out.push({ kind: 'binding', field: w + 'transaction_id', message: 'payment_payload.transaction_id is not the mandate id' });
  if (p.date_time !== undefined && parseDateTimeMs(p.date_time) === undefined) shape('date_time', 'date_time must be a date-time with offset');
  if (p.amount_estimated !== undefined && typeof p.amount_estimated !== 'boolean') shape('amount_estimated', 'amount_estimated must be a boolean');

  // Payee: a payment display restricts the counterparties to the payee.
  const payee = p.payee;
  if (!isObject(payee) || !boundedString(payee.name, 140) || typeof payee.id !== 'string') {
    shape('payee', 'payee needs a name and an id');
  } else {
    unknownKeys(payee, ['name', 'id', 'logo', 'website'], `${w}payee.`, out);
    for (const k of ['logo', 'website'] as const) if (payee[k] !== undefined && typeof payee[k] !== 'string') shape(`payee.${k}`, `payee.${k} must be a string`);
    const id = payee.id;
    // The name, website and logo are what the person reads; only the id is enforced, so they must follow it.
    if (payee.name !== id) display('payee.name', 'payee.name must be the enforced counterparty (payee.id)');
    if (payee.website !== undefined && (id.startsWith('*.') || payee.website !== `https://${id}`)) {
      display('payee.website', 'payee.website must be https:// followed by the concrete payee host');
    }
    if (payee.logo !== undefined && !allowedLogos.includes(payee.logo as string)) display('payee.logo', 'payee.logo is not on the allow-list');
    if (!HOST_PATTERN_RE.test(id) || id.length > 253) {
      display('payee.id', 'payee.id must be the counterparty host pattern so that it can be enforced');
    } else if (!mandate.counterparties) {
      display('payee', 'the mandate allows any counterparty but one payee was shown');
    } else {
      for (const c of mandate.counterparties) if (!hostCovers(id, c)) display('payee', `counterparty ${c} is not covered by the payee shown`);
    }
  }

  // Currency and amounts: a payment display restricts the currency and the amounts.
  const currency = p.currency;
  if (typeof currency !== 'string' || !CURRENCY_RE.test(currency)) {
    shape('currency', 'currency must be an ISO 4217 code');
    return;
  }
  const limits = mandate.limits;
  if (!limits) display('currency', 'the mandate has no spending limits but amounts were shown');
  else if (limits.currency !== currency) display('currency', `the mandate is in ${limits.currency}, the person saw ${currency}`);

  const amount = toMinorUnits(p.amount, currency);
  if (amount === undefined) {
    shape('amount', 'amount must be a non-negative number with the decimals of its currency');
    return;
  }

  let shownPerOp: number = amount;
  let shownTotal: number = amount; // a single payment, unless a recurrence says otherwise
  const r = p.recurrence;
  if (r !== undefined) {
    if (!isObject(r)) {
      shape('recurrence', 'recurrence must be an object');
      return;
    }
    unknownKeys(r, ['start_date', 'end_date', 'frequency', 'mit_options'], `${w}recurrence.`, out);
    // Plenipo does not limit how often the agent acts, so only the least restrictive frequency is honest.
    if (r.frequency !== 'INDA') display('recurrence.frequency', 'only frequency INDA can be enforced; Plenipo does not limit how often the agent acts');
    checkWindow(r.start_date, r.end_date, mandate, `${w}recurrence.`, out);
    shownTotal = Infinity;
    const mo = r.mit_options;
    if (mo !== undefined) {
      if (!isObject(mo)) {
        shape('recurrence.mit_options', 'mit_options must be an object');
        return;
      }
      unknownKeys(mo, ['amount_variable', 'max_amount', 'total_amount'], `${w}recurrence.mit_options.`, out);
      if (mo.amount_variable !== undefined && typeof mo.amount_variable !== 'boolean') shape('recurrence.mit_options.amount_variable', 'amount_variable must be a boolean');
      if (mo.amount_variable === true) shownPerOp = Infinity;
      if (mo.max_amount !== undefined) {
        const v = toMinorUnits(mo.max_amount, currency);
        if (v === undefined) shape('recurrence.mit_options.max_amount', 'max_amount is not a valid amount');
        else shownPerOp = v;
      }
      if (mo.total_amount !== undefined) {
        const v = toMinorUnits(mo.total_amount, currency);
        if (v === undefined) shape('recurrence.mit_options.total_amount', 'total_amount is not a valid amount');
        else shownTotal = v;
      }
    }
  }
  if (!limits) return;
  // The total also caps every single operation.
  const perOp = Math.min(limits.per_operation ?? Infinity, limits.total ?? Infinity);
  const total = limits.total ?? Infinity;
  if (perOp > shownPerOp) display('amount', `the mandate allows ${perOp === Infinity ? 'unlimited amounts' : money(perOp, currency)} per operation, the person saw ${money(shownPerOp, currency)}`);
  if (total > shownTotal) display('total', `the mandate allows ${total === Infinity ? 'an unlimited total' : money(total, currency)}, the person saw a total of ${money(shownTotal, currency)}`);
}
