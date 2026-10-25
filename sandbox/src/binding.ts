/**
 * How a tool call maps to a Plenipo invocation. The bank publishes this in each tool's `_meta`, so any
 * agent can sign the right action, counterparty and amount without knowing the bank in advance.
 * It is a sandbox convention, not part of Plenipo: the guard checks the invocation against the call
 * whatever the agent believed, so a wrong binding only leads to a DENY.
 *
 * `counterparty: null` and `amount: null` mean the operation has no counterparty or moves no money (a
 * balance read, blocking a card): the invocation then carries neither, and the bank declares the same
 * to the verifier, so payee restrictions and spending limits do not apply and nothing is reserved.
 */
import type { Amount } from 'plenipo';

export const BINDING_META_KEY = 'plenipo/binding';

export interface ToolBinding {
  action: string;
  audience: string;
  counterparty: { arg: string } | { value: string } | null;
  amount: { arg: string; currency: string } | null;
}

export interface BoundCall {
  action: string;
  /** The counterparty read from the arguments; `null` when the tool has none, undefined when it cannot be read. */
  counterparty: string | null | undefined;
  /** The amount read from the arguments; `null` when the tool moves no money, undefined when it cannot be read. */
  amount: Amount | null | undefined;
}

export function bindCall(binding: ToolBinding, args: Record<string, unknown>): BoundCall {
  let counterparty: string | null | undefined = null;
  if (binding.counterparty) {
    const c = 'arg' in binding.counterparty ? args[binding.counterparty.arg] : binding.counterparty.value;
    counterparty = typeof c === 'string' && c.length > 0 ? c : undefined;
  }
  let amount: Amount | null | undefined = null;
  if (binding.amount) {
    const v = args[binding.amount.arg];
    amount = typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? { value: v, currency: binding.amount.currency } : undefined;
  }
  return { action: binding.action, counterparty, amount };
}

export function isToolBinding(x: unknown): x is ToolBinding {
  if (typeof x !== 'object' || x === null) return false;
  const b = x as Record<string, unknown>;
  const objOrNull = (v: unknown) => v === null || (typeof v === 'object' && v !== undefined);
  return typeof b.action === 'string' && typeof b.audience === 'string' && objOrNull(b.counterparty) && objOrNull(b.amount);
}

/** The invocation fields for a bound call: absent when the tool has none. */
export function invocationFields(call: BoundCall): { action: string; counterparty?: string; amount?: Amount } {
  return {
    action: call.action,
    ...(typeof call.counterparty === 'string' ? { counterparty: call.counterparty } : {}),
    ...(call.amount ? { amount: call.amount } : {}),
  };
}
