/** The stdio bridge's state: one JSON file, readable only by its owner, holding the agent's private key. */
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { BridgeState, BridgeStateStore } from './core.js';

export class FileStateStore implements BridgeStateStore {
  constructor(readonly path: string) {}

  async load(): Promise<BridgeState> {
    if (!existsSync(this.path)) return {};
    try {
      return JSON.parse(readFileSync(this.path, 'utf8')) as BridgeState;
    } catch {
      throw new Error(`the bridge state file ${this.path} is not valid JSON: delete it to start over`);
    }
  }

  async save(state: BridgeState): Promise<void> {
    writeFileSync(this.path, JSON.stringify(state, null, 2), { mode: 0o600 });
    // writeFileSync keeps the mode of an existing file; make sure it is private either way.
    chmodSync(this.path, 0o600);
  }
}
