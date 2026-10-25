/**
 * Throwaway database engines for the store tests: a Postgres cluster in a temp directory and a
 * redis-server without persistence, each on a random port of 127.0.0.1. When an engine cannot start,
 * the caller gets a reason to skip instead of an error.
 *
 * PLENIPO_TEST_PG_URL / PLENIPO_TEST_REDIS_URL point the tests at existing servers instead; the
 * tests then use random table prefixes and key prefixes and leave the servers running.
 * PLENIPO_SKIP_ENGINES=1 skips every engine test, e.g. on a machine where they cannot run.
 */
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { chownSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { createServer, createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type Engine = { ok: true; url: string; stop(): Promise<void>; restart?(): Promise<void> } | { ok: false; reason: string };

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => (typeof addr === 'object' && addr ? resolve(addr.port) : reject(new Error('no port'))));
    });
  });
}

function findPgBin(): string | undefined {
  const fromEnv = process.env.PLENIPO_PG_BINDIR;
  if (fromEnv && existsSync(join(fromEnv, 'pg_ctl'))) return fromEnv;
  try {
    const dir = execFileSync('pg_config', ['--bindir'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (existsSync(join(dir, 'pg_ctl')) && existsSync(join(dir, 'initdb'))) return dir;
  } catch {
    /* not on PATH */
  }
  const base = '/usr/lib/postgresql';
  if (existsSync(base)) {
    const versions = readdirSync(base)
      .filter((v) => existsSync(join(base, v, 'bin', 'pg_ctl')) && existsSync(join(base, v, 'bin', 'initdb')))
      .sort((a, b) => Number(b) - Number(a));
    if (versions.length) return join(base, versions[0], 'bin');
  }
  for (const dir of (process.env.PATH ?? '').split(':')) {
    if (dir && existsSync(join(dir, 'pg_ctl')) && existsSync(join(dir, 'initdb'))) return dir;
  }
  return undefined;
}

function userIds(name: string): { uid: number; gid: number } | undefined {
  try {
    const uid = Number(execFileSync('id', ['-u', name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim());
    const gid = Number(execFileSync('id', ['-g', name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim());
    return Number.isInteger(uid) && Number.isInteger(gid) ? { uid, gid } : undefined;
  } catch {
    return undefined;
  }
}

/** Postgres refuses to run as root, so as root the cluster runs as the `postgres` system user. */
export async function startPostgres(): Promise<Engine> {
  if (process.env.PLENIPO_SKIP_ENGINES) return { ok: false, reason: 'PLENIPO_SKIP_ENGINES is set' };
  if (process.env.PLENIPO_TEST_PG_URL) {
    return { ok: true, url: process.env.PLENIPO_TEST_PG_URL, stop: async () => {} };
  }
  const bin = findPgBin();
  if (!bin) return { ok: false, reason: 'no Postgres server binaries found (set PLENIPO_PG_BINDIR or PLENIPO_TEST_PG_URL)' };
  let wrap: (cmd: string, args: string[]) => [string, string[]] = (cmd, args) => [cmd, args];
  let owner: { uid: number; gid: number } | undefined;
  if (process.getuid?.() === 0) {
    owner = userIds('postgres');
    if (!owner || !existsSync('/usr/sbin/runuser')) return { ok: false, reason: 'running as root and no postgres user to run the cluster as' };
    wrap = (cmd, args) => ['/usr/sbin/runuser', ['-u', 'postgres', '--', cmd, ...args]];
  }
  const dir = mkdtempSync(join(tmpdir(), 'plenipo-pg-'));
  if (owner) chownSync(dir, owner.uid, owner.gid);
  const data = join(dir, 'data');
  const port = await freePort();
  const run = (cmd: string, args: string[]) => {
    const [c, a] = wrap(join(bin, cmd), args);
    execFileSync(c, a, { stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 });
  };
  const opts = `-p ${port} -k ${dir} -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=200`;
  const start = () => run('pg_ctl', ['-D', data, '-o', opts, '-l', join(dir, 'log'), '-w', '-t', '60', 'start']);
  const stopSync = () => {
    try {
      run('pg_ctl', ['-D', data, '-m', 'immediate', '-w', 'stop']);
    } catch {
      /* already stopped */
    }
  };
  try {
    run('initdb', ['-D', data, '-A', 'trust', '-U', 'plenipo', '-E', 'UTF8', '--no-sync']);
    start();
  } catch (e) {
    stopSync();
    rmSync(dir, { recursive: true, force: true });
    return { ok: false, reason: `Postgres could not start: ${(e as Error).message.split('\n')[0]}` };
  }
  let stopped = false;
  const onExit = () => {
    if (!stopped) stopSync();
  };
  process.once('exit', onExit);
  return {
    ok: true,
    url: `postgres://plenipo@127.0.0.1:${port}/postgres`,
    async restart() {
      run('pg_ctl', ['-D', data, '-m', 'fast', '-w', 'stop']);
      start();
    },
    async stop() {
      stopped = true;
      process.removeListener('exit', onExit);
      stopSync();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function waitForPort(port: number, child: ChildProcess, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`redis-server exited with ${child.exitCode}`);
    const ok = await new Promise<boolean>((resolve) => {
      const s = createConnection({ port, host: '127.0.0.1' }, () => {
        s.end();
        resolve(true);
      });
      s.on('error', () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('redis-server did not open its port');
}

function findRedisServer(): string | undefined {
  if (process.env.PLENIPO_REDIS_SERVER && existsSync(process.env.PLENIPO_REDIS_SERVER)) return process.env.PLENIPO_REDIS_SERVER;
  for (const dir of [...(process.env.PATH ?? '').split(':'), '/usr/bin', '/usr/local/bin']) {
    if (dir && existsSync(join(dir, 'redis-server'))) return join(dir, 'redis-server');
  }
  return undefined;
}

export async function startRedis(): Promise<Engine> {
  if (process.env.PLENIPO_SKIP_ENGINES) return { ok: false, reason: 'PLENIPO_SKIP_ENGINES is set' };
  if (process.env.PLENIPO_TEST_REDIS_URL) {
    return { ok: true, url: process.env.PLENIPO_TEST_REDIS_URL, stop: async () => {} };
  }
  const bin = findRedisServer();
  if (!bin) return { ok: false, reason: 'redis-server not found (set PLENIPO_REDIS_SERVER or PLENIPO_TEST_REDIS_URL)' };
  const dir = mkdtempSync(join(tmpdir(), 'plenipo-redis-'));
  const port = await freePort();
  const child = spawn(
    bin,
    ['--port', String(port), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--dir', dir, '--daemonize', 'no', '--loglevel', 'warning'],
    { stdio: 'ignore' },
  );
  const onExit = () => child.kill('SIGKILL');
  process.once('exit', onExit);
  try {
    await waitForPort(port, child);
  } catch (e) {
    child.kill('SIGKILL');
    process.removeListener('exit', onExit);
    rmSync(dir, { recursive: true, force: true });
    return { ok: false, reason: `redis-server could not start: ${(e as Error).message}` };
  }
  return {
    ok: true,
    url: `redis://127.0.0.1:${port}`,
    async stop() {
      process.removeListener('exit', onExit);
      if (child.exitCode === null) {
        const exited = new Promise((r) => child.once('exit', r));
        child.kill('SIGTERM');
        await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
        if (child.exitCode === null) child.kill('SIGKILL');
      }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
