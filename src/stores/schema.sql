-- Plenipo shared stores, schema version 3.
CREATE TABLE IF NOT EXISTS plenipo_schema_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
);

INSERT INTO plenipo_schema_meta (id, version) VALUES (1, 3) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS plenipo_ledger (
  mandate_key TEXT COLLATE "C" NOT NULL CHECK (length(mandate_key) BETWEEN 1 AND 256),
  currency TEXT COLLATE "C" NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  committed BIGINT NOT NULL DEFAULT 0 CHECK (committed >= 0),
  pending BIGINT NOT NULL DEFAULT 0 CHECK (pending >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (mandate_key, currency)
);

CREATE TABLE IF NOT EXISTS plenipo_reservations (
  id UUID PRIMARY KEY,
  mandate_keys TEXT[] NOT NULL,
  currency TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  amount BIGINT NOT NULL CHECK (amount >= 0),
  state TEXT NOT NULL CONSTRAINT plenipo_reservations_state_check
    CHECK (state IN ('pending', 'committed', 'released', 'expired_spent', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  settled_at TIMESTAMPTZ,
  released_by TEXT CHECK (released_by IN ('release', 'reconcile')),
  corrected_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS plenipo_reservations_pending_idx ON plenipo_reservations (expires_at) WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS plenipo_reservations_settled_idx ON plenipo_reservations (settled_at) WHERE state <> 'pending';

CREATE INDEX IF NOT EXISTS plenipo_reservations_unresolved_idx ON plenipo_reservations (settled_at) WHERE state = 'expired_spent';

CREATE OR REPLACE FUNCTION plenipo_schema_upgrade() RETURNS VOID LANGUAGE plpgsql AS $plenipo$
BEGIN
  IF (SELECT version FROM plenipo_schema_meta WHERE id = 1) < 2 THEN
    ALTER TABLE plenipo_reservations DROP CONSTRAINT IF EXISTS plenipo_reservations_state_check;
    ALTER TABLE plenipo_reservations ADD CONSTRAINT plenipo_reservations_state_check
      CHECK (state IN ('pending', 'committed', 'released', 'expired_spent', 'expired'));
    UPDATE plenipo_schema_meta SET version = 2 WHERE id = 1;
  END IF;
  -- Version 2 to 3: who released a reservation, and when a release was corrected by a later commit.
  IF (SELECT version FROM plenipo_schema_meta WHERE id = 1) < 3 THEN
    ALTER TABLE plenipo_reservations ADD COLUMN IF NOT EXISTS released_by TEXT CHECK (released_by IN ('release', 'reconcile'));
    ALTER TABLE plenipo_reservations ADD COLUMN IF NOT EXISTS corrected_at TIMESTAMPTZ;
    UPDATE plenipo_schema_meta SET version = 3 WHERE id = 1;
  END IF;
END
$plenipo$;

SELECT plenipo_schema_upgrade();

CREATE TABLE IF NOT EXISTS plenipo_nonces (
  namespace TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (namespace, nonce_hash)
);

CREATE INDEX IF NOT EXISTS plenipo_nonces_expiry_idx ON plenipo_nonces (expires_at);

CREATE TABLE IF NOT EXISTS plenipo_revocations (
  mandate_id TEXT PRIMARY KEY CHECK (length(mandate_id) BETWEEN 1 AND 1024),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason TEXT CHECK (reason IS NULL OR length(reason) <= 1024)
);

CREATE TABLE IF NOT EXISTS plenipo_request_sessions (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 512),
  data TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS plenipo_request_sessions_expiry_idx ON plenipo_request_sessions (expires_at);

CREATE OR REPLACE FUNCTION plenipo_ledger_reserve(
  p_id UUID, p_keys TEXT[], p_totals BIGINT[], p_currency TEXT, p_amount BIGINT, p_ttl_seconds DOUBLE PRECISION
) RETURNS BOOLEAN LANGUAGE plpgsql AS $plenipo$
DECLARE
  k TEXT;
  r RECORD;
  n INTEGER;
BEGIN
  IF p_amount IS NULL OR p_amount < 0 THEN RAISE EXCEPTION 'plenipo: invalid amount'; END IF;
  n := coalesce(array_length(p_keys, 1), 0);
  IF n = 0 OR n <> coalesce(array_length(p_totals, 1), 0) THEN RAISE EXCEPTION 'plenipo: invalid ledger entries'; END IF;
  IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 THEN RAISE EXCEPTION 'plenipo: invalid ttl'; END IF;
  FOR k IN SELECT DISTINCT u COLLATE "C" AS u FROM unnest(p_keys) AS u ORDER BY 1 LOOP
    INSERT INTO plenipo_ledger (mandate_key, currency) VALUES (k, p_currency) ON CONFLICT DO NOTHING;
  END LOOP;
  FOR r IN
    SELECT l.committed, l.pending, e.total
      FROM plenipo_ledger l
      JOIN unnest(p_keys, p_totals) AS e(k, total) ON l.mandate_key = e.k
     WHERE l.currency = p_currency
     ORDER BY l.mandate_key COLLATE "C"
       FOR UPDATE OF l
  LOOP
    IF r.total IS NOT NULL AND r.committed + r.pending + p_amount > r.total THEN
      RETURN FALSE;
    END IF;
  END LOOP;
  UPDATE plenipo_ledger SET pending = pending + p_amount, updated_at = now()
   WHERE currency = p_currency AND mandate_key = ANY (p_keys);
  INSERT INTO plenipo_reservations (id, mandate_keys, currency, amount, state, expires_at)
  VALUES (p_id, p_keys, p_currency, p_amount, 'pending', now() + make_interval(secs => p_ttl_seconds));
  RETURN TRUE;
END
$plenipo$;

CREATE OR REPLACE FUNCTION plenipo_ledger_settle(p_id UUID, p_action TEXT) RETURNS TEXT LANGUAGE plpgsql AS $plenipo$
DECLARE
  r RECORD;
  d_pending BIGINT := 0;
  d_committed BIGINT := 0;
  target TEXT;
  corrected BOOLEAN := FALSE;
BEGIN
  IF p_action NOT IN ('commit', 'release', 'not_executed') THEN RAISE EXCEPTION 'plenipo: invalid action'; END IF;
  SELECT * INTO r FROM plenipo_reservations WHERE id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN 'unknown'; END IF;
  IF p_action = 'commit' AND r.state = 'pending' THEN
    d_pending := -r.amount; d_committed := r.amount; target := 'committed';
  ELSIF p_action = 'commit' AND r.state = 'expired_spent' THEN
    target := 'committed';
  ELSIF p_action = 'commit' AND r.state = 'expired' THEN
    d_committed := r.amount; target := 'committed';
  ELSIF p_action = 'commit' AND r.state = 'released' THEN
    d_committed := r.amount; target := 'committed'; corrected := TRUE;
  ELSIF p_action IN ('release', 'not_executed') AND r.state = 'pending' THEN
    d_pending := -r.amount; target := 'released';
  ELSIF p_action = 'not_executed' AND r.state = 'expired_spent' THEN
    d_committed := -r.amount; target := 'released';
  ELSIF p_action = 'not_executed' AND r.state = 'expired' THEN
    target := 'released';
  ELSE
    RETURN r.state;
  END IF;
  IF d_pending <> 0 OR d_committed <> 0 THEN
    PERFORM 1 FROM plenipo_ledger
      WHERE currency = r.currency AND mandate_key = ANY (r.mandate_keys)
      ORDER BY mandate_key COLLATE "C" FOR UPDATE;
    UPDATE plenipo_ledger SET pending = pending + d_pending, committed = committed + d_committed, updated_at = now()
     WHERE currency = r.currency AND mandate_key = ANY (r.mandate_keys);
  END IF;
  UPDATE plenipo_reservations
     SET state = target,
         settled_at = now(),
         released_by = CASE WHEN target = 'released'
                            THEN CASE WHEN p_action = 'release' THEN 'release' ELSE 'reconcile' END
                            ELSE released_by END,
         corrected_at = CASE WHEN corrected THEN now() ELSE corrected_at END
   WHERE id = p_id;
  RETURN target;
END
$plenipo$;

CREATE OR REPLACE FUNCTION plenipo_ledger_expire(p_limit INTEGER) RETURNS INTEGER LANGUAGE plpgsql AS $plenipo$
DECLARE
  cnt INTEGER;
  ks TEXT[];
  cs TEXT[];
  ts BIGINT[];
BEGIN
  WITH stale AS (
    SELECT id FROM plenipo_reservations
     WHERE state = 'pending' AND expires_at <= now()
     ORDER BY expires_at
     LIMIT p_limit
       FOR UPDATE SKIP LOCKED
  ), done AS (
    UPDATE plenipo_reservations t SET state = 'expired_spent', settled_at = now()
      FROM stale WHERE t.id = stale.id
    RETURNING t.mandate_keys, t.currency, t.amount
  ), per_key AS (
    SELECT k COLLATE "C" AS k, d.currency, sum(d.amount)::bigint AS total
      FROM done d, unnest(d.mandate_keys) AS k
     GROUP BY 1, 2
  )
  SELECT (SELECT count(*) FROM done),
         array_agg(k ORDER BY k, currency),
         array_agg(currency ORDER BY k, currency),
         array_agg(total ORDER BY k, currency)
    INTO cnt, ks, cs, ts
    FROM per_key;
  FOR i IN 1 .. coalesce(array_length(ks, 1), 0) LOOP
    UPDATE plenipo_ledger SET pending = pending - ts[i], committed = committed + ts[i], updated_at = now()
     WHERE mandate_key = ks[i] AND currency = cs[i];
  END LOOP;
  RETURN cnt;
END
$plenipo$;
