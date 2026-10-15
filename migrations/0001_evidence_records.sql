-- Bayora Enclave evidence sink.
--
-- The Referee writes the *exact bytes* it also appends to the NDJSON log, so
-- the two sinks can be differenced: the Independent Verifier can be pointed at
-- either, and `--postgres-url` lets it compare them record by record. Storing
-- the serialized evidence (rather than columns) is deliberate -- the bytes are
-- what the signature covers, and any normalisation here would be a place for
-- the two sinks to disagree.
--
-- Apply with:
--   psql "$DATABASE_URL" -f migrations/0001_evidence_records.sql

BEGIN;

CREATE TABLE IF NOT EXISTS evidence_records (
    id           BIGSERIAL   PRIMARY KEY,
    record_bytes BYTEA       NOT NULL,
    -- The insert time is *not* part of the evidence; it exists only so an
    -- operator can find an incident window. The Referee never reads it.
    inserted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The verifier reads the whole table in insertion order and diffs it against a
-- log file, so the only ordering guarantee it needs is on the primary key.
-- This index is here for operators paging through a large table.

CREATE INDEX IF NOT EXISTS evidence_records_inserted_at_idx
    ON evidence_records (inserted_at);

-- Append-only enforcement: the Referee role may INSERT and SELECT, never
-- UPDATE or DELETE. Evidence that can be edited by the process that produced
-- it is not evidence.
--
--   CREATE ROLE bayora_referee LOGIN PASSWORD '...';
--   GRANT INSERT, SELECT ON evidence_records TO bayora_referee;
--   REVOKE UPDATE, DELETE, TRUNCATE ON evidence_records FROM bayora_referee;
--
-- Run the Referee with `--postgres-url postgres://bayora_referee:...@host/db`.

COMMIT;
