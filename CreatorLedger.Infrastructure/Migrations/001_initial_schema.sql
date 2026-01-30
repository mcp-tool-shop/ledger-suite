-- Migration: 001_initial_schema
-- CreatorLedger initial database schema
-- DO NOT MODIFY after deployment - create new migration instead

-- ============================================================================
-- CREATORS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS creators (
    id TEXT PRIMARY KEY,                    -- Guid "D" format
    public_key TEXT NOT NULL,               -- ed25519:base64 format
    display_name TEXT NULL,
    created_at_utc TEXT NOT NULL            -- ISO 8601 "O" format
);

-- Prevent duplicate public keys (one identity per key)
CREATE UNIQUE INDEX IF NOT EXISTS idx_creators_public_key ON creators(public_key);

-- ============================================================================
-- LEDGER_EVENTS TABLE (append-only)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ledger_events (
    id TEXT PRIMARY KEY,                    -- EventId Guid "D" format
    seq INTEGER NOT NULL UNIQUE,            -- Monotonic order (NOT AUTOINCREMENT - we control it)
    event_type TEXT NOT NULL,               -- e.g., "creator_created", "asset_attested"
    occurred_at_utc TEXT NOT NULL,          -- ISO 8601 "O" format
    previous_event_hash TEXT NOT NULL,      -- Hex (64 chars), Digest256.Zero for genesis
    event_hash TEXT NOT NULL,               -- Hex (64 chars), computed on insert
    asset_id TEXT NULL,                     -- Denormalized for index (NULL for non-asset events)
    payload_json TEXT NOT NULL,             -- Canonical JSON (what was signed/hashed)
    signature_base64 TEXT NULL,             -- Ed25519 signature (NULL for system events)
    creator_id TEXT NULL,                   -- Who created this event (NULL for system events)
    creator_public_key TEXT NULL,           -- ed25519:base64 (for self-contained verification)
    schema_version TEXT NOT NULL            -- e.g., "event.v1"
);

-- Fast lookup: events for a specific asset, ordered by sequence
CREATE INDEX IF NOT EXISTS idx_ledger_events_asset_seq ON ledger_events(asset_id, seq);

-- Fast lookup: ordered iteration over all events
CREATE INDEX IF NOT EXISTS idx_ledger_events_seq ON ledger_events(seq);

-- Fast lookup: find event by hash (for chain verification)
CREATE INDEX IF NOT EXISTS idx_ledger_events_hash ON ledger_events(event_hash);

-- ============================================================================
-- APPEND-ONLY ENFORCEMENT (triggers)
-- ============================================================================

-- Block UPDATE on ledger_events
CREATE TRIGGER IF NOT EXISTS trg_ledger_events_no_update
BEFORE UPDATE ON ledger_events
BEGIN
    SELECT RAISE(ABORT, 'ledger_events is append-only: UPDATE not allowed');
END;

-- Block DELETE on ledger_events
CREATE TRIGGER IF NOT EXISTS trg_ledger_events_no_delete
BEFORE DELETE ON ledger_events
BEGIN
    SELECT RAISE(ABORT, 'ledger_events is append-only: DELETE not allowed');
END;

-- ============================================================================
-- SCHEMA MIGRATIONS TABLE (tracks applied migrations)
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,            -- Migration number (e.g., 1, 2, 3)
    name TEXT NOT NULL,                     -- Migration filename
    applied_at_utc TEXT NOT NULL            -- When migration was applied
);
