CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS protocol_slices (
    protocol_name VARCHAR,
    field_name VARCHAR,
    byte_offset_start INTEGER,
    byte_offset_end INTEGER,
    bit_mask VARCHAR,
    field_type VARCHAR,
    endianness VARCHAR,
    discriminant_role VARCHAR,
    description VARCHAR,
    enum_mappings_json VARCHAR,
    content_hash VARCHAR,
    indexed_at_utc VARCHAR,
    PRIMARY KEY (protocol_name, field_name)
);

CREATE TABLE IF NOT EXISTS protocol_signatures (
    hex_prefix VARCHAR PRIMARY KEY,
    protocol_name VARCHAR,
    message_type VARCHAR,
    slice_rule VARCHAR,
    confidence VARCHAR
);

CREATE TABLE IF NOT EXISTS protocol_ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    protocol_name VARCHAR,
    field_count INTEGER,
    detail VARCHAR
);
