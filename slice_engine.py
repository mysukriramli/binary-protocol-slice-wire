import os
import json
import hashlib
from datetime import datetime, timezone
import duckdb

DB_FILE = "data/binary_slices.db"
HISTORY_DIR = "ledger"
DATA_DIR = "data"
EXPORT_DIR = "public"
API_DIR = os.path.join(EXPORT_DIR, "v1")
PROTO_DIR = os.path.join(API_DIR, "protocols")
SIGS_DIR = os.path.join(API_DIR, "signatures")
DELTAS_DIR = os.path.join(API_DIR, "deltas")

CANONICAL_PROTOCOLS = {
    "dns": {
        "title": "Domain Name System (DNS) Header",
        "reference": "RFC 1035",
        "fixed_header_bytes": 12,
        "fields": [
            {
                "field_name": "transaction_id",
                "byte_offset_start": 0,
                "byte_offset_end": 2,
                "bit_mask": "0xFFFF",
                "field_type": "uint16",
                "endianness": "big",
                "discriminant_role": "correlation_id",
                "description": "Identifier assigned by program generating query to match replies.",
                "enums": {}
            },
            {
                "field_name": "flags_qr",
                "byte_offset_start": 2,
                "byte_offset_end": 3,
                "bit_mask": "0x80",
                "field_type": "bit",
                "endianness": "big",
                "discriminant_role": "message_direction",
                "description": "Query (0) or Response (1).",
                "enums": {"0": "QUERY", "1": "RESPONSE"}
            },
            {
                "field_name": "flags_opcode",
                "byte_offset_start": 2,
                "byte_offset_end": 3,
                "bit_mask": "0x78",
                "field_type": "uint4",
                "endianness": "big",
                "discriminant_role": "operation_discriminant",
                "description": "Kind of query in this message.",
                "enums": {"0": "STANDARD_QUERY", "1": "INVERSE_QUERY", "2": "SERVER_STATUS"}
            },
            {
                "field_name": "flags_rcode",
                "byte_offset_start": 3,
                "byte_offset_end": 4,
                "bit_mask": "0x0F",
                "field_type": "uint4",
                "endianness": "big",
                "discriminant_role": "status_code",
                "description": "Response code.",
                "enums": {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED"}
            },
            {
                "field_name": "qdcount",
                "byte_offset_start": 4,
                "byte_offset_end": 6,
                "bit_mask": "0xFFFF",
                "field_type": "uint16",
                "endianness": "big",
                "discriminant_role": "count",
                "description": "Number of entries in question section.",
                "enums": {}
            },
            {
                "field_name": "ancount",
                "byte_offset_start": 6,
                "byte_offset_end": 8,
                "bit_mask": "0xFFFF",
                "field_type": "uint16",
                "endianness": "big",
                "discriminant_role": "count",
                "description": "Number of resource records in answer section.",
                "enums": {}
            }
        ],
        "state_machine": {
            "initial": "HEADER",
            "transitions": [
                {"from": "HEADER", "to": "QUESTION", "condition": "qdcount > 0"},
                {"from": "QUESTION", "to": "ANSWER", "condition": "ancount > 0"},
                {"from": "ANSWER", "to": "DONE", "condition": "payload_exhausted"}
            ]
        },
        "fixtures": [
            {"hex": "103201000001000000000000", "expected": {"transaction_id": 4146, "flags_qr": 0, "flags_opcode": 0, "qdcount": 1, "ancount": 0}},
            {"hex": "103281800001000100000000", "expected": {"transaction_id": 4146, "flags_qr": 1, "flags_rcode": 0, "qdcount": 1, "ancount": 1}}
        ]
    },
    "mqtt": {
        "title": "MQTT Fixed Header",
        "reference": "OASIS MQTT v3.1.1 / v5.0",
        "fixed_header_bytes": 2,
        "fields": [
            {
                "field_name": "packet_type",
                "byte_offset_start": 0,
                "byte_offset_end": 1,
                "bit_mask": "0xF0",
                "field_type": "uint4",
                "endianness": "big",
                "discriminant_role": "control_packet_type",
                "description": "Control packet type.",
                "enums": {
                    "1": "CONNECT", "2": "CONNACK", "3": "PUBLISH", "4": "PUBACK",
                    "8": "SUBSCRIBE", "9": "SUBACK", "12": "PINGREQ", "14": "DISCONNECT"
                }
            },
            {
                "field_name": "flags",
                "byte_offset_start": 0,
                "byte_offset_end": 1,
                "bit_mask": "0x0F",
                "field_type": "uint4",
                "endianness": "big",
                "discriminant_role": "flags",
                "description": "Packet-specific flags (e.g. DUP, QoS, RETAIN for PUBLISH).",
                "enums": {}
            },
            {
                "field_name": "remaining_length",
                "byte_offset_start": 1,
                "byte_offset_end": 2,
                "bit_mask": "0x7F",
                "field_type": "variable_byte_int",
                "endianness": "little",
                "discriminant_role": "payload_length",
                "description": "Length of remaining payload bytes (continuation bit in 0x80).",
                "enums": {}
            }
        ],
        "state_machine": {
            "initial": "FIXED_HEADER",
            "transitions": [
                {"from": "FIXED_HEADER", "to": "VARIABLE_HEADER", "condition": "remaining_length > 0"},
                {"from": "VARIABLE_HEADER", "to": "PAYLOAD", "condition": "type in [CONNECT, PUBLISH, SUBSCRIBE]"}
            ]
        },
        "fixtures": [
            {"hex": "1012", "expected": {"packet_type": 1, "remaining_length": 18}},
            {"hex": "300a", "expected": {"packet_type": 3, "remaining_length": 10}},
            {"hex": "c000", "expected": {"packet_type": 12, "remaining_length": 0}}
        ]
    },
    "tls_record": {
        "title": "TLS Record Layer Outer Envelope",
        "reference": "RFC 5246 / RFC 8446",
        "fixed_header_bytes": 5,
        "fields": [
            {
                "field_name": "content_type",
                "byte_offset_start": 0,
                "byte_offset_end": 1,
                "bit_mask": "0xFF",
                "field_type": "uint8",
                "endianness": "big",
                "discriminant_role": "protocol_envelope_discriminant",
                "description": "Record layer content type.",
                "enums": {"20": "CHANGE_CIPHER_SPEC", "21": "ALERT", "22": "HANDSHAKE", "23": "APPLICATION_DATA"}
            },
            {
                "field_name": "legacy_version",
                "byte_offset_start": 1,
                "byte_offset_end": 3,
                "bit_mask": "0xFFFF",
                "field_type": "uint16",
                "endianness": "big",
                "discriminant_role": "version",
                "description": "Legacy TLS wire version field.",
                "enums": {"0x0301": "TLS_1_0", "0x0302": "TLS_1_1", "0x0303": "TLS_1_2_OR_1_3"}
            },
            {
                "field_name": "length",
                "byte_offset_start": 3,
                "byte_offset_end": 5,
                "bit_mask": "0xFFFF",
                "field_type": "uint16",
                "endianness": "big",
                "discriminant_role": "payload_length",
                "description": "Length in bytes of following TLS fragment.",
                "enums": {}
            }
        ],
        "state_machine": {
            "initial": "RECORD_HEADER",
            "transitions": [
                {"from": "RECORD_HEADER", "to": "HANDSHAKE_FRAGMENT", "condition": "content_type == 22"},
                {"from": "RECORD_HEADER", "to": "ENCRYPTED_DATA", "condition": "content_type == 23"}
            ]
        },
        "fixtures": [
            {"hex": "1603010040", "expected": {"content_type": 22, "legacy_version": "0x0301", "length": 64}},
            {"hex": "1703030100", "expected": {"content_type": 23, "legacy_version": "0x0303", "length": 256}}
        ]
    },
    "dhcp": {
        "title": "Dynamic Host Configuration Protocol (DHCP)",
        "reference": "RFC 2131",
        "fixed_header_bytes": 240,
        "fields": [
            {
                "field_name": "op",
                "byte_offset_start": 0,
                "byte_offset_end": 1,
                "bit_mask": "0xFF",
                "field_type": "uint8",
                "endianness": "big",
                "discriminant_role": "operation",
                "description": "Message op code / message type.",
                "enums": {"1": "BOOTREQUEST", "2": "BOOTREPLY"}
            },
            {
                "field_name": "xid",
                "byte_offset_start": 4,
                "byte_offset_end": 8,
                "bit_mask": "0xFFFFFFFF",
                "field_type": "uint32",
                "endianness": "big",
                "discriminant_role": "correlation_id",
                "description": "Transaction ID randomly chosen by client.",
                "enums": {}
            },
            {
                "field_name": "magic_cookie",
                "byte_offset_start": 236,
                "byte_offset_end": 240,
                "bit_mask": "0xFFFFFFFF",
                "field_type": "uint32",
                "endianness": "big",
                "discriminant_role": "magic_discriminant",
                "description": "DHCP Options Magic Cookie (0x63825363).",
                "enums": {"0x63825363": "DHCP_MAGIC_VALID"}
            }
        ],
        "state_machine": {
            "initial": "BASE_FRAME",
            "transitions": [
                {"from": "BASE_FRAME", "to": "OPTIONS_PARSE", "condition": "magic_cookie == 0x63825363"},
                {"from": "OPTIONS_PARSE", "to": "DONE", "condition": "option_code == 255"}
            ]
        },
        "fixtures": [
            {"hex": "010106003903f326" + ("00" * 228) + "63825363", "expected": {"op": 1, "magic_cookie": "0x63825363"}}
        ]
    }
}

KNOWN_SIGNATURES = [
    {"hex_prefix": "160301", "protocol_name": "tls_record", "message_type": "TLS_HANDSHAKE_CLIENT_HELLO", "slice_rule": "byte 0 == 0x16 && bytes 1..2 == 0x0301", "confidence": "HIGH"},
    {"hex_prefix": "160303", "protocol_name": "tls_record", "message_type": "TLS_RECORD_STANDARD", "slice_rule": "byte 0 == 0x16 && bytes 1..2 == 0x0303", "confidence": "HIGH"},
    {"hex_prefix": "170303", "protocol_name": "tls_record", "message_type": "TLS_APPLICATION_DATA", "slice_rule": "byte 0 == 0x17 && bytes 1..2 == 0x0303", "confidence": "HIGH"},
    {"hex_prefix": "10", "protocol_name": "mqtt", "message_type": "MQTT_CONNECT", "slice_rule": "byte 0 >> 4 == 1", "confidence": "MEDIUM"},
    {"hex_prefix": "c0", "protocol_name": "mqtt", "message_type": "MQTT_PINGREQ", "slice_rule": "byte 0 == 0xC0", "confidence": "HIGH"}
]

def compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def run():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(PROTO_DIR, exist_ok=True)
    os.makedirs(SIGS_DIR, exist_ok=True)
    os.makedirs(DELTAS_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)

    conn = duckdb.connect(DB_FILE)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.execute(f.read())

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")

    conn.execute("BEGIN TRANSACTION")

    ledger_records = []
    protocol_index = []

    for proto_name, proto_data in CANONICAL_PROTOCOLS.items():
        proto_sub_dir = os.path.join(PROTO_DIR, proto_name)
        os.makedirs(proto_sub_dir, exist_ok=True)

        fields = proto_data["fields"]
        for f in fields:
            f_name = f["field_name"]
            b_start = f["byte_offset_start"]
            b_end = f["byte_offset_end"]
            mask = f["bit_mask"]
            f_type = f["field_type"]
            endian = f["endianness"]
            role = f["discriminant_role"]
            desc = f["description"].replace("'", "''")
            enums_json = json.dumps(f["enums"])

            h_str = f"{proto_name}:{f_name}:{b_start}:{b_end}:{mask}:{f_type}:{enums_json}"
            content_hash = compute_sha256(h_str)

            conn.execute(f"""
                INSERT OR REPLACE INTO protocol_slices (
                    protocol_name, field_name, byte_offset_start, byte_offset_end,
                    bit_mask, field_type, endianness, discriminant_role,
                    description, enum_mappings_json, content_hash, indexed_at_utc
                ) VALUES (
                    '{proto_name}', '{f_name}', {b_start}, {b_end},
                    '{mask}', '{f_type}', '{endian}', '{role}',
                    '{desc}', '{enums_json.replace("'", "''")}', '{content_hash}', '{now_iso}'
                )
            """)

        commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
        conn.execute(f"""
            INSERT INTO protocol_ledger (commit_id, timestamp_utc, operation, protocol_name, field_count, detail)
            VALUES ({commit_id}, '{now_iso}', 'REGISTER_SLICE', '{proto_name}', {len(fields)}, '{proto_data['title']}')
        """)

        ledger_records.append({
            "commit_id": commit_id,
            "timestamp_utc": now_iso,
            "operation": "REGISTER_SLICE",
            "protocol_name": proto_name,
            "field_count": len(fields)
        })

        protocol_index.append({
            "protocol": proto_name,
            "title": proto_data["title"],
            "reference": proto_data["reference"],
            "fixed_header_bytes": proto_data["fixed_header_bytes"],
            "fields_count": len(fields),
            "schema_url": f"v1/protocols/{proto_name}/schema.json",
            "state_machine_url": f"v1/protocols/{proto_name}/state-machine.json"
        })

        with open(os.path.join(proto_sub_dir, "schema.json"), "w", encoding="utf-8") as f_out:
            json.dump({
                "protocol": proto_name,
                "title": proto_data["title"],
                "reference": proto_data["reference"],
                "fixed_header_bytes": proto_data["fixed_header_bytes"],
                "fields": fields
            }, f_out, indent=2)

        with open(os.path.join(proto_sub_dir, "state-machine.json"), "w", encoding="utf-8") as f_out:
            json.dump(proto_data["state_machine"], f_out, indent=2)

        with open(os.path.join(proto_sub_dir, "fixtures.jsonl"), "w", encoding="utf-8") as f_out:
            for fix in proto_data["fixtures"]:
                f_out.write(json.dumps(fix) + "\n")

    for sig in KNOWN_SIGNATURES:
        conn.execute(f"""
            INSERT OR REPLACE INTO protocol_signatures (
                hex_prefix, protocol_name, message_type, slice_rule, confidence
            ) VALUES (
                '{sig['hex_prefix']}', '{sig['protocol_name']}', '{sig['message_type']}',
                '{sig['slice_rule']}', '{sig['confidence']}'
            )
        """)

        with open(os.path.join(SIGS_DIR, f"{sig['hex_prefix']}.json"), "w", encoding="utf-8") as f_sig:
            json.dump(sig, f_sig, indent=2)

    conn.execute("COMMIT")

    if ledger_records:
        ledger_file = os.path.join(HISTORY_DIR, "schema-deltas.jsonl")
        with open(ledger_file, "a", encoding="utf-8") as f:
            for rec in ledger_records:
                f.write(json.dumps(rec) + "\n")

    conn.execute(f"COPY (SELECT * FROM protocol_slices) TO '{DATA_DIR}/fields.parquet' (FORMAT PARQUET)")
    conn.execute(f"COPY (SELECT * FROM protocol_slices) TO '{EXPORT_DIR}/fields.parquet' (FORMAT PARQUET)")

    with open(os.path.join(PROTO_DIR, "index.json"), "w", encoding="utf-8") as f:
        json.dump({
            "updated_at_utc": now_iso,
            "total_protocols": len(protocol_index),
            "protocols": protocol_index
        }, f, indent=2)

    with open(os.path.join(DELTAS_DIR, "today.json"), "w", encoding="utf-8") as f:
        json.dump({"date": date_str, "updated_at_utc": now_iso, "schema_deltas": ledger_records}, f, indent=2)

    with open(os.path.join(EXPORT_DIR, "today.json"), "w", encoding="utf-8") as f:
        json.dump({
            "date": date_str,
            "updated_at_utc": now_iso,
            "active_protocols_count": len(protocol_index),
            "protocols": protocol_index
        }, f, indent=2)

    with open(os.path.join(API_DIR, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({
            "wire": "binary-protocol-slice-wire",
            "schema_version": "1.0.0",
            "generated_at": now_iso,
            "source_cursor": "iana-rfcs-wireshark-ir",
            "freshness_slo_seconds": 86400,
            "artifacts": [
                "today.json",
                "fields.parquet",
                "llms.txt",
                "v1/schema.json",
                "v1/protocols/index.json"
            ],
            "coverage": {
                "supported_protocols": list(CANONICAL_PROTOCOLS.keys()),
                "total_slices": conn.execute("SELECT count(*) FROM protocol_slices").fetchone()[0]
            },
            "limitations": [
                "Exposes deterministic outer header envelopes only",
                "Encrypted or variable-length extension payload dissection delegated to higher layers"
            ]
        }, f, indent=2)

    with open(os.path.join(API_DIR, "provenance.json"), "w", encoding="utf-8") as f:
        json.dump({
            "generator": "binary-protocol-slice-wire",
            "runtime": "python-3.11",
            "ir_format": "offset-mask-discriminant-v1",
            "generated_at_utc": now_iso
        }, f, indent=2)

    with open(os.path.join(API_DIR, "schema.json"), "w", encoding="utf-8") as f:
        json.dump({
            "$schema": "https://json-schema.org/draft-07/schema#",
            "title": "ProtocolSliceSchema",
            "type": "object",
            "properties": {
                "protocol": {"type": "string"},
                "fixed_header_bytes": {"type": "integer"},
                "fields": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "field_name": {"type": "string"},
                            "byte_offset_start": {"type": "integer"},
                            "byte_offset_end": {"type": "integer"},
                            "bit_mask": {"type": "string"},
                            "field_type": {"type": "string"}
                        },
                        "required": ["field_name", "byte_offset_start", "byte_offset_end", "field_type"]
                    }
                }
            },
            "required": ["protocol", "fixed_header_bytes", "fields"]
        }, f, indent=2)

    lines = [
        "# Binary Protocol Slice Wire",
        f"> Last Sync: {now_iso} UTC",
        "> Optimization: Deterministic byte/bit offset slices and discriminant mappings for binary network protocols.",
        "> Slashes 20,000 to 200,000 tokens of RFC manuals to compact 300-token field slices.",
        "",
        "## Supported Protocol Slices"
    ]
    for p in protocol_index:
        lines.append(f"### {p['title']} (`{p['protocol']}`)")
        lines.append(f"- Reference: {p['reference']} | Header Length: `{p['fixed_header_bytes']} bytes` | Fields: `{p['fields_count']}`")
        lines.append(f"- Schema: `v1/protocols/{p['protocol']}/schema.json`")
        lines.append(f"- State Machine: `v1/protocols/{p['protocol']}/state-machine.json`")

    lines.extend([
        "",
        "## Quick Magic Signature Lookups"
    ])
    for sig in KNOWN_SIGNATURES:
        lines.append(f"- `0x{sig['hex_prefix']}` -> **{sig['protocol_name']}** ({sig['message_type']}) [{sig['confidence']}]")

    with open(os.path.join(EXPORT_DIR, "llms.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    checksums = []
    for root, _, files in os.walk(EXPORT_DIR):
        for file in sorted(files):
            if file == "checksums.txt":
                continue
            fpath = os.path.join(root, file)
            with open(fpath, "rb") as bf:
                f_hash = hashlib.sha256(bf.read()).hexdigest()
                rel_path = os.path.relpath(fpath, EXPORT_DIR)
                checksums.append(f"{f_hash}  {rel_path}")

    with open(os.path.join(EXPORT_DIR, "checksums.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(checksums) + "\n")

    conn.close()

if __name__ == "__main__":
    run()
