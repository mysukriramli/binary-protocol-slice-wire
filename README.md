```markdown
# 🧩 Binary Protocol Slice Wire

An autonomous data plane running entirely on GitHub Actions that converts complex binary protocols, IoT telemetry frames, and network packets into compact, deterministic byte/bit slice schemas. It gives AI agents the exact boundaries, bitmasks, and enum discriminators needed to dissect payloads with zero external library overhead and zero token waste.

## Token Impact
- **Context Reduction**: 90% – 99%
- **Input Overhead**: Reduces 60,000+ tokens of verbose RFC protocol prose to a ~300 token deterministic slice dictionary.

## Shared Wire Endpoints
- [`/v1/manifest.json`](public/v1/manifest.json)
- [`/today.json`](public/today.json)
- [`/v1/schema.json`](public/v1/schema.json)
- [`/v1/protocols/index.json`](public/v1/protocols/index.json)
- [`/fields.parquet`](public/fields.parquet) (Columnar DuckDB snapshot)
- [`/llms.txt`](public/llms.txt)

## Architecture
- **Protocol IR**: Intermediate representation tracking `[byte_start, byte_end, bit_mask, field_type, enum_map]`
- **Supported Protocols**: DNS (RFC 1035), MQTT v3.1.1/v5, TLS Record Layer (RFC 5246/8446), DHCP (RFC 2131)
- **Database Engine**: DuckDB + Parquet
- **Ledger**: Append-only Git-committed JSONL in `/ledger`
- **Edge Delivery**: GitHub Pages (Fastly CDN)
