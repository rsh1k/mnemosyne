# Architecture

Mnemosyne is a **memory-integrity firewall**: a gateway that sits between an
agent and whatever it uses for persistent memory (vector DB, key-value store,
files, a CLAUDE.md, hooks, system-prompt fragments). Every write *into* memory
and every read *out of* memory passes through it.

```
                         ┌──────────────────────────────────────────┐
   agent / framework     │                Mnemosyne                  │
  (LangChain, Letta,     │                                           │
   custom, HTTP client)  │   guard_write()            guard_read()   │
        │                │        │                        │         │
        │  content +     │        ▼                        ▼         │
        │  provenance +  │  ┌───────────┐           ┌────────────┐   │
        ├───────────────►│  │ provenance│           │ integrity  │   │
        │  surface       │  │ → trust   │           │ verify     │   │
        │                │  └─────┬─────┘           └─────┬──────┘   │
        │                │        ▼                       ▼          │
        │                │  ┌───────────┐           ┌────────────┐   │
        │                │  │ detectors │           │ re-scan     │  │
        │                │  │ injection │           │ (defense    │  │
        │                │  │ secrets   │           │  in depth)  │  │
        │                │  │ anomaly   │           └─────┬──────┘   │
        │                │  └─────┬─────┘                 ▼          │
        │                │        ▼                 ┌────────────┐   │
        │                │  ┌───────────┐           │ read-time  │   │
        │                │  │  policy   │◄──────────│  policy    │   │
        │                │  │  engine   │           └────────────┘   │
        │                │  └─────┬─────┘                            │
        │                │        ▼                                  │
        │                │  ALLOW / SANITIZE / QUARANTINE / DENY     │
        │                │        │                                  │
        │  outcome       │        ▼                                  │
        │◄───────────────┤  sign (HMAC) → store → audit (hash chain) │
        │                │                                           │
        └────────────────┴───────────────────────────────────────────┘
                                  │              │            │
                            ┌─────▼───┐   ┌──────▼─────┐  ┌───▼──────┐
                            │  store  │   │ quarantine │  │  audit   │
                            │ (ns-seg)│   │  (human    │  │  log     │
                            │         │   │  review)   │  │ (chain)  │
                            └─────────┘   └────────────┘  └──────────┘
```

## The cardinal invariant

> Content whose trust tier is not `TRUSTED` may never reach an `INSTRUCTION`
> surface without explicit, audited human promotion.

`INSTRUCTION` surfaces are the agent's **control plane**: system-prompt
fragments, `CLAUDE.md`, hooks, local tool/MCP config. This is precisely the
boundary that the Cisco *MemoryTrap* exploit crossed — a cloned repo led the
agent to write attacker-influenced content into persistent memory and global
hooks that then executed in later sessions. Enforcing this one invariant is the
single highest-value mitigation in the system; everything else is depth.

## The two guarded operations

### `guard_write`
1. **Resolve provenance → trust tier** via policy (`user_direct → trusted`,
   `tool_output/retrieved_doc → limited`, `external_web/untrusted_file → untrusted`).
2. **Run all detectors** (injection signatures, secrets/PII, statistical anomaly).
3. **Policy decides** `ALLOW | SANITIZE | QUARANTINE | DENY` — *most restrictive
   rule wins* (fail-safe default).
4. **Sign** allowed records with HMAC-SHA256 and **persist** with full metadata.
5. **Append a tamper-evident audit entry** (hash-chained).
6. **Feed the per-writer behavioral baseline** (gradual-erosion / sleeper detection).

### `guard_read`
1. **Verify the integrity tag** — detects tampering at rest (the MemoryTrap row
   rewrite). With `require_integrity_on_read`, a mismatch is a hard `DENY`.
2. **Re-scan** content (defense in depth; catches anything written out of band).
3. **Apply read-time policy against the _target_ surface** — content stored as
   knowledge cannot be silently elevated into the instruction plane just by
   reading it there.
4. **Audit** the read.

## Components

| Module | Responsibility |
|---|---|
| `core.models` | Domain types: `Provenance`, `TrustTier`, `MemorySurface`, `Decision`, `Finding`, `ScanResult`, `MemoryRecord`. |
| `core.gateway` | Orchestrates the two guarded operations; dependency-injected and side-effect isolated. |
| `core.config` | `pydantic-settings` configuration (env prefix `MNEMOSYNE_`). |
| `detectors.*` | Pluggable analysers. Bundled: `injection`, `obfuscation`, `secrets_pii`, `anomaly`. Pure-regex/heuristic → deterministic, microsecond, explainable, inline. |
| `policy.engine` | Declarative YAML policy → concrete `Decision`. Security teams tune posture without code changes. |
| `integrity.signer` | HMAC-SHA256 record signing; constant-time verify; KMS/HSM key-provider hook. |
| `integrity.audit` | Hash-chained tamper-evident audit log with chain verification. |
| `store.*` | `MemoryStore` / `QuarantineStore` protocols. Bundled: in-memory + SQLite. Namespacing = segmentation. |
| `nist` | Machine-readable control catalog (drives the CLI + `/compliance`). |
| `api.main` | FastAPI sidecar so non-Python agents call the gateway over HTTP. |
| `telemetry` | Structured JSON logging + Prometheus metrics. |

## Design principles

- **Fail closed.** A detector that raises denies the write (when
  `fail_closed`). Unknown provenance defaults to `untrusted`.
- **Defense in depth.** Trust invariant + signatures + crypto integrity +
  segmentation + audit. No single layer is load-bearing alone.
- **Deterministic core, pluggable edge.** Bundled detectors are
  regex/heuristic for speed and explainability, but the `Detector` protocol lets
  you drop an ML classifier in front of or alongside them.
- **Declarative policy.** Posture lives in YAML, versioned and reviewable, not
  scattered through code.
- **Storage agnostic.** Implement two protocols to back the gateway with your
  vector DB / Redis / Postgres; namespaces give you per-tenant isolation.

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the attacker model and
[`NIST_CONTROL_MAPPING.md`](./NIST_CONTROL_MAPPING.md) for compliance mapping.
