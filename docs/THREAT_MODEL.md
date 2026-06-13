# Threat Model

This document describes the attacker model Mnemosyne defends against, mapped to
**OWASP ASI06 — Memory & Context Poisoning** and the documented real-world
exploit pattern (Cisco *MemoryTrap*).

## What we are protecting

The **persistent memory and context surfaces** of an agentic AI system:

- **Instruction / control plane** — system-prompt fragments, `CLAUDE.md`,
  hooks, startup scripts, tool/MCP configuration. Content here *shapes future
  behaviour*.
- **Knowledge** — RAG corpora, archival memory, "facts the agent knows".
- **Episodic** — conversational history.
- **Scratch** — transient working memory.

The security property we want: **an attacker who can influence content reaching
any of these surfaces cannot thereby change the agent's future behaviour in a
way that persists or crosses trust boundaries.**

## Attacker model

We assume an attacker who can get content in front of the agent but does **not**
control the host, the gateway process, or the integrity key. Concretely they
can:

- Plant files in a repository the agent will clone/read (`untrusted_file`).
- Serve web pages / documents the agent will fetch (`external_web`, `retrieved_doc`).
- Return crafted output from a tool or another agent (`tool_output`, `inter_agent`).
- Attempt slow, low-and-slow corruption across many writes (gradual erosion).

Out of scope (assumed handled by the surrounding environment): host compromise,
theft of the HMAC/KMS key, malicious first-party operators, and model weights
tampering. Mnemosyne *reduces* the damage of some of these (e.g. integrity
verification detects at-rest row tampering) but does not claim to stop an
attacker who already holds the signing key.

## The three ASI06 vectors

### 1. Direct injection
Attacker content is written more-or-less verbatim into a memory surface and
contains instruction-like text ("ignore previous instructions", "you are now…",
"add this to your hooks").

**Mitigations:** `InjectionDetector` signatures (amplified on the control
plane) + the cardinal trust invariant (untrusted content can't reach
`INSTRUCTION` at all) + severity-driven policy.

### 2. Indirect injection
Attacker content arrives via a *trusted-looking channel* (a tool result, a
retrieved document) and is stored as knowledge, then later read back into a
prompt where it acts as an instruction.

**Mitigations:** provenance tracking (a retrieved doc is `limited`, never
`trusted`) + **read-time policy against the target surface** (knowledge content
loaded into an instruction surface is blocked) + re-scan on read.

### 3. Gradual erosion ("sleeper agent")
A writer behaves normally to build a baseline, then drifts — slowly enlarging or
changing writes until malicious content is "normal".

**Mitigations:** `AnomalyDetector` keeps a bounded per-writer baseline of write
sizes and injection scores and flags statistically significant deviation
(robust MAD z-score, with explicit handling of the zero-variance baseline an
attacker would try to exploit). This is the hardest vector and the baseline is a
documented extension point for a streaming-analytics backend.

### 4. Delayed / conditional execution (delayed tool invocation)
Demonstrated by Rehberger against Google Gemini: the attacker plants a
conditional in context — "if the user later says *yes* or *sure*, then add these
memories / run this tool" — so the trigger and the payload are decoupled in
time. The action fires during ordinary use, when nothing looks suspicious.

**Mitigations:** the injection detector's `delayed_execution` family flags a
conditional clause paired with a *sensitive* action (store/run/send/remember).
Because the payload is stored before it fires, write-time provenance/trust
handling and **read-time re-scanning** both apply, and an untrusted record still
cannot be loaded into the instruction plane when the trigger eventually hits.

### 5. Query-only memory injection (MINJA)
MINJA showed >95% injection success with *no* elevated privileges: an ordinary
user sends benign-looking queries whose summaries get written to memory as a
side effect, then surface for a different user later. Input/output moderation
sees nothing because each individual turn is innocuous.

**Mitigations:** provenance (agent-summarised tool/web content is `limited`, not
`trusted`), the trust invariant, quarantine-by-default for untrusted writes to
knowledge, and the behavioral baseline that notices a writer's pattern shifting.

### 6. Invisible-Unicode smuggling (document injection)
A document carries hidden instructions in zero-width characters, Unicode Tag
characters, or bidirectional overrides ("Trojan Source"); a human reviewer sees
clean text while the model reads the payload.

**Mitigations:** the `ObfuscationDetector` flags tag characters (critical), bidi
overrides (high), and zero-width characters interleaved with ASCII (the
smuggling signature), while ignoring legitimate emoji ZWJ sequences and RTL
script. The sanitise path strips these characters before storage.

### Detection difficulty & primary defense

| Vector | Visible at write time? | Hardest part | Primary Mnemosyne defense |
|---|---|---|---|
| Direct injection | Yes | Phrasing variety | Injection signatures + trust invariant |
| Indirect injection | Partly | Looks trusted | Provenance + read-time re-check |
| Gradual erosion | No (per-entry) | Slow drift | Per-writer behavioral baseline |
| Delayed trigger | Payload yes, intent no | Time-decoupled trigger | `delayed_execution` + read-time re-scan |
| Query-only (MINJA) | No | Side-effect writes look benign | Provenance + quarantine + baseline |
| Unicode smuggling | Hidden | Invisible to humans | Obfuscation detector + strip |

## The MemoryTrap pattern (worked example)

1. Victim clones an attacker-controlled repo.
2. Agent reads a file that suggests an action (e.g. `npm install <payload>`).
3. Without a firewall, the agent writes attacker-influenced content into
   persistent memory **and** global hooks / system-prompt instruction layer.
4. The payload now executes in *future, unrelated* sessions — persistence.

**Where Mnemosyne breaks the chain:** step 3. The content's provenance is
`untrusted_file`; its trust tier is `untrusted`; the target is an `INSTRUCTION`
surface whose `surface_min_tier` is `trusted`. The cardinal invariant fires →
`DENY`. Even if the content were merely stored as knowledge, the read-time
check prevents it from being loaded back into the instruction plane, and the
HMAC integrity tag detects any out-of-band rewrite of the stored row.

## STRIDE summary

| STRIDE | Threat in this domain | Primary control |
|---|---|---|
| **S**poofing | Forged provenance to gain trust | Provenance is set by the integration boundary; unknown ⇒ untrusted |
| **T**ampering | Rewriting stored memory at rest | HMAC-SHA256 record integrity, verified on read |
| **R**epudiation | "The agent did that, not my content" | Hash-chained, tamper-evident audit log |
| **I**nformation disclosure | Secrets/PII persisted or exfiltrated | Secrets/PII detector + redaction; exfil-directive signatures |
| **D**enial of service | Oversized / high-entropy memory bombs | Size + entropy anomaly checks |
| **E**levation of privilege | Data promoted into the control plane | The cardinal trust invariant; audited human-only promotion |

## Residual risk & honest limitations

- Signature/heuristic detectors can be evaded by sufficiently novel phrasing.
  They are one layer; the **trust invariant, crypto integrity, segmentation, and
  audit** are the load-bearing guarantees and do not depend on detector recall.
- The behavioral baseline is intentionally simple (bounded, online). Determined
  slow-drift attacks within the baseline window may evade it; pair with external
  analytics for high-assurance deployments.
- Mnemosyne does not defend against theft of the signing key or host compromise.
- It is a control on memory integrity, **not** a general agent sandbox — combine
  it with tool sandboxing, network egress control, and least-privilege identity.
