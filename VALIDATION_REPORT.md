# Mnemosyne — Behavioural Validation Report

**Scope:** 75 end-to-end scenarios run through a real `MemoryGateway`
(in-memory backends), covering every control. Reproduce with
`python validation_harness.py`.

**Headline (v0.1.4): 75/75 pass.** All hard security guarantees pass *and* the
three previously-permissive cases (limited-trust injection on the knowledge
surface) are now contained — see "The finding, and the fix" below. The benign
false-positive guard stays at 13/13 (0%).

> Historical note: on v0.1.3 this harness reported 72/75. The 3 mismatches were
> not crashes or invariant breaks — they were a policy-default posture choice,
> fixed in v0.1.4 by routing injection findings through a stricter table.

## Results by category

| # | Category | Result |
|---|---|---|
| A | Direct injection → instruction (must DENY) | 5/5 ✅ |
| B | Persistence / tooling manipulation → instruction (DENY) | 4/4 ✅ |
| C | Indirect injection → knowledge (block) | 4/4 ✅ |
| D | Delayed / conditional triggers (Gemini-style) | 4/4 ✅ |
| E | Invisible-Unicode smuggling (tags / bidi / zero-width) | 4/4 ✅ |
| F | Secrets / PII detection + redaction | 9/9 ✅ |
| G | Trust-tier × surface invariant (full matrix) | 10/10 ✅ |
| H | Benign content — false-positive guard | 13/13 ✅ |
| I | Integrity / tamper-at-rest detection | 3/3 ✅ |
| J | Quarantine + human promotion lifecycle | 5/5 ✅ |
| K | Namespace segmentation | 2/2 ✅ |
| L | Read-time re-check (no knowledge→instruction promotion) | 3/3 ✅ |
| M | Edge cases (empty, whitespace, huge, unicode, unknown prov.) | 6/6 ✅ |
| N | Gradual erosion / behavioural drift | 2/2 ✅ |
| O | Audit-chain integrity | 1/1 ✅ |

**The load-bearing guarantees — verified working:**

- Untrusted/limited content can **never** reach the `INSTRUCTION` control plane
  (A, B, D4, E4, G3–G5, F4 all DENY).
- A knowledge record cannot be promoted into the instruction surface just by
  reading it there (L2).
- Tampering a stored record (content **or** integrity tag) is detected on read
  and denied (I1–I3).
- Tenants are isolated by namespace (K1–K2).
- Untrusted writes to knowledge quarantine and require audited human promotion
  (J1–J5); unknown provenance defaults to untrusted (M6).
- Secrets/PII are redacted on knowledge and denied on the control plane (F1–F5).
- Invisible-Unicode payloads (tag chars, bidi overrides, zero-width) are caught
  (E1–E4), while legitimate emoji ZWJ sequences are **not** false-flagged (H8).
- 13/13 benign writes — including text that *talks about* security, "ignore",
  "install", conditionals, multilingual content, and code — are preserved
  (0% false-positive rate on the benign set).

## The finding, and the fix (C3, C4, D3)

All three were the **same case**: a **limited-trust** source
(`tool_output`, `retrieved_doc`, `inter_agent`) writing a *single*
injection-flavoured phrase to the **knowledge** surface.

On v0.1.3 the decision was **SANITIZE**, because one injection family scores
`medium` and the generic policy mapped `knowledge.medium → sanitize`. The
problem: `sanitize` only strips secrets/PII and hidden Unicode — it does **not**
remove injection *phrasing*. So the record was stored with the injection text
intact. The cardinal invariant still held (it could never reach the instruction
plane, verified by L2), but for MINJA-style retrieval poisoning, retaining the
text is weaker than holding it for review.

**Fix (v0.1.4):** injection findings now use a dedicated stricter table
(`injection_severity_decisions`), separate from anomaly/obfuscation. On the
knowledge surface a medium injection signal is **quarantined**. Anomaly findings
(size/entropy/behavioural drift) stay on the gentle generic table, so a writer
who legitimately makes a large write is **not** over-blocked, and obfuscation
still strips-on-sanitize. The split is why the benign guard remained 13/13.

The new section is optional; policies without it fall back to the generic table,
so existing custom policies are unaffected.

**Remaining trade-off (documented, your call):** the stricter table can hold
back legitimate content that *quotes* injection phrases (e.g. security
documentation). If that matters for your corpus, relax the relevant cell in
`injection_severity_decisions` — e.g. set `knowledge.medium: sanitize`.

## Edge-case behaviour observed

- Empty / whitespace-only content: handled, no crash, stored (M1–M2).
- ~100 KB benign blob: a size-anomaly finding is raised but a *trusted* write is
  not hard-denied (M3) — anomaly informs, the trust tier governs.
- Emoji / CJK / Cyrillic benign content: stored (M4); emoji ZWJ not mistaken for
  smuggling (H8).
- Unknown provenance → treated as untrusted → quarantined on knowledge (M6),
  i.e. fail-safe default.

## Conclusion

Every guarantee the library advertises as load-bearing — the trust invariant,
cryptographic integrity, segmentation, audit, secrets-to-control-plane denial,
obfuscation detection, and the benign false-positive guard — behaves correctly
across the battery. As of v0.1.4 the harness is 75/75: the one nuance found on
v0.1.3 (medium-severity injection retained on the knowledge surface) is now
contained by quarantining injection-class findings, while keeping anomaly
findings gentle to preserve the 0% false-positive rate.
