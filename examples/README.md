# Examples

Runnable demonstrations of Mnemosyne. All use the bundled in-memory backends,
so they need nothing beyond the base install (`pip install -e .`).

| File | What it shows |
|---|---|
| [`quickstart.py`](./quickstart.py) | The full guarded lifecycle: benign write, secret redaction, the MemoryTrap control-plane attack being denied, integrity verification on read, at-rest tamper detection, and the quarantine → human-promotion path. |
| [`langchain_memory_guard.py`](./langchain_memory_guard.py) | The integration *pattern*: a `GuardedMemory` wrapper that routes every save through `guard_write` and every load through `guard_read`, in front of any framework store (LangChain / Letta / custom). |

Run them:

```bash
python examples/quickstart.py
python examples/langchain_memory_guard.py
```

For the HTTP service, see the API quickstart in the top-level
[`README.md`](../README.md).
