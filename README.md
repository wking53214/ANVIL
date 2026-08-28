# ANVIL

A deterministic, hash-chained governance kernel for tamper-evident execution
lineage and fail-closed execution recording.

ANVIL preserves an inspectable record of governed execution and detects
post-record modification through cryptographically linked state.

> The core implementation lives in `ANVIL.py` as a single file. Its header
> still reads `GSA Governance Adapter v2.1` — same code, the pre-ANVIL name.

## Core Properties

- deterministic execution records;
- hash-chained lineage;
- tamper-evident state;
- fail-closed execution (opt-in — see **Enforcement model** below);
- explicit governance boundaries;
- inspectable execution history.

## Architectural Purpose

ANVIL addresses a specific governance problem:

> A governed system needs a durable way to represent what occurred, preserve the relationship between successive states, and detect unauthorized modification of that recorded history.

The kernel therefore treats execution lineage as a first-class governed artifact rather than relying solely on application logs or mutable state.

## Running it

`ANVIL.py` is a library — importing or running it produces no output on its
own. The behaviour is exercised by the validation harness:

```bash
python3 anvil_validation_harness.py
```

The harness runs 14 checks across integrity chaining, immutability, registry
rules, and a full chained round-trip, and prints a set of `[FINDING]` notes on
the enforcement model (below). Current result: **14 passed, 0 failed**.

## Enforcement model

The validation harness documents how "fail-closed" actually behaves, and the
distinction matters for any caller:

- **Governance is opt-in.** `GsaKernel()` with no arguments wires no validator
  and no policy engine; execution runs the module directly. Fail-closed
  behaviour requires explicitly supplying those.
- **`execute()` returns, it does not raise.** A rejected validation, a denied
  authorization, or a module that itself raises all come back as a normally
  returned envelope with `execution_state.status == FAILED` and the module
  *not* run — not as an exception. The failure is recorded truthfully, but a
  caller that only checks "did an exception happen" will treat it as success.

So ANVIL fails closed in the sense that a failed execution never lets a module
produce output and the failure is always recorded; it does **not** force the
caller to notice. Whether that contract is acceptable is a policy decision per
deployment.

## Design Boundary

ANVIL establishes tamper evidence and execution lineage within the structures it governs.

It does not, by itself, establish the truth of an external event, guarantee the security of the surrounding host environment, or prevent a system from bypassing the kernel entirely.

Its guarantees therefore depend on the execution boundary through which governed activity is required to pass.

## Status

A focused governance-kernel implementation providing a deterministic
foundation for tamper-evident execution lineage and fail-closed control.
Python 3.11+, standard library only. Apache-2.0 licensed.
