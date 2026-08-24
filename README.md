# ANVIL

A deterministic, hash-chained governance kernel for tamper-evident execution lineage and fail-closed enforcement.

ANVIL is designed to preserve an inspectable record of governed execution and to detect post-record modification through cryptographically linked state.

## Core Properties

- deterministic execution records;
- hash-chained lineage;
- tamper-evident state;
- fail-closed enforcement;
- explicit governance boundaries;
- inspectable execution history.

## Architectural Purpose

ANVIL addresses a specific governance problem:

> A governed system needs a durable way to represent what occurred, preserve the relationship between successive states, and detect unauthorized modification of that recorded history.

The kernel therefore treats execution lineage as a first-class governed artifact rather than relying solely on application logs or mutable state.

## Design Boundary

ANVIL establishes tamper evidence and execution lineage within the structures it governs.

It does not, by itself, establish the truth of an external event, guarantee the security of the surrounding host environment, or prevent a system from bypassing the kernel entirely.

Its guarantees therefore depend on the execution boundary through which governed activity is required to pass.

## Status

ANVIL is a focused governance-kernel implementation intended to provide a deterministic foundation for tamper-evident execution lineage and fail-closed control.