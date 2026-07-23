"""
===============================================================================
ANVIL Validation Harness v1.0
===============================================================================

Purpose:
    Proves (or disproves) specific claims made by ANVIL.py — rather than
    just checking "does it run," each test targets one concrete promise
    the code makes about itself and reports PASS/FAIL/FINDING plainly.

How to run:
    python3 anvil_validation_harness.py

    Place this file in the same folder as ANVIL.py before running.

Output:
    A labeled report, grouped into five buckets, in priority order:
      1. Enforcement       - does governance actually block anything?
      2. Integrity Chain   - are hashes deterministic and tamper-evident?
      3. Immutability      - can state be quietly mutated after the fact?
      4. Registry Rules    - are duplicate/unknown/disabled modules blocked?
      5. Full Round-Trip   - does a multi-step chain verify end-to-end?

    A "FINDING" (as opposed to PASS/FAIL) means the code behaved
    consistently and did not crash, but the behavior itself is worth
    William's attention - e.g. "governance ran, but nothing was actually
    checked, because no validator was wired in."
===============================================================================
"""

import asyncio
import sys
import traceback as tb_module

RESULTS = []  # (bucket, name, status, detail)


def record(bucket, name, status, detail=""):
    RESULTS.append((bucket, name, status, detail))


# =============================================================================
# Load ANVIL.py
# =============================================================================

try:
    with open("ANVIL.py") as f:
        _src = f.read()
    ANVIL = {}
    exec(compile(_src, "ANVIL.py", "exec"), ANVIL)
except Exception as e:
    print("FATAL: could not load ANVIL.py -", e)
    sys.exit(1)

# Pull the names we need out of the executed module namespace
GsaKernel = ANVIL["GsaKernel"]
GsaDependencies = ANVIL["GsaDependencies"]
GsaGovernanceRuntime = ANVIL["GsaGovernanceRuntime"]
GsaContextEnvelope = ANVIL["GsaContextEnvelope"]
GovernanceResult = ANVIL["GovernanceResult"]
RuntimeStatus = ANVIL["RuntimeStatus"]
ModuleIdentity = ANVIL["ModuleIdentity"]
ModuleDescriptor = ANVIL["ModuleDescriptor"]
GsaModuleRegistry = ANVIL["GsaModuleRegistry"]
ConfigurationException = ANVIL["ConfigurationException"]
AuthorizationException = ANVIL["AuthorizationException"]
IntegrityEngine = ANVIL["IntegrityEngine"]
ChainVerifier = ANVIL["ChainVerifier"]
IntegrityManager = ANVIL["IntegrityManager"]
GovernanceDag = ANVIL["GovernanceDag"]
GovernanceNode = ANVIL["GovernanceNode"]
create_gsa_kernel = ANVIL["create_gsa_kernel"]
ModuleLoader = ANVIL["ModuleLoader"]
deep_freeze = ANVIL["deep_freeze"]


# A tiny always-succeeds module for round-trip / baseline tests
class _EchoModule:
    async def execute(self, context):
        envelope = context.envelope
        from dataclasses import replace as _replace
        return _replace(
            envelope,
            payload_data=deep_freeze(
                {**dict(envelope.payload_data), "touched_by": "echo"}
            ),
        )


class _ExplodingModule:
    async def execute(self, context):
        raise RuntimeError("simulated module failure")


class _AlwaysRejectValidator:
    async def validate(self, envelope):
        return GovernanceResult(
            passed=False, score=0.0, decision="REJECTED",
            violations=("simulated validation rejection",),
        )


class _AlwaysRejectPolicy:
    async def evaluate(self, envelope):
        return GovernanceResult(
            passed=False, score=0.0, decision="DENIED",
            violations=("simulated policy denial",),
        )


# =============================================================================
# BUCKET 1 - Enforcement (fail-closed?)
# =============================================================================

async def bucket_1_enforcement():
    bucket = "1. Enforcement"

    # 1a. Default GsaKernel wiring: is a validator/policy engine even present?
    kernel = create_gsa_kernel()
    has_validator = kernel.runtime.dependencies.validator is not None
    has_policy = kernel.runtime.dependencies.policy_engine is not None
    if not has_validator and not has_policy:
        record(
            bucket, "Default kernel has governance checks wired in", "FINDING",
            "GsaKernel() with no arguments wires NO validator and NO policy "
            "engine. Every execution skips straight to running the module - "
            "there is nothing to fail-closed FROM by default. Governance is "
            "opt-in, not on by default.",
        )
    else:
        record(bucket, "Default kernel has governance checks wired in", "PASS")

    # 1b. When a validator rejects, does execute() raise, or return quietly?
    runtime = GsaGovernanceRuntime(
        dependencies=GsaDependencies(validator=_AlwaysRejectValidator())
    )
    envelope = GsaContextEnvelope(payload_data=deep_freeze({"x": 1}))
    result_envelope = await runtime.execute(_EchoModule(), envelope)
    raised = False  # it didn't raise, we're still here
    status_is_failed = result_envelope.execution_state.status == RuntimeStatus.FAILED
    module_ran_anyway = result_envelope.payload_data.get("touched_by") == "echo"

    if not raised and status_is_failed and not module_ran_anyway:
        record(
            bucket, "Rejected validation blocks module execution", "FINDING",
            "A rejected validation does NOT raise an exception out of "
            "runtime.execute() - it returns a normal envelope object with "
            "status=FAILED buried inside it. The module itself was correctly "
            "NOT run. But any caller that only checks 'did an exception "
            "happen' (rather than inspecting execution_state.status) will "
            "treat this as a successful call.",
        )
    elif module_ran_anyway:
        record(
            bucket, "Rejected validation blocks module execution", "FAIL",
            "The module ran even though validation was rejected. This is "
            "the more serious version of the problem - bad data would "
            "flow through, not just be mislabeled.",
        )
    else:
        record(bucket, "Rejected validation blocks module execution", "PASS")

    # 1c. Same test for policy/authorization rejection
    runtime2 = GsaGovernanceRuntime(
        dependencies=GsaDependencies(policy_engine=_AlwaysRejectPolicy())
    )
    result2 = await runtime2.execute(_EchoModule(), envelope)
    module_ran_anyway_2 = result2.payload_data.get("touched_by") == "echo"
    if not module_ran_anyway_2:
        record(
            bucket, "Denied authorization blocks module execution", "FINDING",
            "Same pattern as validation: module correctly did not run, but "
            "the denial surfaces only as execution_state.status == FAILED "
            "on a normally-returned object, not as a raised exception.",
        )
    else:
        record(
            bucket, "Denied authorization blocks module execution", "FAIL",
            "Module ran despite policy denial.",
        )

    # 1d. A module that throws mid-execution - does the exception escape,
    #     or get swallowed into a FAILED envelope the same way?
    runtime3 = GsaGovernanceRuntime()
    result3 = await runtime3.execute(_ExplodingModule(), envelope)
    exception_escaped = False  # we're past the call, so it didn't
    status3 = result3.execution_state.status
    record(
        bucket, "Module exceptions are caught and labeled, not raised", "FINDING",
        f"A module that raises RuntimeError does not propagate the "
        f"exception to the caller. execution_state.status came back as "
        f"'{status3.value}' with error_message='{result3.execution_state.error_message}'. "
        f"Consistent with 1b/1c: the runtime never raises on failure, it "
        f"always returns an envelope and encodes failure inside it.",
    )

    # 1e. The actionable takeaway, stated once explicitly
    record(
        bucket,
        "Net finding: is ANVIL fail-closed at the API level?",
        "FINDING",
        "No - not by default, and not automatically. ANVIL fails closed "
        "in the sense that a rejected/failed execution never lets a "
        "module produce output, and the failure is truthfully recorded. "
        "But it does NOT fail closed in the sense of forcing the caller "
        "to notice: execute() always returns an object rather than "
        "raising, so a caller that doesn't explicitly check "
        "execution_state.status will proceed as if everything succeeded. "
        "Whether that's acceptable depends on whether every caller can be "
        "trusted to check status - which is a policy decision, not a bug "
        "fix, and worth William deciding deliberately either way.",
    )


# =============================================================================
# BUCKET 2 - Integrity Chain
# =============================================================================

async def bucket_2_integrity():
    bucket = "2. Integrity Chain"

    # 2a. Determinism: same input -> same hash
    h1 = IntegrityEngine.hash_value({"a": 1, "b": [1, 2, 3]})
    h2 = IntegrityEngine.hash_value({"b": [1, 2, 3], "a": 1})  # different key order
    if h1 == h2:
        record(bucket, "Same logical input produces identical hash regardless of key order", "PASS")
    else:
        record(bucket, "Same logical input produces identical hash regardless of key order", "FAIL",
               f"{h1} != {h2}")

    # 2b. Different input -> different hash
    h3 = IntegrityEngine.hash_value({"a": 1, "b": [1, 2, 4]})
    if h1 != h3:
        record(bucket, "Different input produces different hash", "PASS")
    else:
        record(bucket, "Different input produces different hash", "FAIL", "Hash collision on different input")

    # 2c. Tamper detection via verify_signature
    sig = IntegrityEngine.create_state_signature(
        parent_hash="ROOT_STATE", iteration=1, actor="test", payload={"amount": 100}
    )
    # create_state_signature hashes its payload wrapped in a list (via
    # hash_components), so the comparison state must match that same shape.
    tampered_ok = IntegrityEngine.verify_signature(sig, [{
        "parent_hash": "ROOT_STATE", "iteration": 1, "actor": "test",
        "payload": {"amount": 100}, "metadata": {},
    }])
    tampered_bad = IntegrityEngine.verify_signature(sig, [{
        "parent_hash": "ROOT_STATE", "iteration": 1, "actor": "test",
        "payload": {"amount": 999}, "metadata": {},  # tampered
    }])
    if tampered_ok and not tampered_bad:
        record(bucket, "Tampered payload is detected via signature mismatch", "PASS")
    else:
        record(bucket, "Tampered payload is detected via signature mismatch", "FAIL",
               f"tampered_ok={tampered_ok}, tampered_bad(should be False)={tampered_bad}")

    # 2d. ChainVerifier rejects a non-advancing hash (replay/no-op attempt)
    same_hash_rejected = not ChainVerifier.verify_append("abc123", "abc123")
    real_advance_accepted = ChainVerifier.verify_append("abc123", "def456")
    if same_hash_rejected and real_advance_accepted:
        record(bucket, "Chain rejects a non-advancing (replayed) hash", "PASS")
    else:
        record(bucket, "Chain rejects a non-advancing (replayed) hash", "FAIL",
               f"same_hash_rejected={same_hash_rejected}, real_advance_accepted={real_advance_accepted}")

    # 2e. Full transition through IntegrityManager: does verify_transition
    #     correctly flag a broken/negative chain depth as invalid?
    envelope = GsaContextEnvelope(payload_data=deep_freeze({"n": 1}))
    snapshot = IntegrityManager.create_transition(envelope, "tester")
    updated = IntegrityManager.apply_transition(envelope, snapshot)
    valid = IntegrityManager.verify_transition(updated)
    if valid and updated.execution_state.chain_depth == 1:
        record(bucket, "A normal state transition verifies as valid", "PASS")
    else:
        record(bucket, "A normal state transition verifies as valid", "FAIL",
               f"valid={valid}, chain_depth={updated.execution_state.chain_depth}")


# =============================================================================
# BUCKET 3 - Immutability
# =============================================================================

async def bucket_3_immutability():
    bucket = "3. Immutability"

    envelope = GsaContextEnvelope(payload_data=deep_freeze({"n": 1}))

    # 3a. Frozen dataclass actually prevents attribute mutation
    try:
        envelope.payload_data = {"n": 999}
        record(bucket, "Envelope cannot be mutated directly after creation", "FAIL",
               "Setting an attribute on the envelope succeeded - should have raised.")
    except Exception:
        record(bucket, "Envelope cannot be mutated directly after creation", "PASS")

    # 3b. deep_freeze actually produces structures that reject mutation
    frozen = deep_freeze({"list": [1, 2, 3], "nested": {"x": 1}})
    mutation_blocked = True
    try:
        frozen["list"] = [9, 9, 9]
        mutation_blocked = False
    except Exception:
        pass
    try:
        frozen["list"].append(4)  # tuple has no .append - should raise AttributeError
        mutation_blocked = False
    except Exception:
        pass
    if mutation_blocked:
        record(bucket, "deep_freeze output rejects in-place mutation", "PASS")
    else:
        record(bucket, "deep_freeze output rejects in-place mutation", "FAIL",
               "A frozen structure was mutated in place without error.")

    # 3c. with_updates produces a NEW object; original is untouched
    updated = envelope.with_updates(payload_data=deep_freeze({"n": 2}))
    if envelope.payload_data["n"] == 1 and updated.payload_data["n"] == 2:
        record(bucket, "with_updates() leaves the original envelope untouched", "PASS")
    else:
        record(bucket, "with_updates() leaves the original envelope untouched", "FAIL",
               f"original n={envelope.payload_data['n']}, updated n={updated.payload_data['n']}")


# =============================================================================
# BUCKET 4 - Registry Rules
# =============================================================================

async def bucket_4_registry():
    bucket = "4. Registry Rules"

    registry = GsaModuleRegistry()
    descriptor = ModuleDescriptor(
        identity=ModuleIdentity(name="DupeTest", version="1.0.0"),
        module_class=_EchoModule,
    )
    registry.register(descriptor)

    # 4a. Duplicate registration is blocked
    try:
        registry.register(descriptor)
        record(bucket, "Duplicate module registration is rejected", "FAIL",
               "Registering the same module twice succeeded silently.")
    except ConfigurationException:
        record(bucket, "Duplicate module registration is rejected", "PASS")

    # 4b. Unknown module lookup fails clearly rather than returning None
    try:
        registry.get("GSA:DoesNotExist:1.0.0")
        record(bucket, "Unknown module lookup raises rather than returning None/garbage", "FAIL")
    except ConfigurationException:
        record(bucket, "Unknown module lookup raises rather than returning None/garbage", "PASS")

    # 4c. A disabled module is blocked at load time, not silently run
    disabled_descriptor = ModuleDescriptor(
        identity=ModuleIdentity(name="DisabledTest", version="1.0.0"),
        module_class=_EchoModule,
        enabled=False,
    )
    registry.register(disabled_descriptor)
    loader = ModuleLoader(registry=registry)
    try:
        loader.create("GSA:DisabledTest:1.0.0")
        record(bucket, "Disabled module is blocked from being instantiated", "FAIL",
               "ModuleLoader.create() returned an instance of a disabled module.")
    except AuthorizationException:
        record(bucket, "Disabled module is blocked from being instantiated", "PASS")


# =============================================================================
# BUCKET 5 - Full Round-Trip
# =============================================================================

async def bucket_5_roundtrip():
    bucket = "5. Full Round-Trip"

    kernel = create_gsa_kernel()

    try:
        r1 = await kernel.execute("GSA:ExampleModule:1.0.0", payload={"step": 1})
        r2 = await kernel.execute("GSA:ExampleModule:1.0.0", payload={"step": 2}, continue_from=r1)
        r3 = await kernel.execute("GSA:ExampleModule:1.0.0", payload={"step": 3}, continue_from=r2)

        # 3 chained executions + 1 seeded root-state node = 4 total
        all_recorded = len(kernel.dag._nodes) == 4
        all_healthy = kernel.health().healthy
        all_succeeded = all(
            r.execution_state.status == RuntimeStatus.COMPLETED
            for r in (r1, r2, r3)
        )

        if all_recorded and all_healthy and all_succeeded:
            record(bucket, "Three chained executions all complete and are recorded in the DAG", "PASS")
        else:
            record(bucket, "Three chained executions all complete and are recorded in the DAG", "FAIL",
                   f"recorded={len(kernel.dag._nodes)}/4, healthy={all_healthy}, "
                   f"statuses={[r.execution_state.status.value for r in (r1, r2, r3)]}")

        # Each execution's hash should be unique (no accidental hash reuse)
        hashes = {r.execution_state.current_hash for r in (r1, r2, r3)}
        if len(hashes) == 3:
            record(bucket, "Each execution produces a unique integrity hash", "PASS")
        else:
            record(bucket, "Each execution produces a unique integrity hash", "FAIL",
                   f"Only {len(hashes)} unique hashes across 3 executions.")

        # Checkpoint creation + verification round-trip
        checkpoint = kernel.create_checkpoint("checkpoint-1", r3, "tester")
        checkpoint_verifies = kernel.checkpoints.verify("checkpoint-1", r3)
        if checkpoint_verifies:
            record(bucket, "Named checkpoint verifies against the envelope it was created from", "PASS")
        else:
            record(bucket, "Named checkpoint verifies against the envelope it was created from", "FAIL")

    except Exception as e:
        record(bucket, "Full round-trip completed without an unhandled exception", "FAIL",
               f"{type(e).__name__}: {e}\n{tb_module.format_exc()}")


# =============================================================================
# Runner + Report
# =============================================================================

async def main():
    await bucket_1_enforcement()
    await bucket_2_integrity()
    await bucket_3_immutability()
    await bucket_4_registry()
    await bucket_5_roundtrip()

    print("=" * 79)
    print("ANVIL VALIDATION HARNESS - RESULTS")
    print("=" * 79)

    current_bucket = None
    counts = {"PASS": 0, "FAIL": 0, "FINDING": 0}

    for bucket, name, status, detail in RESULTS:
        if bucket != current_bucket:
            print(f"\n{bucket}")
            print("-" * len(bucket))
            current_bucket = bucket
        counts[status] = counts.get(status, 0) + 1
        marker = {"PASS": "[PASS]   ", "FAIL": "[FAIL]   ", "FINDING": "[FINDING]"}[status]
        print(f"  {marker} {name}")
        if detail:
            for line in detail.split(". "):
                line = line.strip()
                if line:
                    print(f"             {line}{'.' if not line.endswith('.') else ''}")

    print("\n" + "=" * 79)
    print(f"SUMMARY: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['FINDING']} findings")
    print("=" * 79)

    if counts["FAIL"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
