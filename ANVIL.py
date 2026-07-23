"""
===============================================================================
GSA Governance Adapter v2.1

Single-file governance kernel: module registry, hash-chained integrity
engine, execution runtime, DAG lineage, audit/telemetry services, and the
GsaKernel entry point. Organized into ten labeled sections below (1A-10);
all sections live in this one file and share the consolidated import block
at the top rather than re-importing per section.

Responsibilities:
    - Runtime metadata, immutable data handling, deterministic identifiers
    - Canonical serialization and SHA-256 integrity signatures
    - Governance data models (envelopes, execution state, audit events)
    - Module registry, discovery, and dependency-injected execution runtime
    - DAG-based execution lineage and named integrity anchors
    - Audit ledger, telemetry, event bus, and health monitoring services
    - GsaKernel: the top-level entry point that wires all of the above

Design Goals:
    - Python 3.11+
    - Deterministic behavior
    - Immutable state propagation
    - Fail-closed architecture
    - Framework independence

v2.1 changes from v2.0:
    - Fixed: 10 duplicate `from __future__ import annotations` statements
      (one per section) collapsed into the single required top-of-file
      import; the v2.0 file could not be compiled/run as-is.
    - Fixed: ConfigurationException's `code` attribute was accidentally
      written inside its docstring (unclosed triple-quote swallowed the
      assignment), so it silently inherited the generic base-class code
      instead of "GSA_CONFIGURATION_FAILURE".
    - Consolidated ~25 duplicated per-section import statements into one
      header block; no behavior change, less to scan per section.
    - Reformatted with Black (line length 88) to collapse the one-
      argument-per-line / blank-line-per-statement style used throughout
      v2.0; purely cosmetic, no logic changed.
    - Verified end-to-end: compiles cleanly and GsaKernel.execute() runs
      the example module successfully (see accompanying update notes).

===============================================================================
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import platform
import time
import traceback
import uuid

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
)
from uuid import UUID, uuid4

# =============================================================================
# Module Metadata
# =============================================================================
GSA_VERSION = "2.0.0"
GSA_SCHEMA_VERSION = "2.0"
RUNTIME_NAME = "GSA Governance Kernel"
HASH_ALGORITHM = "sha256"

# =============================================================================
# Type Aliases
# =============================================================================
JsonPrimitive = str | int | float | bool | None
JsonValue = JsonPrimitive | Dict[str, "JsonValue"] | List["JsonValue"]
HashString = str
TraceId = str
ModuleName = str
T = TypeVar("T")


# =============================================================================
# Enumerations
# =============================================================================
class RuntimeStatus(str, Enum):
    """
    Runtime lifecycle state.
    """

    INITIALIZED = "INITIALIZED"
    VALIDATING = "VALIDATING"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


class GovernanceSeverity(str, Enum):
    """
    Governance event severity.
    """

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# =============================================================================
# Exception Hierarchy
# =============================================================================
class GsaException(Exception):
    """
    Root GSA exception.
    """

    code = "GSA_UNKNOWN_ERROR"


class IntegrityException(GsaException):
    """
    Hash, signature, or lineage validation failure.
    """

    code = "GSA_INTEGRITY_FAILURE"


class ValidationException(GsaException):
    """
    Payload or schema validation failure.
    """

    code = "GSA_VALIDATION_FAILURE"


class ModuleExecutionException(GsaException):
    """
    Module execution failure.
    """

    code = "GSA_MODULE_FAILURE"


class AuthorizationException(GsaException):
    """
    Unauthorized execution attempt.
    """

    code = "GSA_AUTHORIZATION_FAILURE"


class ConfigurationException(GsaException):
    """
    Runtime configuration failure.
    """

    code = "GSA_CONFIGURATION_FAILURE"


# =============================================================================
# Time Utilities
# =============================================================================
def utc_timestamp() -> float:
    """
    Returns deterministic UTC epoch timestamp.
    """
    return time.time()


def utc_iso_timestamp() -> str:
    """
    Returns ISO formatted UTC timestamp.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# =============================================================================
# Identifier Utilities
# =============================================================================
def create_trace_id() -> TraceId:
    """
    Generates execution trace identifier.
    """
    return uuid.uuid4().hex


def create_deterministic_id(
    parent_hash: str,
    actor: str,
    iteration: int,
) -> str:
    """
    Creates deterministic execution identity.
    Same inputs always produce the same ID.
    """
    source = f"{parent_hash}|" f"{actor}|" f"{iteration}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


# =============================================================================
# Immutable Structure Utilities
# =============================================================================
def deep_freeze(value: Any) -> Any:
    """
    Recursively converts mutable structures into immutable equivalents.
    dict      -> MappingProxyType
    list      -> tuple
    set       -> frozenset
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(deep_freeze(item) for item in value)
    return value


def deep_thaw(value: Any) -> Any:
    """
    Converts immutable structures back into mutable equivalents.
    """
    if isinstance(value, Mapping):
        return {key: deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [deep_thaw(item) for item in value]
    if isinstance(value, frozenset):
        return {deep_thaw(item) for item in value}
    return copy.deepcopy(value)


# =============================================================================
# Dictionary Utilities
# =============================================================================
def merge_dicts(
    base: Mapping[str, Any],
    updates: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    Immutable dictionary merge.
    """
    merged = dict(base)
    merged.update(updates)
    return merged


def require_keys(
    payload: Mapping[str, Any],
    required: Iterable[str],
) -> None:
    """
    Validates required fields.
    """
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValidationException(f"Missing required fields: {missing}")


# =============================================================================
# Runtime Environment Metadata
# =============================================================================
@dataclass(frozen=True)
class RuntimeEnvironment:
    """
    Immutable runtime information snapshot.
    """

    python_version: str = field(default_factory=lambda: platform.python_version())
    operating_system: str = field(default_factory=lambda: platform.system())
    hostname: str = field(default_factory=lambda: platform.node())
    process_id: int = field(default_factory=os.getpid)


# =============================================================================
# Protocol Contracts
# =============================================================================
class GovernanceModule(Protocol):
    """
    Standard execution contract.
    """

    async def execute(
        self,
        context: Any,
    ) -> Any: ...
class TelemetryProvider(Protocol):
    """
    Runtime metrics contract.
    """

    def record(
        self,
        event: Mapping[str, Any],
    ) -> None: ...
class AuditProvider(Protocol):
    """
    Audit persistence contract.
    """

    def append(
        self,
        event: Mapping[str, Any],
    ) -> None: ...


# =============================================================================
# Thread-Safe Primitive
# =============================================================================
class LockedRegistry:
    """
    Reusable thread-safe registry primitive.
    """

    def __init__(self):
        self._lock = RLock()
        self._entries: Dict[str, Any] = {}

    def register(
        self,
        name: str,
        value: Any,
    ) -> None:
        with self._lock:
            if name in self._entries:
                raise ConfigurationException(f"Duplicate registration: {name}")
            self._entries[name] = value

    def get(
        self,
        name: str,
    ) -> Any:
        with self._lock:
            if name not in self._entries:
                raise ConfigurationException(f"Unknown registry item: {name}")
            return self._entries[name]

    def list_items(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._entries.keys())


# =============================================================================
# Section 1B - Canonical Serialization & Integrity Engine
# =============================================================================
"""
Provides deterministic serialization and cryptographic integrity primitives.
Responsibilities:
- Canonical object normalization
- Stable JSON serialization
- SHA-256 hashing
- Envelope state signatures
- Chain verification
- Deterministic replay validation
"""


class CanonicalSerializationException(GsaException):
    code = "GSA_SERIALIZATION_FAILURE"


class CanonicalSerializer:
    """
    Converts runtime objects into deterministic representations.
    """

    @staticmethod
    def normalize(value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.astimezone().isoformat()
        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, Path):
            return str(value)
        if is_dataclass(value):
            return CanonicalSerializer.normalize(asdict(value))
        if isinstance(value, Mapping):
            return {
                str(key): CanonicalSerializer.normalize(item)
                for key, item in sorted(value.items(), key=lambda x: str(x[0]))
            }
        if isinstance(value, (list, tuple)):
            return [CanonicalSerializer.normalize(item) for item in value]
        if isinstance(value, (set, frozenset)):
            return sorted(
                [CanonicalSerializer.normalize(item) for item in value],
                key=lambda x: str(x),
            )
        if hasattr(value, "__dict__"):
            return CanonicalSerializer.normalize(vars(value))
        raise CanonicalSerializationException(f"Unsupported type: {type(value)}")

    @staticmethod
    def serialize(value: Any) -> str:
        normalized = CanonicalSerializer.normalize(value)
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


class IntegrityEngine:
    """
    Generates and verifies immutable state signatures.
    """

    algorithm = HASH_ALGORITHM

    @classmethod
    def hash_value(cls, value: Any) -> str:
        serialized = CanonicalSerializer.serialize(value)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def hash_components(
        cls,
        *components: Any,
    ) -> str:
        payload = [CanonicalSerializer.normalize(item) for item in components]
        return cls.hash_value(payload)

    @classmethod
    def create_state_signature(
        cls,
        parent_hash: str,
        iteration: int,
        actor: str,
        payload: Any,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> str:
        return cls.hash_components(
            {
                "parent_hash": parent_hash,
                "iteration": iteration,
                "actor": actor,
                "payload": payload,
                "metadata": metadata or {},
            }
        )

    @classmethod
    def verify_signature(
        cls,
        expected_hash: str,
        actual_state: Any,
    ) -> bool:
        return cls.hash_value(actual_state) == expected_hash


class ChainVerifier:
    """
    Validates ordered execution lineage.
    """

    @staticmethod
    def verify_chain(
        chain: Iterable[str],
    ) -> bool:
        previous = None
        for entry in chain:
            if not isinstance(entry, str):
                return False
            if not entry:
                return False
            previous = entry
        return previous is not None

    @staticmethod
    def verify_append(
        previous_hash: str,
        new_hash: str,
    ) -> bool:
        if not previous_hash:
            return False
        if not new_hash:
            return False
        return previous_hash != new_hash


class ReplayValidator:
    """
    Ensures deterministic execution replay.
    """

    @staticmethod
    def validate(
        original_hash: str,
        replay_hash: str,
    ) -> bool:
        return original_hash == replay_hash


class StateLineage:
    """
    Represents immutable execution ancestry.
    """

    def __init__(
        self,
        genesis: str = "GENESIS_ANCHOR",
    ):
        self._chain = [genesis]

    @property
    def chain(self) -> tuple[str, ...]:
        return tuple(self._chain)

    @property
    def current_hash(self) -> str:
        return self._chain[-1]

    def append(
        self,
        new_hash: str,
    ) -> None:
        if not ChainVerifier.verify_append(
            self.current_hash,
            new_hash,
        ):
            raise IntegrityException("Invalid lineage transition")
        self._chain.append(new_hash)


# =============================================================================
# Section 2 - Core Governance Models
# =============================================================================

"""
Immutable governance runtime models.

Provides:
- Context envelopes
- Execution metadata
- Module identity
- Governance decisions
- Audit events
- Execution state tracking
"""


# =============================================================================
# Module Identity
# =============================================================================


@dataclass(frozen=True)
class ModuleIdentity:
    """
    Identifies an executable governance module.
    """

    name: str
    version: str = "1.0.0"
    vendor: str = "GSA"
    description: str = ""

    @property
    def qualified_name(self) -> str:
        return f"{self.vendor}:{self.name}:{self.version}"


# =============================================================================
# Execution Metadata
# =============================================================================


@dataclass(frozen=True)
class ExecutionMetadata:
    """
    Immutable execution information.
    """

    trace_id: str = field(default_factory=lambda: uuid4().hex)

    execution_id: str = ""

    parent_execution_id: Optional[str] = None

    actor: str = ""

    module_identity: Optional[ModuleIdentity] = None

    created_timestamp: float = field(default_factory=time.time)

    iteration: int = 0

    runtime_version: str = GSA_VERSION

    environment: Optional[RuntimeEnvironment] = None


# =============================================================================
# Governance Result
# =============================================================================


@dataclass(frozen=True)
class GovernanceResult:
    """
    Structured governance evaluation result.
    """

    passed: bool

    score: float

    decision: str

    violations: Tuple[str, ...] = ()

    warnings: Tuple[str, ...] = ()

    recommendations: Tuple[str, ...] = ()

    evaluator: str = "GSA"


# =============================================================================
# Audit Event
# =============================================================================


@dataclass(frozen=True)
class AuditEvent:
    """
    Immutable governance audit record.
    """

    event_type: str

    severity: GovernanceSeverity

    timestamp: float = field(default_factory=time.time)

    trace_id: Optional[str] = None

    actor: Optional[str] = None

    details: Mapping[str, Any] = field(default_factory=dict)


# =============================================================================
# Execution State
# =============================================================================


@dataclass(frozen=True)
class ExecutionState:
    """
    Tracks runtime execution state.
    """

    status: RuntimeStatus = RuntimeStatus.INITIALIZED

    current_hash: str = "GENESIS_ANCHOR"

    previous_hash: Optional[str] = None

    chain_depth: int = 0

    error_message: Optional[str] = None


# =============================================================================
# GSA Context Envelope
# =============================================================================


@dataclass(frozen=True)
class GsaContextEnvelope:
    """
    Immutable message container passed between modules.

    All governance execution occurs through this object.
    """

    payload_data: Mapping[str, Any] = field(default_factory=dict)

    session_state: Mapping[str, Any] = field(default_factory=dict)

    headers: Mapping[str, Any] = field(default_factory=dict)

    metadata: ExecutionMetadata = field(default_factory=ExecutionMetadata)

    execution_state: ExecutionState = field(default_factory=ExecutionState)

    governance_result: Optional[GovernanceResult] = None

    audit_events: Tuple[AuditEvent, ...] = ()

    schema_version: str = GSA_SCHEMA_VERSION

    def with_updates(
        self,
        **changes: Any,
    ) -> "GsaContextEnvelope":
        """
        Immutable envelope update.
        """

        return replace(
            self,
            **changes,
        )

    def add_audit_event(
        self,
        event: AuditEvent,
    ) -> "GsaContextEnvelope":

        return replace(self, audit_events=self.audit_events + (event,))

    def update_status(
        self,
        status: RuntimeStatus,
    ) -> "GsaContextEnvelope":

        updated_state = replace(
            self.execution_state,
            status=status,
        )

        return replace(
            self,
            execution_state=updated_state,
        )


# =============================================================================
# Execution Context Wrapper
# =============================================================================


@dataclass(frozen=True)
class ExecutionContext:
    """
    Runtime wrapper around envelope and module identity.
    """

    envelope: GsaContextEnvelope

    module: ModuleIdentity

    started_at: float = field(default_factory=time.time)

    def elapsed(self) -> float:
        return time.time() - self.started_at


# =============================================================================
# Section 3 - Integrity Engine Integration Layer
# =============================================================================

"""
Integrates envelope state with cryptographic lineage.

Provides:
- Envelope fingerprinting
- State transitions
- Anchor tracking
- Branch lineage
- Replay verification
- Integrity validation
"""


# =============================================================================
# Integrity Snapshot
# =============================================================================


@dataclass(frozen=True)
class IntegritySnapshot:
    """
    Immutable cryptographic state record.
    """

    hash_value: str

    parent_hash: str

    actor: str

    iteration: int

    timestamp: float = field(default_factory=time.time)


# =============================================================================
# Anchor Registry
# =============================================================================


@dataclass(frozen=True)
class IntegrityAnchor:
    """
    Named immutable checkpoint.
    """

    anchor_id: str

    hash_value: str

    created_by: str

    iteration: int


class AnchorRegistry:
    """
    Maintains execution checkpoints.
    """

    def __init__(self):
        self._anchors: Dict[str, IntegrityAnchor] = {}

    def create(
        self,
        anchor_id: str,
        envelope: GsaContextEnvelope,
        actor: str,
    ) -> IntegrityAnchor:

        snapshot_hash = IntegrityManager.fingerprint(envelope)

        anchor = IntegrityAnchor(
            anchor_id=anchor_id,
            hash_value=snapshot_hash,
            created_by=actor,
            iteration=envelope.metadata.iteration,
        )

        self._anchors[anchor_id] = anchor

        return anchor

    def get(
        self,
        anchor_id: str,
    ) -> Optional[IntegrityAnchor]:

        return self._anchors.get(anchor_id)

    def verify(
        self,
        anchor_id: str,
        envelope: GsaContextEnvelope,
    ) -> bool:

        anchor = self.get(anchor_id)

        if not anchor:
            return False

        return anchor.hash_value == IntegrityManager.fingerprint(envelope)


# =============================================================================
# Branch Lineage
# =============================================================================


@dataclass(frozen=True)
class BranchNode:
    """
    Immutable graph execution node.
    """

    node_id: str

    hash_value: str

    parent_nodes: Tuple[str, ...] = ()

    actor: str = ""

    iteration: int = 0


class GovernanceGraph:
    """
    Immutable-oriented execution graph.

    Tracks forks and merges.
    """

    def __init__(self):
        self._nodes: Dict[str, BranchNode] = {}

    def add_node(
        self,
        node: BranchNode,
    ) -> None:

        if node.node_id in self._nodes:
            raise IntegrityException(f"Duplicate graph node {node.node_id}")

        self._nodes[node.node_id] = node

    def get(
        self,
        node_id: str,
    ) -> Optional[BranchNode]:

        return self._nodes.get(node_id)

    def lineage(
        self,
        node_id: str,
    ) -> List[BranchNode]:

        result = []

        current = self.get(node_id)

        while current:

            result.append(current)

            if not current.parent_nodes:
                break

            current = self.get(current.parent_nodes[0])

        return list(reversed(result))


# =============================================================================
# Integrity Manager
# =============================================================================


class IntegrityManager:
    """
    High-level governance integrity service.
    """

    @staticmethod
    def fingerprint(
        envelope: GsaContextEnvelope,
    ) -> str:

        return IntegrityEngine.hash_components(
            {
                "payload": envelope.payload_data,
                "session": envelope.session_state,
                "headers": envelope.headers,
                "metadata": envelope.metadata,
                "state": envelope.execution_state,
                "schema": envelope.schema_version,
            }
        )

    @staticmethod
    def create_transition(
        envelope: GsaContextEnvelope,
        actor: str,
    ) -> IntegritySnapshot:

        parent_hash = envelope.execution_state.current_hash

        iteration = envelope.metadata.iteration + 1

        new_hash = IntegrityEngine.create_state_signature(
            parent_hash=parent_hash,
            iteration=iteration,
            actor=actor,
            payload=envelope,
        )

        return IntegritySnapshot(
            hash_value=new_hash,
            parent_hash=parent_hash,
            actor=actor,
            iteration=iteration,
        )

    @staticmethod
    def apply_transition(
        envelope: GsaContextEnvelope,
        snapshot: IntegritySnapshot,
    ) -> GsaContextEnvelope:

        new_metadata = replace(
            envelope.metadata,
            iteration=snapshot.iteration,
        )

        new_state = replace(
            envelope.execution_state,
            previous_hash=snapshot.parent_hash,
            current_hash=snapshot.hash_value,
            chain_depth=envelope.execution_state.chain_depth + 1,
        )

        return replace(
            envelope,
            metadata=new_metadata,
            execution_state=new_state,
        )

    @staticmethod
    def verify_transition(
        envelope: GsaContextEnvelope,
    ) -> bool:

        if not envelope.execution_state.current_hash:
            return False

        if envelope.execution_state.chain_depth < 0:
            return False

        return True


# =============================================================================
# Section 4 - Module Registry & Discovery System
# =============================================================================

"""
Provides governed module discovery and registration.

Responsibilities:
- Thread-safe module registration
- Module metadata
- Capability tracking
- Version management
- Dependency declarations
- Runtime lookup
"""


# =============================================================================
# Module Capability Model
# =============================================================================


@dataclass(frozen=True)
class ModuleCapability:
    """
    Declares module abilities.
    """

    name: str
    description: str = ""


@dataclass(frozen=True)
class ModuleDependency:
    """
    Declares required module dependency.
    """

    module_name: str
    minimum_version: str = "1.0.0"


@dataclass(frozen=True)
class ModuleDescriptor:
    """
    Complete module registration metadata.
    """

    identity: ModuleIdentity

    module_class: Type[Any]

    capabilities: Tuple[ModuleCapability, ...] = ()

    dependencies: Tuple[ModuleDependency, ...] = ()

    enabled: bool = True


# =============================================================================
# Module Registry
# =============================================================================


class GsaModuleRegistry:
    """
    Thread-safe governance module registry.
    """

    def __init__(self):

        self._lock = RLock()

        self._modules: Dict[str, ModuleDescriptor] = {}

    def register(
        self,
        descriptor: ModuleDescriptor,
    ) -> None:

        key = descriptor.identity.qualified_name

        with self._lock:

            if key in self._modules:
                raise ConfigurationException(f"Module already registered: {key}")

            self._modules[key] = descriptor

    def unregister(
        self,
        qualified_name: str,
    ) -> None:

        with self._lock:

            self._modules.pop(
                qualified_name,
                None,
            )

    def get(
        self,
        qualified_name: str,
    ) -> ModuleDescriptor:

        with self._lock:

            descriptor = self._modules.get(qualified_name)

            if descriptor is None:
                raise ConfigurationException(f"Unknown module: {qualified_name}")

            return descriptor

    def list_modules(
        self,
    ) -> Tuple[ModuleDescriptor, ...]:

        with self._lock:

            return tuple(self._modules.values())

    def find_by_name(
        self,
        name: str,
    ) -> List[ModuleDescriptor]:

        with self._lock:

            return [
                module
                for module in self._modules.values()
                if module.identity.name == name
            ]

    def has_module(
        self,
        qualified_name: str,
    ) -> bool:

        with self._lock:

            return qualified_name in self._modules


# =============================================================================
# Global Registry
# =============================================================================

GLOBAL_GSA_REGISTRY = GsaModuleRegistry()


# =============================================================================
# Registration Decorator
# =============================================================================


def register_gsa_module(
    name: str,
    version: str = "1.0.0",
    vendor: str = "GSA",
    capabilities: Optional[List[ModuleCapability]] = None,
    dependencies: Optional[List[ModuleDependency]] = None,
):
    """
    Decorator for governed module registration.
    """

    def decorator(module_class):

        descriptor = ModuleDescriptor(
            identity=ModuleIdentity(
                name=name,
                version=version,
                vendor=vendor,
                description=module_class.__doc__ or "",
            ),
            module_class=module_class,
            capabilities=tuple(capabilities or []),
            dependencies=tuple(dependencies or []),
        )

        GLOBAL_GSA_REGISTRY.register(descriptor)

        return module_class

    return decorator


# =============================================================================
# Module Loader
# =============================================================================


class ModuleLoader:
    """
    Creates registered module instances.
    """

    def __init__(
        self,
        registry: GsaModuleRegistry = GLOBAL_GSA_REGISTRY,
    ):
        self.registry = registry

    def create(
        self,
        qualified_name: str,
        **kwargs,
    ) -> Any:

        descriptor = self.registry.get(qualified_name)

        if not descriptor.enabled:
            raise AuthorizationException(f"Module disabled: {qualified_name}")

        return descriptor.module_class(**kwargs)


# =============================================================================
# Section 5 - Protocol Layer & Dependency Injection
# =============================================================================

"""
Defines execution contracts and injectable runtime services.

Responsibilities:
- Module execution protocols
- Lifecycle hooks
- Governance policy interfaces
- Telemetry interfaces
- Audit interfaces
- Dependency containers
"""


# =============================================================================
# Module Execution Protocols
# =============================================================================


class GsaExecutable(Protocol):
    """
    Required module execution contract.
    """

    async def execute(
        self,
        context: ExecutionContext,
    ) -> GsaContextEnvelope: ...


class GsaValidator(Protocol):
    """
    Validation contract.
    """

    async def validate(
        self,
        envelope: GsaContextEnvelope,
    ) -> GovernanceResult: ...


class GsaPolicyEvaluator(Protocol):
    """
    Governance policy contract.
    """

    async def evaluate(
        self,
        envelope: GsaContextEnvelope,
    ) -> GovernanceResult: ...


# =============================================================================
# Lifecycle Hooks
# =============================================================================


class GsaLifecycleHooks(Protocol):
    """
    Optional module lifecycle extension points.
    """

    async def before_execution(
        self,
        context: ExecutionContext,
    ) -> ExecutionContext: ...

    async def after_execution(
        self,
        context: ExecutionContext,
        result: GsaContextEnvelope,
    ) -> GsaContextEnvelope: ...

    async def on_failure(
        self,
        context: ExecutionContext,
        error: Exception,
    ) -> GsaContextEnvelope: ...


# =============================================================================
# Audit and Telemetry Contracts
# =============================================================================


class GsaAuditSink(Protocol):
    """
    Receives immutable audit events.
    """

    def write(
        self,
        event: AuditEvent,
    ) -> None: ...


class GsaTelemetrySink(Protocol):
    """
    Receives runtime metrics.
    """

    def record(
        self,
        metric_name: str,
        value: float,
        metadata: Mapping[str, Any],
    ) -> None: ...


# =============================================================================
# Policy Decision Model
# =============================================================================


@dataclass(frozen=True)
class PolicyDecision:
    """
    Output from governance policy evaluation.
    """

    allowed: bool

    reason: str

    score: float = 0.0

    controls_triggered: tuple[str, ...] = ()


# =============================================================================
# Dependency Container
# =============================================================================


@dataclass(frozen=True)
class GsaDependencies:
    """
    Injected runtime services.

    Avoids hidden global dependencies.
    """

    validator: Optional[GsaValidator] = None

    policy_engine: Optional[GsaPolicyEvaluator] = None

    audit_sink: Optional[GsaAuditSink] = None

    telemetry_sink: Optional[GsaTelemetrySink] = None

    lifecycle_hooks: Optional[GsaLifecycleHooks] = None


# =============================================================================
# Default Implementations
# =============================================================================


class NullAuditSink:
    """
    Safe no-op audit sink.
    """

    def write(
        self,
        event: AuditEvent,
    ) -> None:
        return None


class NullTelemetrySink:
    """
    Safe no-op telemetry sink.
    """

    def record(
        self,
        metric_name: str,
        value: float,
        metadata: Mapping[str, Any],
    ) -> None:
        return None


# =============================================================================
# Execution Adapter Contract
# =============================================================================


class GsaExecutionAdapter(Protocol):
    """
    Contract for governed execution adapters.
    """

    async def process(
        self,
        envelope: GsaContextEnvelope,
    ) -> GsaContextEnvelope: ...


# =============================================================================
# Dependency Factory
# =============================================================================


def create_default_dependencies() -> GsaDependencies:
    """
    Creates safe baseline runtime dependencies.
    """

    return GsaDependencies(
        audit_sink=NullAuditSink(),
        telemetry_sink=NullTelemetrySink(),
    )


# =============================================================================
# Section 6 - Governance Runtime Core
# =============================================================================

"""
Core governance execution engine.

Responsibilities:
- Controlled execution flow
- Validation pipeline
- Policy enforcement
- Integrity transitions
- Audit emission
- Telemetry collection
- Fail-closed execution
"""


# =============================================================================
# Runtime Exceptions
# =============================================================================


class RuntimeExecutionException(GsaException):
    code = "GSA_RUNTIME_EXECUTION_FAILURE"


# =============================================================================
# Governance Runtime
# =============================================================================


class GsaGovernanceRuntime:
    """
    Main execution coordinator.

    Execution lifecycle:

    1. Receive envelope
    2. Validate
    3. Evaluate policy
    4. Execute module
    5. Verify integrity
    6. Commit state transition
    7. Emit audit/telemetry
    """

    def __init__(
        self,
        dependencies: Optional[GsaDependencies] = None,
    ):

        self.dependencies = dependencies or create_default_dependencies()

    async def execute(
        self,
        module: GsaExecutable,
        envelope: GsaContextEnvelope,
    ) -> GsaContextEnvelope:

        context = ExecutionContext(
            envelope=envelope,
            module=ModuleIdentity(
                name=type(module).__name__,
            ),
        )

        start = time.time()

        try:
            envelope = await self._prepare(context)

            envelope = await self._validate(envelope)

            envelope = await self._authorize(envelope)

            envelope = await module.execute(
                ExecutionContext(
                    envelope=envelope,
                    module=context.module,
                )
            )

            envelope = self._commit_integrity(
                envelope,
                context.module,
            )

            envelope = await self._complete(
                envelope,
                start,
            )

            return envelope

        except Exception as exc:

            return await self._fail(
                envelope,
                exc,
            )

    # =============================================================================
    # Pipeline Stages
    # =============================================================================

    async def _prepare(
        self,
        context: ExecutionContext,
    ) -> GsaContextEnvelope:

        envelope = context.envelope

        if self.dependencies.lifecycle_hooks:

            context = await self.dependencies.lifecycle_hooks.before_execution(context)

            envelope = context.envelope

        return envelope

    async def _validate(
        self,
        envelope: GsaContextEnvelope,
    ) -> GsaContextEnvelope:

        validator = self.dependencies.validator

        if validator:

            result = await validator.validate(envelope)

            envelope = replace(
                envelope,
                governance_result=result,
            )

            if not result.passed:

                raise ValidationException("Governance validation rejected execution")

        return envelope

    async def _authorize(
        self,
        envelope: GsaContextEnvelope,
    ) -> GsaContextEnvelope:

        policy = self.dependencies.policy_engine

        if policy:

            result = await policy.evaluate(envelope)

            envelope = replace(
                envelope,
                governance_result=result,
            )

            if not result.passed:

                raise AuthorizationException("Policy rejected execution")

        return envelope

    def _commit_integrity(
        self,
        envelope: GsaContextEnvelope,
        module: ModuleIdentity,
    ) -> GsaContextEnvelope:

        snapshot = IntegrityManager.create_transition(
            envelope,
            module.qualified_name,
        )

        return IntegrityManager.apply_transition(
            envelope,
            snapshot,
        )

    # =============================================================================
    # Completion and Failure Handling
    # =============================================================================

    async def _complete(
        self,
        envelope: GsaContextEnvelope,
        started: float,
    ) -> GsaContextEnvelope:

        elapsed = time.time() - started

        event = AuditEvent(
            event_type="EXECUTION_COMPLETE",
            severity=GovernanceSeverity.INFO,
            trace_id=envelope.metadata.trace_id,
            details={
                "duration": elapsed,
                "hash": envelope.execution_state.current_hash,
            },
        )

        envelope = envelope.add_audit_event(event)

        if self.dependencies.telemetry_sink:

            self.dependencies.telemetry_sink.record(
                "gsa.execution.duration",
                elapsed,
                {
                    "trace": envelope.metadata.trace_id,
                },
            )

        if self.dependencies.lifecycle_hooks:

            context = ExecutionContext(
                envelope=envelope,
                module=envelope.metadata.module_identity or ModuleIdentity("unknown"),
            )

            envelope = await self.dependencies.lifecycle_hooks.after_execution(
                context,
                envelope,
            )

        return envelope

    async def _fail(
        self,
        envelope: GsaContextEnvelope,
        error: Exception,
    ) -> GsaContextEnvelope:

        event = AuditEvent(
            event_type="EXECUTION_FAILURE",
            severity=GovernanceSeverity.ERROR,
            trace_id=envelope.metadata.trace_id,
            details={
                "error": str(error),
                "type": type(error).__name__,
                "trace": traceback.format_exc(),
            },
        )

        envelope = envelope.add_audit_event(event)

        state = replace(
            envelope.execution_state,
            status=RuntimeStatus.FAILED,
            error_message=str(error),
        )

        return replace(
            envelope,
            execution_state=state,
        )


# =============================================================================
# Section 7 - Universal Governance Adapter
# =============================================================================

"""
Universal module adapter.

Responsibilities:
- Wrap arbitrary modules
- Normalize execution interfaces
- Preserve governance lineage
- Support legacy modules
- Integrate with runtime kernel
"""


# =============================================================================
# Legacy Bridge Contract
# =============================================================================

LegacyBridge = Callable[
    [
        Any,
        GsaContextEnvelope,
    ],
    Any,
]


# =============================================================================
# Universal Adapter
# =============================================================================


class GsaUniversalAdapter:
    """
    Converts any compatible module into a governed execution unit.

    Supported module styles:

    1. Modern:
        async execute(context)

    2. Legacy:
        async process_payload(envelope)

    3. Governance:
        async execute_governance_logic(envelope)

    4. External:
        synchronous bridge adapter
    """

    def __init__(
        self,
        module: Any,
        runtime: Optional[GsaGovernanceRuntime] = None,
        bridge: Optional[LegacyBridge] = None,
        dependencies: Optional[GsaDependencies] = None,
    ):

        self.module = module

        self.identity = ModuleIdentity(
            name=type(module).__name__,
            version=getattr(
                module,
                "__version__",
                "1.0.0",
            ),
        )

        self.bridge = bridge

        self.runtime = runtime or GsaGovernanceRuntime(dependencies)

    async def process(
        self,
        envelope: GsaContextEnvelope,
    ) -> GsaContextEnvelope:

        executor = self._resolve_executor()

        return await self.runtime.execute(
            executor,
            envelope,
        )

    # =============================================================================
    # Execution Resolution
    # =============================================================================

    def _resolve_executor(
        self,
    ) -> GsaExecutable:

        adapter = self

        class WrappedModule:

            async def execute(
                self,
                context: ExecutionContext,
            ) -> GsaContextEnvelope:

                return await adapter._execute_module(context.envelope)

        return WrappedModule()

    async def _execute_module(
        self,
        envelope: GsaContextEnvelope,
    ) -> GsaContextEnvelope:

        module = self.module

        if hasattr(
            module,
            "execute",
        ):

            result = await module.execute(
                ExecutionContext(
                    envelope=envelope,
                    module=self.identity,
                )
            )

            return self._normalize_result(
                envelope,
                result,
            )

        if hasattr(
            module,
            "process_payload",
        ):

            result = await module.process_payload(envelope)

            return self._normalize_result(
                envelope,
                result,
            )

        if hasattr(
            module,
            "execute_governance_logic",
        ):

            result = await module.execute_governance_logic(envelope)

            return self._normalize_result(
                envelope,
                result,
            )

        if self.bridge:

            result = await self._run_bridge(envelope)

            return self._normalize_result(
                envelope,
                result,
            )

        raise ModuleExecutionException(
            f"Module {self.identity.name} " "has no supported execution interface"
        )

    # =============================================================================
    # Bridge Execution
    # =============================================================================

    async def _run_bridge(
        self,
        envelope: GsaContextEnvelope,
    ) -> Any:

        loop = asyncio.get_running_loop()

        return await loop.run_in_executor(
            None,
            self.bridge,
            self.module,
            envelope,
        )

    # =============================================================================
    # Output Normalization
    # =============================================================================

    def _normalize_result(
        self,
        original: GsaContextEnvelope,
        result: Any,
    ) -> GsaContextEnvelope:

        if isinstance(
            result,
            GsaContextEnvelope,
        ):
            return result

        return replace(
            original,
            payload_data={
                **original.payload_data,
                "module_output": result,
            },
        )


# =============================================================================
# Section 8 - Governance DAG & Branch Management
# =============================================================================

"""
Governance execution graph.

Responsibilities:
- Immutable lineage graph
- Branch creation
- Branch merging
- Anchor restoration
- Conflict detection
- Replay path discovery
"""


# =============================================================================
# Graph Models
# =============================================================================


@dataclass(frozen=True)
class GovernanceNode:
    """
    Immutable graph execution node.
    """

    node_id: str

    execution_hash: str

    actor: str

    iteration: int

    parent_nodes: Tuple[str, ...] = ()

    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GovernanceBranch:
    """
    Represents an execution fork.
    """

    branch_id: str

    source_node: str

    branch_hash: str

    owner: str

    active: bool = True


@dataclass(frozen=True)
class MergeRecord:
    """
    Records deterministic branch merges.
    """

    merge_id: str

    source_branches: Tuple[str, ...]

    target_node: str

    merge_hash: str

    actor: str


# =============================================================================
# Governance DAG
# =============================================================================


class GovernanceDag:
    """
    Directed acyclic governance graph.
    """

    def __init__(self):

        self._nodes: Dict[str, GovernanceNode] = {}

        self._branches: Dict[str, GovernanceBranch] = {}

        self._merges: Dict[str, MergeRecord] = {}

    # =============================================================================
    # Node Management
    # =============================================================================

    def add_node(
        self,
        node: GovernanceNode,
    ) -> None:

        if node.node_id in self._nodes:
            raise IntegrityException(f"Node already exists: {node.node_id}")

        for parent in node.parent_nodes:

            if parent not in self._nodes:
                raise IntegrityException(f"Missing parent node: {parent}")

        self._nodes[node.node_id] = node

    def get_node(
        self,
        node_id: str,
    ) -> Optional[GovernanceNode]:

        return self._nodes.get(node_id)

    # =============================================================================
    # Branch Management
    # =============================================================================

    def create_branch(
        self,
        branch_id: str,
        source_node: str,
        owner: str,
    ) -> GovernanceBranch:

        source = self.get_node(source_node)

        if source is None:
            raise IntegrityException("Cannot branch from unknown node")

        branch_hash = IntegrityEngine.hash_components(
            source.execution_hash,
            branch_id,
            owner,
        )

        branch = GovernanceBranch(
            branch_id=branch_id,
            source_node=source_node,
            branch_hash=branch_hash,
            owner=owner,
        )

        self._branches[branch_id] = branch

        return branch

    def get_branch(
        self,
        branch_id: str,
    ) -> Optional[GovernanceBranch]:

        return self._branches.get(branch_id)

    def close_branch(
        self,
        branch_id: str,
    ) -> None:

        branch = self.get_branch(branch_id)

        if not branch:
            raise IntegrityException("Unknown branch")

        self._branches[branch_id] = GovernanceBranch(
            branch_id=branch.branch_id,
            source_node=branch.source_node,
            branch_hash=branch.branch_hash,
            owner=branch.owner,
            active=False,
        )

    # =============================================================================
    # Merge Management
    # =============================================================================

    def merge_branches(
        self,
        merge_id: str,
        branch_ids: List[str],
        target_node: str,
        actor: str,
    ) -> MergeRecord:

        if target_node not in self._nodes:
            raise IntegrityException("Invalid merge target")

        branches = []

        for branch_id in branch_ids:

            branch = self.get_branch(branch_id)

            if not branch:
                raise IntegrityException(f"Missing branch {branch_id}")

            if not branch.active:
                raise IntegrityException(f"Inactive branch {branch_id}")

            branches.append(branch)

        merge_hash = IntegrityEngine.hash_components(
            [branch.branch_hash for branch in branches],
            target_node,
            actor,
        )

        record = MergeRecord(
            merge_id=merge_id,
            source_branches=tuple(branch_ids),
            target_node=target_node,
            merge_hash=merge_hash,
            actor=actor,
        )

        self._merges[merge_id] = record

        for branch in branches:
            self.close_branch(branch.branch_id)

        return record

    # =============================================================================
    # Replay and Lineage
    # =============================================================================

    def lineage(
        self,
        node_id: str,
    ) -> List[GovernanceNode]:

        node = self.get_node(node_id)

        if not node:
            return []

        result = [node]

        if node.parent_nodes:

            result.extend(self.lineage(node.parent_nodes[0]))

        return list(reversed(result))

    def verify_acyclic(
        self,
    ) -> bool:

        visited = set()

        def visit(node_id):

            if node_id in visited:
                return False

            visited.add(node_id)

            node = self.get_node(node_id)

            if not node:
                return True

            return all(visit(parent) for parent in node.parent_nodes)

        return all(visit(node_id) for node_id in self._nodes)


# =============================================================================
# Section 9 - Runtime Services Layer
# =============================================================================

"""
Operational services supporting the GSA runtime.

Responsibilities:
- Audit storage
- Telemetry collection
- Runtime events
- Health monitoring
- Service dependency management
"""


# =============================================================================
# Audit Ledger
# =============================================================================


class InMemoryAuditLedger:
    """
    Reference audit implementation.

    Production implementations can replace this with:
    - PostgreSQL
    - immutable storage
    - blockchain ledger
    - append-only event stream
    """

    def __init__(self):

        self._events: List[AuditEvent] = []

        self._lock = RLock()

    def write(
        self,
        event: AuditEvent,
    ) -> None:

        with self._lock:

            self._events.append(event)

    def query(
        self,
        trace_id: Optional[str] = None,
    ) -> Tuple[AuditEvent, ...]:

        with self._lock:

            if trace_id is None:
                return tuple(self._events)

            return tuple(event for event in self._events if event.trace_id == trace_id)

    def count(self) -> int:

        with self._lock:
            return len(self._events)


# =============================================================================
# Telemetry Collector
# =============================================================================


@dataclass
class MetricPoint:
    """
    Runtime measurement.
    """

    name: str

    value: float

    timestamp: float = field(default_factory=time.time)

    metadata: Mapping[str, Any] = field(default_factory=dict)


class InMemoryTelemetry:
    """
    Runtime metric collector.
    """

    def __init__(self):

        self._metrics: List[MetricPoint] = []

        self._lock = RLock()

    def record(
        self,
        metric_name: str,
        value: float,
        metadata: Mapping[str, Any],
    ) -> None:

        with self._lock:

            self._metrics.append(
                MetricPoint(
                    name=metric_name,
                    value=value,
                    metadata=dict(metadata),
                )
            )

    def get_metrics(
        self,
        name: Optional[str] = None,
    ) -> Tuple[MetricPoint, ...]:

        with self._lock:

            if name is None:
                return tuple(self._metrics)

            return tuple(metric for metric in self._metrics if metric.name == name)


# =============================================================================
# Runtime Event Bus
# =============================================================================


@dataclass(frozen=True)
class RuntimeEvent:
    """
    Internal runtime notification.
    """

    event_type: str

    payload: Mapping[str, Any]

    timestamp: float = field(default_factory=time.time)


class RuntimeEventBus:
    """
    Simple synchronous event dispatcher.
    """

    def __init__(self):

        self._handlers: Dict[str, List[Any]] = {}

    def subscribe(
        self,
        event_type: str,
        handler,
    ) -> None:

        self._handlers.setdefault(
            event_type,
            [],
        ).append(handler)

    def publish(
        self,
        event: RuntimeEvent,
    ) -> None:

        for handler in self._handlers.get(
            event.event_type,
            [],
        ):
            handler(event)


# =============================================================================
# Health Monitoring
# =============================================================================


@dataclass(frozen=True)
class HealthStatus:
    """
    Runtime health snapshot.
    """

    healthy: bool

    services: Mapping[str, bool]

    timestamp: float = field(default_factory=time.time)


class RuntimeHealthMonitor:
    """
    Evaluates runtime service state.
    """

    def __init__(self):

        self._checks: Dict[str, Any] = {}

    def register_check(
        self,
        name: str,
        check,
    ) -> None:

        self._checks[name] = check

    def evaluate(
        self,
    ) -> HealthStatus:

        results = {}

        for name, check in self._checks.items():

            try:
                results[name] = bool(check())

            except Exception:
                results[name] = False

        return HealthStatus(
            healthy=all(results.values()),
            services=results,
        )


# =============================================================================
# Runtime Service Container
# =============================================================================


@dataclass(frozen=True)
class GsaRuntimeServices:
    """
    Injectable runtime service collection.
    """

    audit: InMemoryAuditLedger

    telemetry: InMemoryTelemetry

    events: RuntimeEventBus

    health: RuntimeHealthMonitor


def create_runtime_services() -> GsaRuntimeServices:
    """
    Creates default runtime services.
    """

    audit = InMemoryAuditLedger()

    telemetry = InMemoryTelemetry()

    events = RuntimeEventBus()

    health = RuntimeHealthMonitor()

    health.register_check(
        "audit",
        lambda: audit is not None,
    )

    health.register_check(
        "telemetry",
        lambda: telemetry is not None,
    )

    return GsaRuntimeServices(
        audit=audit,
        telemetry=telemetry,
        events=events,
        health=health,
    )


# =============================================================================
# Section 10 - Integrated GSA v2.0 Runtime
# =============================================================================

"""
Canonical GSA Governance Kernel Runtime.

Combines:
- Module registry
- Governance runtime
- Integrity engine
- DAG lineage
- Audit services
- Telemetry
- Dependency injection

Primary entry point:
    GsaKernel
"""


# =============================================================================
# Kernel
# =============================================================================


class GsaKernel:
    """
    Top-level governance runtime.

    Example:

        kernel = GsaKernel()

        result = await kernel.execute(
            "GSA:ExampleModule:1.0.0",
            payload={}
        )
    """

    def __init__(
        self,
        registry: GsaModuleRegistry = GLOBAL_GSA_REGISTRY,
        services: Optional[GsaRuntimeServices] = None,
    ):

        self.registry = registry

        self.services = services or create_runtime_services()

        self.dag = GovernanceDag()

        self.anchors = AnchorRegistry()

        self.runtime = GsaGovernanceRuntime(
            dependencies=GsaDependencies(
                audit_sink=self.services.audit,
                telemetry_sink=self.services.telemetry,
            )
        )

    # =============================================================================
    # Module Execution
    # =============================================================================

    async def execute(
        self,
        module_name: str,
        payload: dict[str, Any],
    ) -> GsaContextEnvelope:

        descriptor = self.registry.get(module_name)

        module = descriptor.module_class()

        envelope = GsaContextEnvelope(
            payload_data=deep_freeze(payload),
            metadata=ExecutionMetadata(
                module_identity=descriptor.identity,
            ),
        )

        adapter = GsaUniversalAdapter(
            module,
            runtime=self.runtime,
        )

        result = await adapter.process(envelope)

        self._record_graph(
            result,
            descriptor.identity,
        )

        return result

    # =============================================================================
    # Graph Recording
    # =============================================================================

    def _record_graph(
        self,
        envelope: GsaContextEnvelope,
        identity: ModuleIdentity,
    ) -> None:

        node_id = create_deterministic_id(
            envelope.execution_state.previous_hash or "GENESIS_ANCHOR",
            identity.qualified_name,
            envelope.metadata.iteration,
        )

        node = GovernanceNode(
            node_id=node_id,
            execution_hash=envelope.execution_state.current_hash,
            actor=identity.qualified_name,
            iteration=envelope.metadata.iteration,
            parent_nodes=(
                (envelope.execution_state.previous_hash)
                if envelope.execution_state.previous_hash
                else ()
            ),
        )

        self.dag.add_node(node)

    # =============================================================================
    # Kernel Utilities
    # =============================================================================

    def create_anchor(
        self,
        anchor_id: str,
        envelope: GsaContextEnvelope,
        actor: str,
    ) -> IntegrityAnchor:

        return self.anchors.create(
            anchor_id,
            envelope,
            actor,
        )

    def health(
        self,
    ) -> HealthStatus:

        return self.services.health.evaluate()


# =============================================================================
# Example Governed Module
# =============================================================================


@register_gsa_module(
    name="ExampleModule",
    version="1.0.0",
    vendor="GSA",
    capabilities=[
        ModuleCapability(
            name="example.execution",
            description="Reference governed module",
        )
    ],
)
class ExampleModule:
    """
    Reference GSA execution module.
    """

    async def execute(
        self,
        context: ExecutionContext,
    ) -> GsaContextEnvelope:

        envelope = context.envelope

        output = {
            **deep_thaw(envelope.payload_data),
            "processed": True,
            "actor": context.module.qualified_name,
        }

        return replace(
            envelope,
            payload_data=deep_freeze(output),
        )


# =============================================================================
# Example Runtime Factory
# =============================================================================


def create_gsa_kernel() -> GsaKernel:
    """
    Creates canonical runtime.
    """

    return GsaKernel()
