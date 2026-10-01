# Attestation Event Schema — Compatibility Contract

This document defines the **public compatibility contract** for attestation events
emitted by the escrow contract and validated by
`escrow/src/tests/attestation_event_schema.rs`.

Any change to the fields, ordering, or encoding below is a **breaking change** and
must ship with a tested migration path. The focused tests in
`attestation_event_schema.rs` are the executable source of truth for this contract;
this document explains the invariants those tests protect.

## Event shape

An attestation event is a fixed, ordered tuple of fields. Consumers (indexers,
clients, downstream contracts) rely on this exact shape:

| Position | Field        | Type   | Invariant                                                        |
|----------|--------------|--------|------------------------------------------------------------------|
| 0        | `event_type` | symbol | Always the attestation event discriminator; never empty.         |
| 1        | `escrow_id`  | u64    | Identifies the escrow; stable across retries.                    |
| 2        | `attestor`   | address| The authorized attestor that produced the event.                |
| 3        | `payload`    | bytes  | Opaque attestation payload; may be empty but never truncated.    |
| 4        | `timestamp`  | u64    | Monotonic per escrow; never decreases for a given escrow.        |

## Determinism guarantees

- **Valid input** produces exactly one event with the field values above, in order.
- **Invalid input** (missing/unauthorized attestor, malformed payload) is rejected
  before any event is emitted; no partial event is written.
- **Duplicate input** (same `escrow_id` + `attestor` + `payload`) is idempotent: it
  must not emit a second event or mutate state twice.
- **Boundary input** (empty payload, max `u64` ids/timestamps) is handled without
  overflow, truncation, or panic.

## Invariants preserved through failure

- Authorization is checked before emission; an unauthorized caller cannot produce
  an event even under retries or concurrent execution.
- State transitions are atomic: an event is emitted only if the corresponding state
  change succeeds, and vice versa.
- Retries and partial failures cannot produce an unsafe or inconsistent result —
  re-running a rejected or duplicate operation leaves state unchanged.

## Observability

Failures surface a diagnosable, non-sensitive error (reason code + escrow id).
Attestor addresses and payload contents are never logged in error paths.

## Compatibility

Existing callers remain compatible as long as the field order and types above are
unchanged. If a field must change, add a new versioned event type rather than
mutating this one, and provide a tested migration path for consumers.
