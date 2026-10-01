use soroban_sdk::contracterror;

/// Error codes for the Liquifact escrow contract.
///
/// ## Deterministic failure recovery invariants

///
/// The escrow mutates persistent state and invokes external token contracts.
/// Any operation that can partially complete must be recoverable and
/// observable. To make recovery deterministic, the error taxonomy separates:
///
/// - **Permanent rejections**: invalid input, authorization failures,
///   invariant violations. Retrying with the same arguments will always
///   fail the same way; callers must change inputs or state.
/// - **Transient / recoverable failures**: dependency (token) failures or in
///   flight concurrency contention. These carry a stable code so clients
///   can retry with backoff without guessing whether state was mutated.
/// - **Partial completion markers**: distinct codes for the case where a
///   multi-step operation may have applied some but not all of its effects.
///   These codes tell the caller to re-read state before retrying.
///
/// Every variant is explicitly numbered and numbers are never reused or
/// reordered, because clients and off-chain monitoring depend on them being
/// stable across deployments.

#[contracterror]
#derive(Copy, Clone, Debug, Eq, PartialE, Ord, PartialOrd)]
#[repr(u32)]
pub enum EscrowError {
    // ----------------------------------------------------------------------------
    // Initialization & State Errors (1..19)
    // ----------------------------------------------------------------------------
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidStatus = 3,
    EscrowExpired = 4,

    // ----------------------------------------------------------------------------
    // Authorization & Admin Errors (20..35)
    // ----------------------------------------------------------------------------
    Unauthorized = 20,
    AdminAlreadySet = 21,
    PendingAdminNotFound = 22,
    AdminTransferTimelockNotElapsed = 23,
    EmptyRecoveryReason = 24,

    // ----------------------------------------------------------------------------
    // Token / SEP-41 Safety Wrapper Errors (36..45)
    // ----------------------------------------------------------------------------
    FundingTokenTransferFailed = 36,
    BalanceMismatchAfterTransfer = 37,
    NonPositiveTransferAmount = 38,
    TokenBalanceUnderflow = 39,
    TokenBalanceOverflow = 40,
    TokenWrapperInvariantViolation = 41,
    /// The token contract reported success but the observed balance did not
    /// change by the expected delta. This is a permanent invariant failure:
    /// retrying the same operation with the same inputs will fail again.
    TokenWrapperDeltaMismatch = 42,
    /// The token contract returned a failure that is classified as transient
    /// (e.g. temporary liquidity or non-ceding condition). Callers may retry
    /// with backoff; no escrow state was mutated.
    TokenWrapperTransientFailure = 43,
    /// The token contract returned a failure that is classified as permanent
    /// (e.g. insufficient balance, frozen account). Retrying without changing
    /// inputs or state will fail again.
    TokenWrapperPermanentFailure = 44,
    /// A multi-step token operation partially completed (for example, a batch
    /// transfer where some legs succeeded and one failed). The caller must
    /// re-read state before retrying; the error is recoverable but not
    /// idempotent without a reconciliation step.
    TokenPartialTransfer = 45,

    // ----------------------------------------------------------------------------
    // Funding & Contribution Errors (50..69)
    // ----------------------------------------------------------------------------
    FundingTargetExceeded = 50,
    ZeroContributionAmount = 51,
    InvestorCapReached = 52,
    BelowMinContributionFloor = 53,
    FundingClosed = 54,
    /// Mutation of SME/beneficiary address is forbidden once any principal has been
    /// recorded for the escrow instance. This preserves auditability of payout
    /// destination for funded escrows.
    BeneficiaryImmutableAfterFunding = 55,
    /// Registry/reference metadata may not be rebound after funding begins; this
    /// prevents changing off-chain pointers that clients use to reconcile identity.
    RegistryImmutableAfterFunding = 56,

    // ----------------------------------------------------------------------------
    // Batch Operations Errors (80..89)
    // ----------------------------------------------------------------------------
    FundingBatchEmpty = 80,
    FundingBatchExceedsLimit = 81,
    FundingBatchInvalidAmount = 82,
    FundingBatchDuplicateInvestor = 84,

    ClaimBatchEmpty = 85,
    ClaimBatchExceedsLimit = 86,
    /// A claim batch was partially applied before a failure. The caller must
    /// re-read claim state and resume from the last unclaimed entry.
    ClaimBatchPartialCompletion = 87,

    // ----------------------------------------------------------------------------
    // Migration & Upgrade Errors (90..99)
    // ----------------------------------------------------------------------------
    MigrationVersionMismatch = 90,
    AlreadyCurrentSchemaVersion = 91,
    NoMigrationPath = 92,
    /// A migration was interrupted midway. The contract must be resumed from
    /// the last committed step; re-running completed steps is safe because
    /// migration steps are idempotent.
    MigrationInterrupted = 93,

    // ----------------------------------------------------------------------------
    // Settlement & Bounds Validation Errors (100..109)
    // ----------------------------------------------------------------------------
    SettlementAmountInvalid = 100,
    MaturityNotReached = 101,
    EscrowNotInFundedState = 102,
    WithdrawAmountInvalid = 103,
    /// A settlement was partially executed. The caller must re-read settlement
    /// state and resume remaining legs; already-settled legs are skipped.
    SettlementPartialCompletion = 104,

    // ----------------------------------------------------------------------------
    // Legal Hold & Operational Pause (200..209)
    // ----------------------------------------------------------------------------
    LegalHoldActive = 200,
    ContractPaused = 201,

    // ----------------------------------------------------------------------------
    // SME Collateral Errors (300..309)
    // ----------------------------------------------------------------------------
    NoCollateralToClear = 300,

    // ----------------------------------------------------------------------------
    // Pause Configuration & Rate-Limit Errors (230..239)
    // ----------------------------------------------------------------------------
    /// `LiquifactEscrow::set_pause_max_duration` received a duration outside
    /// `MIN_PAUSE_MAX_DURATION_SECS`..=[`MAX_PAUSE_MAX_DURATION_SECS`. Zero is always allowed.
    PauseMaxDurationOutOfRange = 230,
    /// `LiquifactEscrow::set_pause_rate_limit` received a toggle limit outside
    /// `MIN_PAUSE_TOGGLE_LIMIT`..=[`MAX_PAUSE_TOGGLE_LIMIT`. Zero is allowed only with zero window.
    PauseToggleLimitOutOfRange = 231,
    /// `LiquifactEscrow::set_pause_rate_limit` received a window outside
    /// `MIN_PAUSE_TOGGLE_WINDOW_SECS`..=[`MAX_PAUSE_TOGGLE_WINDOW_SECS`. Zero is allowed only with zero toggles.
    PauseToggleWindowOutOfRange = 232,
    /// `LiquifactEscrow::set_pause_rate_limit` received an inconsistent configuration:
    /// nonzero toggles must have a nonzero window, and nonzero window must have nonzero toggles.
    PauseRateLimitInvalidCombination = 233,
    /// `LiquifactEscrow::set_paused` blocked because the admin has exceeded the configured pause toggle rate limit.
    PauseToggleRateLimitExceeded = 234,

    // ----------------------------------------------------------------------------
    // Fee Schedule Errors (240..249)
    // ----------------------------------------------------------------------------
    /// `LiquifactEscrow::set_fee_schedule` received a fee outside the schedule's declared min/max bounds.
    FeeScheduleOutOfBounds = 240,
    /// `LiquifactEscrow::set_fee_schedule` attempted to create a second pending schedule before the first activates.
    FeeCheduleAlreadyPending = 241,
    /// `LiquifactEscrow::set_fee_schedule` received an activation ledger in the past.
    FeeCheduleInvalidActivation = 242,
    /// `LiquifactEscrow::set_fee_schedule` attempted to submit a schedule identical to the active schedule.
    FeeScheduleSameAsACtive = 243,
    FundingTokenScaleInvalid = 244,
    FundingTokenScaleNotSet = 245,

    // ----------------------------------------------------------------------------
    // Deterministic Recovery Errors (400..409)
    // ----------------------------------------------------------------------------
    /// A previous operation was interrupted and left a recovery marker in
    /// storage. The caller must invoke the corresponding recovery entry
    /// point before proceeding. This is deterministic: the marker contents
    /// the exact step that must be resumed.
    RecoveryRequired = 400,
    /// A recovery entry point was invoked but no recovery marker is present.
    /// This is a permanent rejection and indicates a caller bug or a stale
    /// off-chain view.
    NoRecoveryPending = 401,
    /// The recovery marker is present but the caller did not supply the
    /// authorization required to complete recovery (e.g. admin approval).
    RecoveryUnauthorized = 402,
    /// The recovery attempt failed because the underlying dependency (token
    /// contract) was still unavailable. The recovery marker remains set and
    /// the caller may retry after backoff without risk of double-applying.
    RecoveryDependencyUnavailable = 403,
    /// The recovery attempt detected that the persisted state is inconsistent
    /// with the recovery marker (e.g. a partially applied transfer that did not
    /// record its led). This is a permanent failure that requires admin
    /// intervention; the contract will not silently proceed.
    RecoveryStateInconsistent = 404,
    /// The recovery attempt exceeded the maximum number of attempts allowed
    /// within the configured window. The marker remains set and the admin
    /// must intervene to avoid an unrecoverable loop.
    RecoveryAttemptsExhausted = 405,
    /// The recovery attempt was rejected because a concurrent caller has
    /// already claimed the recovery lock. This is transient and safe to
    /// retry after the lock is released.
    RecoveryConcurrentAttempt = 406,
    /// The recovery marker was cleared but the corresponding compensating
    /// action could not be completed. The marker is re-set so recovery can
    /// be retried deterministically.
    RecoveryCompensationFailed = 407,
}
impl EscrowError {}
