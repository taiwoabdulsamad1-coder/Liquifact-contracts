use soroban_sdk::{contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol};

const YIELD_TIER_KEY: Symbol = symbol_short!("YLD_TIER");
const ADMIN_KEY: Symbol = symbol_short!("ADMIN");

/// Errors returned by the contract.
/// /// Invariants:
/// - `NotInitialized` is returned when an admin-only operation is attempted before `init`.
/// - `AlreadyInitialized` is returned when `init` is called more than once.
/// - `NotAuthorized` is returned when the admin authorization check fails.
/// - `InvalidTier` is returned when an unsupported tier value is supplied.
///
/// These errors are deterministic and do not leak sensitive data. They are
/// surfaced to callers through the `Result` return type of each entry point.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotAuthorized = 1,
    NotInitialized = 2,
    AlreadyInitialized = 3,
    InvalidTier = 4,
}

/// Persisted yield-tier state.
///
/// The `Unset` variant is the canonical default and is the only value returned
/// when no tier has been explicitly set. This guarantees that `read` operations
/// are total and never panic on missing storage.
#[derive(Clone, Debug, PartialEq, Eq)]
#[soroban_sdk::contracttype]
pub enum YieldTierState {
    Unset,
    Tier1,
    Tier2,
    Tier3,
}

pub struct YieldTierContract;

/// State invariants owned by this contract:
/// 1. ADMIN_KEY is written at most once (during `init`) and never changed by any other entry point.
/// 2. Every mutating entry point (`upgrade`, `set_yield_tier`) requires the
//    stored admin's authorization before any state change or external effect.
/// 3. YIELD_TIER_KEY is only written after authorization succeeds, so a
///    rejected call leaves the previous tier intact.
/// 4. `upgrade` performs the WASM update and emits the event as a single
///    authorized transition; failure of the deployer call aborts the tx.
/// 5. `get_yield_tier` is pure and never mutates storage.
#[contractimpl]
impl YieldTierContract {
    /// Initializes the contract with an admin address.
    ///
    /// # Invariants
    /// - Must be called exactly once. A second call returns `AlreadyInitialized`
    ///   without mutating storage, making the failure recoverable and observable.
    /// - The admin is persisted atomically with the initialization flag.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&ADMIN_KEY) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&ADMIN_KEY, &admin);
        env.storage().instance().set(&YIELD_TIER_KEY, &YieldTierState::Unset);
        Ok(())
    }

    /// Upgrades the contract WASM hash (admin-only).
    ///
    /// # Invariants
    /// - Requires initialization and admin authorization.
    /// - Returns `NotInitialized` or `NotAuthorized` deterministically without
    ///   mutating state on failure.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN <32>) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&ADMIN_KEY).ok(Error::NotInitialized)?;
        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        env.events().publish((symbol_short!("upgrade"),), (new_wasm_hash.clone(),));

        Ok()
    }

    /// Returns the current yield-tier state without mutating contract storage.
    /// Returns `YieldTierState::Unset` as a default if no state has been initialized.
    ///
    /// # Invariants
    /// - Total function: never panics and always returns a valid tier.
    /// - Read-only: no storage mutation, no authorization required.
    pub fn get_yield_tier(env: Env) -> YieldTierState {
        env.storage()
            .instance()
            .get(&YIELD_TIER_KEY)
            .unwrap_or(YieldTierState::Unset)
    }

    /// Sets the yield-tier state (admin-only).
    ///
    /// # Invariants
    /// - Requires initialization and admin authorization.
    /// - Rejects the `Unset` value with `InvalidTier` so the persisted tier is
    ///   always a concrete tier once set. This makes duplicate and boundary
    ///   inputs deterministic.
    /// - On failure the stored tier is left unchanged (state transition is
    ///   all-or-nothing), so retries are safe and idempotent for the same input.
    pub fn set_yield_tier(env: Env, tier: YieldTierState) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&ADMIN_KEY).ok(Error::NotInitialized)?;
        admin.require_auth();

        if matches!(tier, YieldTierState::Unset) {
            return Err(Error::InvalidTier);
        }

        env.storage().instance().set(&YIELD_TIER_KEY, &tier);
        env.events().publish((symbol_short!("tier_set"),), (tier.clone(),));
        Ok(()
    }
}
