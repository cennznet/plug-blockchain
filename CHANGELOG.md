# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2019-21-10

## Changed
`srml/staking/*`
- Add `RewardCurrency` type to allow paying out staking rewards in a different currency to the staked currency
- Change `fn make_payout()` so that RewardCurrency is paid to the stash account and not added to the total stake, if the reward currency is not the staked currency

## [1.0.0] - 2019-17-10

## Added
`prml/attestation/*`
- Added attestation runtime module

## [1.0.0] - 2019-16-10
### Added

`prml/doughnut/*`
- Add `PlugDoughnut` wrapper struct to allow doughnut integration with `SignedExtension` hooks  
- Add `PlugDoughnutDispatcher` as the defacto Plug implementor for `DelegatedDispatchVerifier`  

`node/runtime/src/lib.rs`
- Add doughnut proof as an optional first parameter to the `node/runtime` `SignedExtra` payload allowing doughnut's to be added to extrinsics  

- Add `DelegatedDispatchVerifier` and `Doughnut` proof type to `system::Trait` type bounds

`core/sr-primitives/src/traits.rs`
- Blanket impl SignedExtension for `Option<T>` to allow Optional<PlugDoughnut> in extrinsics
- Add `MaybeDoughnut` trait for SignedExtension type to allow extracting doughnut from `SignedExtra` tuple
- impl `MaybeDoughnut` for SignedExtension macro tuple of all lengths

### Changed
`core/sr-primitives/src/traits.rs`
- Make trait `SignedExtension::pre_dispatch` method receive self by reference (`&self`), instead of move (`self`)

`srml/system/src/lib.rs` and `srml/support/src/origin.rs`
- Add `DelegatedOrigin` variant to `RawOrigin` for delegated transactions
- Add `MaybeDoughnutRef` trait for extracting doughnut proof from `origin` without move in runtime module methods

`srml/support/src/dispatch.rs`
- Add `DelegatedDispatchVerifier` check to `decl_module!` expansion. This allows doughnut proofs to be checked when an extrinsic is dispatched using the `<T as system::Trait>::DelegatedDispatchVerifier` impl  
