// Copyright 2019 Centrality Investments Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//!
//! Define doughnut validation traits for the runtime
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Encode, Decode};
use primitives::{
	ed25519::{self},
	sr25519::{self},
};
use rstd::{self};
use sr_primitives::traits::{DispatchError, DoughnutApi, DoughnutVerify, SignedExtension, Verify};
use sr_primitives::transaction_validity::ValidTransaction;
use sr_primitives::weights::DispatchInfo;
use support::additional_traits::DispatchVerifier;
use system;
use timestamp;

/// Alias the necessary bounds for doughnut validation by a runtime
pub trait DoughnutRuntime: system::Trait + timestamp::Trait {}
/// The runtime Account ID type
type AccountId<Runtime> = <Runtime as system::Trait>::AccountId;
/// The runtime doughnut type
type Doughnut<Runtime> = <Runtime as system::Trait>::Doughnut;

/// A doughnut wrapped for compatibility with the extrinsic transport layer and the plug runtime types.
/// It can be passed to the runtime as a `SignedExtension` in an extrinsic.
#[derive(Encode, Decode, Clone, Eq, PartialEq)]
pub struct PlugDoughnut<Runtime: DoughnutRuntime>(Doughnut<Runtime>);

#[cfg(feature = "std")]
impl<Runtime: DoughnutRuntime + Send + Sync> rstd::fmt::Debug for PlugDoughnut<Runtime> {
	fn fmt(&self, f: &mut rstd::fmt::Formatter) -> rstd::fmt::Result {
		self.0.encode().fmt(f)
	}
}

impl<Runtime: DoughnutRuntime> PlugDoughnut<Runtime> {
	/// Create a new PlugDoughnut
	pub fn new(doughnut: Doughnut<Runtime>) -> Self {
		Self(doughnut)
	}
}

// Re-implemented here due to sr25519 verification requiring an external
// wasm VM call when using `no std`
impl<Runtime: DoughnutRuntime> DoughnutVerify for PlugDoughnut<Runtime>
where
	Runtime: DoughnutRuntime,
	Doughnut<Runtime>: DoughnutApi<PublicKey=[u8; 32], Signature=[u8; 64]>,
{
	/// Verify the doughnut signature. Returns `true` on success, false otherwise
	fn verify(&self) -> bool {
		match self.0.signature_version() {
			// sr25519
			0 => {
				let signature = sr25519::Signature(self.0.signature());
				let issuer = sr25519::Public(self.0.issuer());
				return signature.verify(&self.0.payload()[..], &issuer)
			}
			// ed25519
			1 => {
				let signature = ed25519::Signature(self.0.signature());
				let issuer = ed25519::Public(self.0.issuer());
				return ed25519::Signature::verify(&signature, &self.0.payload()[..], &issuer)
			}
			// signature version unsupported.
			_ => false,
		}
	}
}

impl<Runtime> SignedExtension for PlugDoughnut<Runtime>
where
	Runtime: DoughnutRuntime + Send + Sync,
	Doughnut<Runtime>: DoughnutApi<PublicKey=[u8; 32], Signature=[u8; 64]> + Send + Sync,
	AccountId<Runtime>: AsRef<[u8]>,
{
	type AccountId = AccountId<Runtime>;
	type AdditionalSigned = ();
	type Call = Runtime::Call;
	type Pre = ();
	fn additional_signed(&self) -> rstd::result::Result<(), &'static str> { Ok(()) }
	fn validate(&self, who: &Self::AccountId, _call: &Self::Call, _info: DispatchInfo, _len: usize) -> Result<ValidTransaction, DispatchError>
	{
		// TODO: These error variants are intended for transactions
		//			 update to use doughnut specific `DispatchError` variants to avoid confusion for clients.
		if !self.verify() {
			return Err(DispatchError::BadProof)
		}
		if !self.0.validate(who, timestamp::Module::<Runtime>::now()).is_ok() {
			return Err(DispatchError::NoPermission)
		}
		Ok(ValidTransaction::default())
	}
}

/// It verifies a doughnut allows execution of module/method logic
pub struct PlugDoughnutDispatcher<Runtime: DoughnutRuntime>(rstd::marker::PhantomData<Runtime>);

impl<Runtime: DoughnutRuntime> DispatchVerifier<Doughnut<Runtime>> for PlugDoughnutDispatcher<Runtime> {
	const DOMAIN: &'static str = "plug";
	/// Verify a Doughnut proof authorizes method dispatch given some input parameters
	fn verify(
		_doughnut: &Doughnut<Runtime>,
		_module: &str,
		_method: &str,
	) -> Result<(), &'static str> {
		Err("Doughnut dispatch verification is not implemented for this domain")
	}
}
