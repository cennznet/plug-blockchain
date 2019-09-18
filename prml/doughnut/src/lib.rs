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
use rstd::{self, prelude::*};
use sr_primitives::traits::{DispatchError, DoughnutApi, DoughnutVerify, Member, SignedExtension, Verify};
use sr_primitives::transaction_validity::ValidTransaction;
use sr_primitives::weights::DispatchInfo;
use support::{Parameter, additional_traits::DispatchVerifier};
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
pub struct PlugDoughnut<Doughnut: DoughnutApi, Runtime: DoughnutRuntime>(Doughnut, rstd::marker::PhantomData<Runtime>);

#[cfg(feature = "std")]
impl<Doughnut, Runtime> rstd::fmt::Debug for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi + Encode,
	Runtime: DoughnutRuntime + Send + Sync,
{
	fn fmt(&self, f: &mut rstd::fmt::Formatter) -> rstd::fmt::Result {
		self.0.encode().fmt(f)
	}
}

impl<Doughnut, Runtime> PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi,
	Runtime: DoughnutRuntime,
{
	/// Create a new PlugDoughnut
	pub fn new(doughnut: Doughnut) -> Self {
		Self(doughnut, rstd::marker::PhantomData)
	}
}

// proxy calls to the inner Doughnut type
impl<Doughnut, Runtime> DoughnutApi for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi,
	Runtime: DoughnutRuntime,
{
	type PublicKey = <Doughnut as DoughnutApi>::PublicKey;
	type Signature = <Doughnut as DoughnutApi>::Signature;
	type Timestamp = <Doughnut as DoughnutApi>::Timestamp;

	fn holder(&self) -> Self::PublicKey {
		self.0.holder()
	}
	fn issuer(&self) -> Self::PublicKey {
		self.0.issuer()
	}
	fn not_before(&self) -> Self::Timestamp {
		self.0.not_before()
	}
	fn expiry(&self) -> Self::Timestamp {
		self.0.expiry()
	}
	fn signature(&self) -> Self::Signature {
		self.0.signature()
	}
	fn signature_version(&self) -> u8 {
		self.0.signature_version()
	}
	fn payload(&self) -> Vec<u8> {
		self.0.payload()
	}
	fn get_domain(&self, domain: &str) -> Option<&[u8]> {
		self.0.get_domain(domain)
	}
}

// Re-implemented here due to sr25519 verification requiring an external
// wasm VM call when using `no std`
impl<Doughnut, Runtime> DoughnutVerify for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi<PublicKey=[u8; 32], Signature=[u8; 64]>,
	Runtime: DoughnutRuntime,
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

impl<Doughnut, Runtime> SignedExtension for PlugDoughnut<Doughnut, Runtime>
where
	AccountId<Runtime>: AsRef<[u8]>,
	Doughnut: DoughnutApi<PublicKey=[u8; 32], Signature=[u8; 64]> + Member + Parameter,
	Runtime: DoughnutRuntime + Send + Sync,
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
