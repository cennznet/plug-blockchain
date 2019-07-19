// Copyright (C) 2019 Centrality Investments Limited
// This file is part of PLUG.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use parity_codec::{Decode, Encode, Input};
use rstd::vec::Vec;

use crate::types::{AccountId, Timestamp, Signature};
use crate::util::encode_with_vec_prefix;
use primitives::{
	crypto::UncheckedFrom,
	H256,
	sr25519::Signature as Sr25519Sig,
};
use primitives::ed25519::{Public as Ed25519Pub, Signature as Ed25519Sig};

use runtime_primitives::doughnut::{DoughnutV0, ValidationError};
use runtime_primitives::traits::{DoughnutApi};
use runtime_primitives::traits::{DoughnutVerify, Verify};

/// A doughnut compatible with the plug runtime
/// It handles type conversion from DoughnutV0 types into plug runtime types e.g. `PublicKey` -> `AccountId`
/// It also provides length prefix support for the SCALE codec used by the extrinsic format
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Eq, PartialEq, Clone)]
pub struct PlugDoughnut(DoughnutV0);

impl PlugDoughnut {
	/// Create a new PlugDoughnut
	pub fn new(doughnut: DoughnutV0) -> Self {
		Self(doughnut)
	}
}

impl Decode for PlugDoughnut {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		// This is a little more complicated than usual since the binary format must be compatible
		// with substrate's generic `Vec<u8>` type. Basically this just means accepting that there
		// will be a prefix of vector length (we don't need to use this).
		let _length_do_not_remove_me_see_above: Vec<()> = Decode::decode(input)?;
		let doughnut = DoughnutV0::decode(input)?;
		Some(PlugDoughnut(doughnut))
	}
}

impl Encode for PlugDoughnut {
	fn encode(&self) -> Vec<u8> {
		encode_with_vec_prefix::<Self, _>(|v| self.0.encode_to(v))
	}
}

impl DoughnutApi for PlugDoughnut {
	type PublicKey = AccountId;
	type Timestamp = Timestamp;
	type Signature = Signature;
	/// Return the doughnut holder
	fn holder(&self) -> Self::PublicKey {
		AccountId::unchecked_from(self.0.holder())
	}
	/// Return the doughnut issuer
	fn issuer(&self) -> Self::PublicKey {
		AccountId::unchecked_from(self.0.issuer())
	}
	/// Return the doughnut expiry timestamp
	fn expiry(&self) -> Self::Timestamp {
		self.0.expiry().into()
	}
	/// Return the doughnut 'not before' timestamp
	fn not_before(&self) -> Self::Timestamp {
		self.0.not_before().into()
	}
	/// Return the doughnut payload bytes
	fn payload(&self) -> Vec<u8> {
		self.0.payload()
	}
	/// Return the doughnut signature
	fn signature(&self) -> Self::Signature {
		Sr25519Sig::from_slice(self.0.signature().as_ref()).into()
	}
	fn signature_version(&self) -> u8 {
		self.0.signature_version()
	}
	/// Return the payload for domain, if it exists in the doughnut
	fn get_domain(&self, domain: &str) -> Option<&[u8]> {
		self.0.get_domain(domain)
	}
	/// Validate the doughnut against `who` and the current timestamp `now`
	fn validate(&self, who: &Self::PublicKey, now: Self::Timestamp) -> Result<(), ValidationError> {
		let _who: H256 = AsRef::<[u8; 32]>::as_ref(who).into();
		self.0.validate(&_who, now as u32)
	}
}

// This is re-implemented here due to sr25519 verification requiring an external
// wasm VM call when using `no std`
impl DoughnutVerify for PlugDoughnut
where
	<PlugDoughnut as DoughnutApi>::Signature: Verify<Signer=AccountId>,
{
	/// Verify the doughnut signature. Returns `true` if it is ok
	fn verify(&self) -> bool {
		match self.signature_version() {
			0 => {
				self.signature().verify(&self.payload()[..], &self.issuer())
			}
			1 => {
				let signature = Ed25519Sig::from_slice(self.0.signature().as_ref());
				let issuer = Ed25519Pub::from_h256(self.0.issuer());
				Ed25519Sig::verify(&signature, &self.payload()[..], &issuer)
			}
			_ => {
				// Unsupported
				false
			}
		}
	}
}
