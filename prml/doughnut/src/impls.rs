use crate::{DoughnutRuntime, PlugDoughnut};
use primitives::{
	crypto::UncheckedFrom,
	ed25519::{self},
	sr25519::{self},
};
use rstd::{self, prelude::*};
use sr_primitives::traits::{DispatchError, DoughnutApi, DoughnutVerify, Member, SignedExtension, Verify};
use sr_primitives::transaction_validity::ValidTransaction;
use sr_primitives::weights::DispatchInfo;
use support::{
	Parameter,
	traits::Time,
};

// Proxy calls to the inner Doughnut type and provide Runtime type conversions where required.
impl<Doughnut, Runtime> DoughnutApi for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi<Signature=[u8; 64]>,
	<Doughnut as DoughnutApi>::PublicKey: Into<[u8; 32]>,
	Runtime: DoughnutRuntime,
	Runtime::AccountId: AsRef<[u8]> + UncheckedFrom<[u8; 32]>,
{
	type PublicKey = Runtime::AccountId;
	type Signature = <Doughnut as DoughnutApi>::Signature;
	type Timestamp = <Doughnut as DoughnutApi>::Timestamp;

	fn holder(&self) -> Self::PublicKey {
		UncheckedFrom::unchecked_from(self.0.holder().into())
	}
	fn issuer(&self) -> Self::PublicKey {
		UncheckedFrom::unchecked_from(self.0.issuer().into())
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
#[cfg(not(feature = "mock"))]
impl<Doughnut, Runtime> DoughnutVerify for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi<Signature=[u8; 64]>,
	<Doughnut as DoughnutApi>::PublicKey: Into<[u8; 32]>,
	Runtime: DoughnutRuntime,
{
	/// Verify the doughnut signature. Returns `true` on success, false otherwise
	fn verify(&self) -> bool {
		match self.0.signature_version() {
			// sr25519
			0 => {
				let signature = sr25519::Signature(self.0.signature());
				let issuer = sr25519::Public(self.0.issuer().into());
				return signature.verify(&self.0.payload()[..], &issuer)
			}
			// ed25519
			1 => {
				let signature = ed25519::Signature(self.0.signature());
				let issuer = ed25519::Public(self.0.issuer().into());
				return ed25519::Signature::verify(&signature, &self.0.payload()[..], &issuer)
			}
			// signature version unsupported.
			_ => false,
		}
	}
}

impl<Doughnut, Runtime> SignedExtension for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi<Signature=[u8; 64]> + Member + Parameter,
	<Doughnut as DoughnutApi>::PublicKey: Into<[u8; 32]>,
	Runtime: DoughnutRuntime + Eq + Clone + Send + Sync,
	Runtime::AccountId: AsRef<[u8]>,
{
	type AccountId = Runtime::AccountId;
	type AdditionalSigned = ();
	type Call = Runtime::Call;
	type Pre = ();
	fn additional_signed(&self) -> rstd::result::Result<(), &'static str> { Ok(()) }
	fn validate(&self, who: &Self::AccountId, _call: &Self::Call, _info: DispatchInfo, _len: usize) -> Result<ValidTransaction, DispatchError>
	{
		if !self.verify() {
			return Err(DispatchError::BadSignatureDoughnut)
		}
		if let Err(_) =self.0.validate(who, Runtime::TimestampProvider::now()) {
			// TODO: Surface detailed error
			return Err(DispatchError::InvalidDoughnut)
		}
		Ok(ValidTransaction::default())
	}
}

#[cfg(feature = "mock")]
impl<Doughnut, Runtime> DoughnutVerify for PlugDoughnut<Doughnut, Runtime>
where
	Doughnut: DoughnutApi<Signature=[u8; 64]>,
	Runtime: DoughnutRuntime,
{
	/// Hack signature check for mocks.
	/// `signature[0] = 1` signal true, otherwise `false`
	fn verify(&self) -> bool {
		self.0.signature()[0] == 1
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use primitives::crypto::Pair;
	use sr_primitives::doughnut::DoughnutV0;

	#[derive(Clone, Eq, PartialEq)]
	pub struct Runtime;

	pub struct TimestampProvider;
	impl Time for TimestampProvider {
		type Moment = u64;
		fn now() -> Self::Moment {
			0
		}
	}
	impl DoughnutRuntime for Runtime {
		type AccountId = sr25519::Public;
		type Call = ();
		type Doughnut = PlugDoughnut<DoughnutV0, Self>;
		type TimestampProvider = TimestampProvider;
	}

	#[test]
	fn plug_doughnut_validates() {
		let issuer = sr25519::Pair::from_string("//Alice", None).unwrap();
		let holder = sr25519::Pair::from_string("//Bob", None).unwrap();
		let doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 3000,
			not_before: 0,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 0,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		assert!(
			<PlugDoughnut<_, _> as DoughnutApi>::validate(&plug_doughnut, holder.public(), 100).is_ok()
		);
	}

	#[test]
	fn plug_doughnut_does_not_validate() {
		let issuer = sr25519::Pair::from_string("//Alice", None).unwrap();
		let holder = sr25519::Pair::from_string("//Bob", None).unwrap();
		let signer = sr25519::Pair::from_string("//Charlie", None).unwrap();
		let doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 3000,
			not_before: 1000,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 0,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		// premature
		assert!(
			<PlugDoughnut<_, _> as DoughnutApi>::validate(&plug_doughnut, holder.public(), 999).is_err()
		);
		// expired
		assert!(
			<PlugDoughnut<_, _> as DoughnutApi>::validate(&plug_doughnut, holder.public(), 3001).is_err()
		);
		// signer is not holder
		assert!(
			<PlugDoughnut<_, _> as DoughnutApi>::validate(&plug_doughnut, signer.public(), 100).is_err()
		);
	}

	#[test]
	fn plug_doughnut_verifies_sr25519_signature() {
		let issuer = sr25519::Pair::from_string("//Alice", None).unwrap();
		let holder = sr25519::Pair::from_string("//Bob", None).unwrap();
		let mut doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 0,
			not_before: 0,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 0,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		doughnut.signature = issuer.sign(&doughnut.payload()).into();
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		assert!(plug_doughnut.verify());
	}

	#[test]
	fn plug_doughnut_does_not_verify_sr25519_signature() {
		let issuer = sr25519::Pair::from_string("//Alice", None).unwrap();
		let holder = sr25519::Pair::from_string("//Bob", None).unwrap();
		let mut doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 0,
			not_before: 0,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 0,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		doughnut.signature = holder.sign(&doughnut.payload()).into();
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		assert_eq!(plug_doughnut.verify(), false);
	}

	#[test]
	fn plug_doughnut_verifies_ed25519_signature() {
		let issuer = ed25519::Pair::from_legacy_string("//Alice", None);
		let holder = ed25519::Pair::from_legacy_string("//Bob", None);
		let mut doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 0,
			not_before: 0,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 1,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		doughnut.signature = issuer.sign(&doughnut.payload()).into();
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		assert!(DoughnutVerify::verify(&plug_doughnut));
	}

	#[test]
	fn plug_doughnut_does_not_verify_ed25519_signature() {
		let issuer = ed25519::Pair::from_legacy_string("//Alice", None);
		let holder = ed25519::Pair::from_legacy_string("//Bob", None);
		let mut doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 0,
			not_before: 0,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 1,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		// !holder signs the doughnuts
		doughnut.signature = holder.sign(&doughnut.payload()).into();
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		assert_eq!(plug_doughnut.verify(), false);
	}

	#[test]
	fn plug_doughnut_does_not_verify_unknown_signature_version() {
		let issuer = ed25519::Pair::from_legacy_string("//Alice", None);
		let holder = ed25519::Pair::from_legacy_string("//Bob", None);
		let mut doughnut = DoughnutV0 {
			issuer: issuer.public().into(),
			holder: holder.public().into(),
			expiry: 0,
			not_before: 0,
			payload_version: 0,
			signature: [1u8; 64].into(),
			signature_version: 200,
			domains: vec![("test".to_string(), vec![0u8])],
		};
		doughnut.signature = issuer.sign(&doughnut.payload()).into();
		let plug_doughnut = PlugDoughnut::<_, Runtime>::new(doughnut);
		assert_eq!(plug_doughnut.verify(), false);
	}

	#[test]
	fn plug_doughnut_proxies_to_inner_doughnut() {
		let issuer = [0u8; 32];
		let holder = [1u8; 32];
		let expiry = 55555;
		let not_before = 123;
		let signature = [1u8; 64];
		let signature_version = 1;

		let doughnut = PlugDoughnut::<_, Runtime>::new(DoughnutV0 {
			issuer,
			holder,
			expiry,
			not_before,
			payload_version: 0,
			signature: signature.into(),
			signature_version,
			domains: vec![("test".to_string(), vec![0u8])],
		});

		assert_eq!(Into::<[u8; 32]>::into(doughnut.issuer()), issuer);
		assert_eq!(Into::<[u8; 32]>::into(doughnut.holder()), holder);
		assert_eq!(doughnut.expiry(), expiry);
		assert_eq!(doughnut.not_before(), not_before);
		assert_eq!(doughnut.signature_version(), signature_version);
		assert_eq!(&doughnut.signature()[..], &signature[..]);
		assert_eq!(doughnut.payload(), doughnut.0.payload());
	}
}