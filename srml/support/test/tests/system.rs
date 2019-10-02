use srml_support::codec::{Encode, Decode};
use srml_support::additional_traits::{DispatchVerifier as DispatchVerifierT, MaybeDoughnutRef};

pub trait Trait: 'static + Eq + Clone {
	type Origin: Into<Result<RawOrigin<Self::AccountId, Self::Doughnut>, Self::Origin>>
		+ From<RawOrigin<Self::AccountId, Self::Doughnut>> + MaybeDoughnutRef<Doughnut=()>;
	type BlockNumber: Decode + Encode + Clone + Default;
	type Hash;
	type AccountId: Encode + Decode;
	type Event: From<Event>;
	type DispatchVerifier: DispatchVerifierT<()>;
	type Doughnut;
}

srml_support::decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		pub fn deposit_event(_event: T::Event) {
		}
	}
}

srml_support::decl_event!(
	pub enum Event {
		ExtrinsicSuccess,
		ExtrinsicFailed,
	}
);

/// Origin for the system module.
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum RawOrigin<AccountId, Doughnut> {
	Root,
	Signed(AccountId),
	Delegated(AccountId, Doughnut),
	None,
}

impl<AccountId, Doughnut> From<(Option<AccountId>,Option<Doughnut>)> for RawOrigin<AccountId, Doughnut> {
	fn from(s: (Option<AccountId>, Option<Doughnut>)) -> RawOrigin<AccountId, Doughnut> {
		match s {
			(Some(who), None) => RawOrigin::Signed(who),
			(Some(who), Some(doughnut)) => RawOrigin::Delegated(who, doughnut),
			_ => RawOrigin::None,
		}
	}
}

pub type Origin<T> = RawOrigin<<T as Trait>::AccountId, <T as Trait>::Doughnut>;

#[allow(dead_code)]
pub fn ensure_root<OuterOrigin, AccountId, Doughnut>(o: OuterOrigin) -> Result<(), &'static str>
	where OuterOrigin: Into<Result<RawOrigin<AccountId, Doughnut>, OuterOrigin>>
{
	o.into().map(|_| ()).map_err(|_| "bad origin: expected to be a root origin")
}
