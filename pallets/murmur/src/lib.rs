#![cfg_attr(not(feature = "std"), no_std)]

//! # Murmur Pallet
//!
//!
//!
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
// pub mod weights; TODO
// pub use weights::WeightInfo;

use ckb_merkle_mountain_range::{
	util::{MemMMR, MemStore},
	Merge, MerkleProof, Result as MMRResult, MMR,
};
use codec::{Decode, Encode};
use frame_support::{
	dispatch::GetDispatchInfo,
	pallet_prelude::*,
	traits::{ConstU32, IsSubType},
};
use log::info;
use murmur_core::{
	murmur,
	types::{BlockNumber, Leaf, MergeLeaves},
};
use scale_info::TypeInfo;
use sp_runtime::{traits::Dispatchable, DispatchResult};
use sp_std::{prelude::ToOwned, vec, vec::Vec};

use pallet_randomness_beacon::{Ciphertext, TimelockEncryptionProvider};

/// a bounded name
pub type Name = BoundedVec<u8, ConstU32<32>>;

/// A struct to represent specific details of a murmur proxy account
#[derive(
	Debug,
	PartialEq,
	Eq,
	Hash,
	Clone,
	Encode,
	Decode,
	TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct MurmurProxyDetails<AccountId> {
	/// The proxy account address
	pub address: AccountId,
	/// The MMR root
	pub root: Vec<u8>,
	/// The MMR size
	pub size: u64,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::{traits::Zero, DispatchResult};

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_proxy::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// The overarching call type.
		type RuntimeCall: Parameter
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin>
			+ GetDispatchInfo
			+ From<frame_system::Call<Self>>
			+ IsSubType<Call<Self>>
			+ IsType<<Self as frame_system::Config>::RuntimeCall>;
		// / Type representing the weight of this pallet
		// type WeightInfo: WeightInfo;
		/// something that can decrypt messages locked for the current slot
		type TlockProvider: TimelockEncryptionProvider<BlockNumberFor<Self>>;
	}

	/// a registry to track registered 'usernames' for OTP wallets
	/// Q: what happens when this map becomes very large? in terms of query time?
	#[pallet::storage]
	pub(super) type Registry<T: Config> =
		StorageMap<_, Blake2_256, Name, MurmurProxyDetails<T::AccountId>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		OtpProxyCreated,
		OtpProxyExecuted,
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		BadCiphertext,
		DuplicateName,
		InvalidOTP,
		InvalidMerkleProof,
		InvalidProxy,
		ProxyDNE,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		/// Create a time-based proxy account
		///
		/// * `root`: The MMR root
		/// * `size`: The size (number of leaves) of the MMR
		/// * `name`: The name to assign to the murmur proxy
		///
		#[pallet::weight(0)]
		#[pallet::call_index(0)]
		pub fn create(
			origin: OriginFor<T>,
			root: Vec<u8>,
			size: u64,
			name: BoundedVec<u8, ConstU32<32>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// check duplicate name
			ensure!(Registry::<T>::get(name.clone()).is_none(), Error::<T>::DuplicateName);

			// create a pure proxy with no delegate
			let signed_origin: T::RuntimeOrigin =
				frame_system::RawOrigin::Signed(who.clone()).into();
			pallet_proxy::Pallet::<T>::create_pure(
				signed_origin,
				T::ProxyType::default(),
				BlockNumberFor::<T>::zero(),
				0u16,
				true,
			)?;

			let address =
				pallet_proxy::Pallet::<T>::pure_account(&who, &T::ProxyType::default(), 0, None);

			Registry::<T>::insert(name, &MurmurProxyDetails { address, root, size });
			Self::deposit_event(Event::OtpProxyCreated);

			Ok(())
		}

		/// Proxy a call after verifying the ciphertext
		/// this function first checks the validity of the merkle proof (using the ciphertext)
		/// if valid, it decrypts the ciphertext and uses it to verify the hash
		/// if valid, it proxies the call
		///
		/// * `name`: The uid of the murmur proxy
		/// * `position`: The position in the MMR of the encrypted OTP code
		/// * `target_leaf`: The target leaf data (ciphertext)
		/// * `hash`: A hash to commit to the OTP code and call data
		/// * `proof`: A merkle proof that the target leaf is in the expected MMR at the given position
		/// * `size`: The size of the Merkle proof
		/// * `call`: The call to be proxied
		///
		#[pallet::weight(0)]
		#[pallet::call_index(1)]
		pub fn proxy(
			_origin: OriginFor<T>,
			name: BoundedVec<u8, ConstU32<32>>,
			position: u64,
			hash: Vec<u8>,
			ciphertext: Vec<u8>,
			proof: Vec<Vec<u8>>,
			size: u64,
			call: sp_std::boxed::Box<<T as pallet_proxy::Config>::RuntimeCall>,
		) -> DispatchResult {
			let when = T::TlockProvider::latest();

			let proxy_details = Registry::<T>::get(name.clone()).ok_or(Error::<T>::InvalidProxy)?;

			let result = T::TlockProvider::decrypt_at(&ciphertext, when)
				.map_err(|_| Error::<T>::BadCiphertext)?;
			let mut otp = result.message;

			let leaves: Vec<Leaf> = proof.clone().into_iter().map(|p| Leaf(p)).collect::<Vec<_>>();
			let merkle_proof = MerkleProof::<Leaf, MergeLeaves>::new(size, leaves.clone());
			let root = Leaf(proxy_details.root);

			let validity = murmur::verify(
				root,
				merkle_proof,
				hash,
				ciphertext,
				otp,
				call.encode().to_vec(),
				position
			);

			frame_support::ensure!(validity, Error::<T>::InvalidMerkleProof);

			let def = pallet_proxy::Pallet::<T>::find_proxy(
				&proxy_details.address,
				None,
				Some(T::ProxyType::default()),
			)
			.map_err(|_| Error::<T>::InvalidProxy)?;

			pallet_proxy::Pallet::<T>::do_proxy(def, proxy_details.address, *call);

			Self::deposit_event(Event::OtpProxyExecuted);
			Ok(())
		}
	}
}
