//! # Drand Bridge Pallet
//!
//! A pallet to bridge to [drand](drand.love)'s Quicknet, injecting publicly verifiable randomness into the runtime
//!
//! ## Overview
//!
//! Quicknet chain runs in an 'unchained' mode, producing a fresh pulse of randomness every 3s
//! This pallet implements an offchain worker that consumes pulses from quicket and then sends a signed
//! transaction to encode them in the runtime. The runtime uses the optimized arkworks host functions
//! to efficiently verify the pulse.
//!
//! Run `cargo doc --package pallet-drand --open` to view this pallet's documentation.

// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

extern crate alloc;
use crate::alloc::string::ToString;

use alloc::{format, string::String, vec, vec::Vec};
use ark_ec::{hashing::HashToCurve, AffineRepr};
use ark_serialize::CanonicalSerialize;
use codec::{Decode, Encode};
use frame_support::{
	pallet_prelude::*,
	traits::{Randomness, ValidatorSetWithIdentification},
};
use frame_system::offchain::{AppCrypto, CreateSignedTransaction, SendUnsignedTransaction, Signer};
use frame_system::offchain::{SignedPayload, SigningTypes};
use frame_system::pallet_prelude::BlockNumberFor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_ark_bls12_381::{G1Affine as G1AffineOpt, G2Affine as G2AffineOpt};
use sp_runtime::{
	offchain::{http, Duration},
	traits::{Hash, One, Zero},
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	KeyTypeId,
};
use w3f_bls::{EngineBLS, TinyBLS381};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;

pub mod bls12_381;
pub mod utils;

const USAGE: ark_scale::Usage = ark_scale::WIRE;
type ArkScale<T> = ark_scale::ArkScale<T, USAGE>;

/// the main drand api endpoint
pub const API_ENDPOINT: &str = "https://api.drand.sh";
/// the drand quicknet chain hash
pub const QUICKNET_CHAIN_HASH: &str =
	"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"drnd");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

	// implemented for runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

pub type OpaquePublicKeyG2 = BoundedVec<u8, ConstU32<96>>;
/// an opaque hash type
pub type BoundedHash = BoundedVec<u8, ConstU32<32>>;
/// the round number to track rounds of the beacon
pub type RoundNumber = u64;

/// the expected response body from the drand api endpoint `api.drand.sh/{chainId}/info`
#[derive(Debug, Decode, Default, PartialEq, Encode, Serialize, Deserialize, TypeInfo, Clone)]
pub struct BeaconInfoResponse {
	#[serde(with = "hex::serde")]
	pub public_key: Vec<u8>,
	pub period: u32,
	pub genesis_time: u32,
	#[serde(with = "hex::serde")]
	pub hash: Vec<u8>,
	#[serde(with = "hex::serde", rename = "groupHash")]
	pub group_hash: Vec<u8>,
	#[serde(rename = "schemeID")]
	pub scheme_id: String,
	pub metadata: MetadataInfoResponse,
}

/// metadata associated with the drand info response
#[derive(Debug, Decode, Default, PartialEq, Encode, Serialize, Deserialize, TypeInfo, Clone)]
pub struct MetadataInfoResponse {
	#[serde(rename = "beaconID")]
	beacon_id: String,
}

impl BeaconInfoResponse {
	fn try_into_beacon_config(&self) -> Result<BeaconConfiguration, String> {
		let bounded_pubkey = OpaquePublicKeyG2::try_from(self.public_key.clone())
			.map_err(|_| "Failed to convert public_key")?;
		let bounded_hash =
			BoundedHash::try_from(self.hash.clone()).map_err(|_| "Failed to convert hash")?;
		let bounded_group_hash = BoundedHash::try_from(self.group_hash.clone())
			.map_err(|_| "Failed to convert group_hash")?;
		let bounded_scheme_id = BoundedHash::try_from(self.scheme_id.as_bytes().to_vec().clone())
			.map_err(|_| "Failed to convert scheme_id")?;
		let bounded_beacon_id =
			BoundedHash::try_from(self.metadata.beacon_id.as_bytes().to_vec().clone())
				.map_err(|_| "Failed to convert beacon_id")?;

		Ok(BeaconConfiguration {
			public_key: bounded_pubkey,
			period: self.period,
			genesis_time: self.genesis_time,
			hash: bounded_hash,
			group_hash: bounded_group_hash,
			scheme_id: bounded_scheme_id,
			metadata: Metadata { beacon_id: bounded_beacon_id },
		})
	}
}

/// a pulse from the drand beacon
/// the expected response body from the drand api endpoint `api.drand.sh/{chainId}/public/latest`
#[derive(Debug, Decode, Default, PartialEq, Encode, Serialize, Deserialize)]
pub struct DrandResponseBody {
	/// the randomness round number
	pub round: RoundNumber,
	/// the sha256 hash of the signature
	// TODO: use Hash (https://github.com/ideal-lab5/pallet-drand/issues/2)
	#[serde(with = "hex::serde")]
	pub randomness: Vec<u8>,
	/// BLS sig for the current round
	// TODO: use Signature (https://github.com/ideal-lab5/pallet-drand/issues/2)
	#[serde(with = "hex::serde")]
	pub signature: Vec<u8>,
}

impl DrandResponseBody {
	fn try_into_pulse(&self) -> Result<Pulse, String> {
		let bounded_randomness = BoundedVec::<u8, ConstU32<32>>::try_from(self.randomness.clone())
			.map_err(|_| "Failed to convert randomness")?;
		let bounded_signature = BoundedVec::<u8, ConstU32<144>>::try_from(self.signature.clone())
			.map_err(|_| "Failed to convert signature")?;

		Ok(Pulse {
			round: self.round,
			randomness: bounded_randomness,
			signature: bounded_signature,
		})
	}
}
/// a drand chain configuration
#[derive(
	Clone,
	Debug,
	Decode,
	Default,
	PartialEq,
	Encode,
	Serialize,
	Deserialize,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct BeaconConfiguration {
	pub public_key: OpaquePublicKeyG2,
	pub period: u32,
	pub genesis_time: u32,
	pub hash: BoundedHash,
	pub group_hash: BoundedHash,
	pub scheme_id: BoundedHash,
	pub metadata: Metadata,
}

/// Payload used by to hold the beacon
/// config required to submit a transaction.
#[derive(Encode, Decode, Debug, Clone, PartialEq, scale_info::TypeInfo)]
pub struct BeaconConfigurationPayload<Public, BlockNumber> {
	pub block_number: BlockNumber,
	pub config: BeaconConfiguration,
	pub public: Public,
}

impl<T: SigningTypes> SignedPayload<T>
	for BeaconConfigurationPayload<T::Public, BlockNumberFor<T>>
{
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

/// metadata for the drand beacon configuration
#[derive(
	Clone,
	Debug,
	Decode,
	Default,
	PartialEq,
	Encode,
	Serialize,
	Deserialize,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct Metadata {
	beacon_id: BoundedHash,
}

/// a pulse from the drand beacon
#[derive(
	Clone,
	Debug,
	Decode,
	Default,
	PartialEq,
	Encode,
	Serialize,
	Deserialize,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct Pulse {
	/// the randomness round number
	pub round: RoundNumber,
	/// the sha256 hash of the signature
	// TODO: use Hash (https://github.com/ideal-lab5/pallet-drand/issues/2)
	pub randomness: BoundedVec<u8, ConstU32<32>>,
	/// BLS sig for the current round
	// TODO: use Signature (https://github.com/ideal-lab5/pallet-drand/issues/2)
	pub signature: BoundedVec<u8, ConstU32<144>>,
}

/// Payload used by to hold the pulse
/// data required to submit a transaction.
#[derive(Encode, Decode, Debug, Clone, PartialEq, scale_info::TypeInfo)]
pub struct PulsePayload<Public, BlockNumber> {
	pub block_number: BlockNumber,
	pub pulse: Pulse,
	pub public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for PulsePayload<T::Public, BlockNumberFor<T>> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// The overarching runtime event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// A type representing the weights required by the dispatchables of this pallet.
		type WeightInfo: WeightInfo;
		/// something that knows how to verify beacon pulses
		type Verifier: Verifier;
		/// A type for retrieving the validators supposed to be online in a session.
		type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
		/// The origin permissioned to update beacon configurations
		// #[pallet::constant]
		// type TrustedOrigins: Get<Vec<Self::AuthorityId>>;
		/// A configuration for base priority of unsigned transactions.
		///
		/// This is exposed so that it can be tuned for particular runtime, when
		/// multiple pallets send unsigned transactions.
		#[pallet::constant]
		type UnsignedPriority: Get<TransactionPriority>;
	}

	/// the drand beacon configuration
	#[pallet::storage]
	pub type BeaconConfig<T: Config> = StorageValue<_, BeaconConfiguration, OptionQuery>;

	/// map block number to round number of pulse authored during that block
	#[pallet::storage]
	pub type Pulses<T: Config> =
		StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, Pulse, OptionQuery>;

	/// Defines the block when next unsigned transaction will be accepted.
	///
	/// To prevent spam of unsigned (and unpaid!) transactions on the network,
	/// we only allow one transaction per block.
	/// This storage entry defines when new transaction is going to be accepted.
	#[pallet::storage]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		BeaconConfigChanged,
		/// A user has successfully set a new value.
		NewPulse {
			/// The new value set.
			round: RoundNumber,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The value retrieved was `None` as no value was previously set.
		NoneValue,
		/// There was an attempt to increment the value in storage over `u32::MAX`.
		StorageOverflow,
		/// failed to connect to the
		DrandConnectionFailure,
		/// the pulse is invalid
		UnverifiedPulse,
		/// the round number did not increment
		InvalidRoundNumber,
		/// the pulse could not be verified
		PulseVerificationError,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: BlockNumberFor<T>) {
			// if the beacon config isn't available, get it now
			if BeaconConfig::<T>::get().is_none() {
				if let Err(e) = Self::fetch_drand_config_and_send(block_number) {
					log::error!(
						"Failed to fetch chain config from drand, are you sure the chain hash is valid? {:?}",
						e
					);
				}
			} else {
				// otherwise query drand
				if let Err(e) = Self::fetch_drand_pulse_and_send_unsigned(block_number) {
					log::error!(
						"Failed to fetch pulse from drand, are you sure the chain hash is valid? {:?}",
						e
					);
				}
			}
		}
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		/// By default unsigned transactions are disallowed, but implementing the validator
		/// here we make sure that some particular calls (the ones produced by offchain worker)
		/// are being whitelisted and marked as valid.
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			match call {
				Call::set_beacon_config { config_payload: ref payload, ref signature } => {
					let signature = signature.as_ref().ok_or(InvalidTransaction::BadSigner)?;
					// TODO validate it is a trusted source as any well-formatted config would pass
					// https://github.com/ideal-lab5/pallet-drand/issues/3
					Self::validate_signature_and_parameters(
						payload,
						signature,
						&payload.block_number,
					)
				},
				Call::write_pulse { pulse_payload: ref payload, ref signature } => {
					let signature = signature.as_ref().ok_or(InvalidTransaction::BadSigner)?;
					Self::validate_signature_and_parameters(
						payload,
						signature,
						&payload.block_number,
					)
				},
				_ => InvalidTransaction::Call.into(),
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Verify and write a pulse from the beacon into the runtime
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::write_pulse())]
		pub fn write_pulse(
			origin: OriginFor<T>,
			pulse_payload: PulsePayload<T::Public, BlockNumberFor<T>>,
			_signature: Option<T::Signature>,
		) -> DispatchResult {
			ensure_none(origin)?;

			match BeaconConfig::<T>::get() {
				Some(config) => {
					let is_verified = T::Verifier::verify(config, pulse_payload.pulse.clone())
						.map_err(|s| {
							log::error!("Could not verify the pulse due to: {}", s);
							Error::<T>::PulseVerificationError
						})?;

					if is_verified {
						let current_block = frame_system::Pallet::<T>::block_number();
						let mut last_block = current_block.clone();

						// TODO: improve this, it's not efficient as it can be very slow when the history is large.
						// We could set a new storage value with the latest round.
						// Retrieve the lastest pulse and verify the round number
						// https://github.com/ideal-lab5/pallet-drand/issues/4
						loop {
							if let Some(last_pulse) = Pulses::<T>::get(last_block) {
								frame_support::ensure!(
									last_pulse.round < pulse_payload.pulse.round,
									Error::<T>::InvalidRoundNumber
								);
								break;
							}
							if last_block == Zero::zero() {
								break;
							}
							last_block -= One::one();
						}

						// Store the new pulse
						Pulses::<T>::insert(current_block, pulse_payload.pulse.clone());
						// now increment the block number at which we expect next unsigned transaction.
						<NextUnsignedAt<T>>::put(current_block + One::one());
						// Emit event for new pulse
						Self::deposit_event(Event::NewPulse { round: pulse_payload.pulse.round });
					}
				},
				None => {
					log::warn!("No beacon config available");
				},
			}

			Ok(())
		}
		/// allows the root user to set the beacon configuration
		/// generally this would be called from an offchain worker context.
		/// there is no verification of configurations, so be careful with this.
		///
		/// * `origin`: the root user
		/// * `config`: the beacon configuration
		///
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_beacon_config())]
		pub fn set_beacon_config(
			origin: OriginFor<T>,
			config_payload: BeaconConfigurationPayload<T::Public, BlockNumberFor<T>>,
			_signature: Option<T::Signature>,
		) -> DispatchResult {
			ensure_none(origin)?;
			BeaconConfig::<T>::put(config_payload.config);

			// now increment the block number at which we expect next unsigned transaction.
			let current_block = frame_system::Pallet::<T>::block_number();
			<NextUnsignedAt<T>>::put(current_block + One::one());

			Self::deposit_event(Event::BeaconConfigChanged {});
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// query drand's /info endpoint for the quicknet chain
	/// then send a signed transaction to encode it on-chain
	fn fetch_drand_config_and_send(block_number: BlockNumberFor<T>) -> Result<(), &'static str> {
		// Make sure we don't fetch the config if the transaction is going to be rejected
		// anyway.
		let next_unsigned_at = NextUnsignedAt::<T>::get();
		if next_unsigned_at > block_number {
			return Err("Too early to send unsigned transaction");
		}

		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)?;
		}

		let body_str =
			Self::fetch_drand_chain_info().map_err(|_| "Failed to fetch drand chain info")?;
		let beacon_config: BeaconInfoResponse = serde_json::from_str(&body_str)
			.map_err(|_| "Failed to convert response body to beacon configuration")?;
		let config = beacon_config
			.try_into_beacon_config()
			.map_err(|_| "Failed to convert BeaconInfoResponse to BeaconConfiguration")?;

		let results = signer.send_unsigned_transaction(
			|account| BeaconConfigurationPayload {
				block_number,
				config: config.clone(),
				public: account.public.clone(),
			},
			|config_payload, signature| Call::set_beacon_config {
				config_payload,
				signature: Some(signature),
			},
		);

		if results.is_empty() {
			log::error!("Empty result from config: {:?}", config);
		}

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted new config: {:?}", acc.id, config),
				Err(e) => log::error!("[{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}

		Ok(())
	}

	/// fetch the latest public pulse from the configured drand beacon
	/// then send a signed transaction to include it on-chain
	fn fetch_drand_pulse_and_send_unsigned(
		block_number: BlockNumberFor<T>,
	) -> Result<(), &'static str> {
		// Make sure we don't fetch the price if the transaction is going to be rejected
		// anyway.
		let next_unsigned_at = NextUnsignedAt::<T>::get();
		if next_unsigned_at > block_number {
			return Err("Too early to send unsigned transaction");
		}

		let signer = Signer::<T, T::AuthorityId>::all_accounts();

		let pulse_body = Self::fetch_drand().map_err(|_| "Failed to query drand")?;
		let unbounded_pulse: DrandResponseBody = serde_json::from_str(&pulse_body)
			.map_err(|_| "Failed to serialize response body to pulse")?;
		let pulse = unbounded_pulse
			.try_into_pulse()
			.map_err(|_| "Received pulse contains invalid data")?;

		// TODO: verify, before sending the tx that the pulse.round is greater than the stored one
		// https://github.com/ideal-lab5/pallet-drand/issues/4

		let results = signer.send_unsigned_transaction(
			|account| PulsePayload {
				block_number,
				pulse: pulse.clone(),
				public: account.public.clone(),
			},
			|pulse_payload, signature| Call::write_pulse {
				pulse_payload,
				signature: Some(signature),
			},
		);

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted new pulse: {:?}", acc.id, pulse.round),
				Err(e) => log::info!("[{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}

		Ok(())
	}

	/// Query the endpoint `{api}/{chainHash}/info` to receive information about the drand chain
	/// Valid response bodies are deserialized into `BeaconInfoResponse`
	fn fetch_drand_chain_info() -> Result<String, http::Error> {
		// TODO: move this value to config
		// https://github.com/ideal-lab5/pallet-drand/issues/5
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(1_000));
		let uri: &str = &format!("{}/{}/info", API_ENDPOINT, QUICKNET_CHAIN_HASH);
		let request = http::Request::get(uri);
		let pending = request.deadline(deadline).send().map_err(|_| {
			log::warn!("HTTP IO Error");
			http::Error::IoError
		})?;
		let response = pending.try_wait(deadline).map_err(|_| {
			log::warn!("HTTP Deadline Reached");
			http::Error::DeadlineReached
		})??;

		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}
		let body = response.body().collect::<Vec<u8>>();
		let body_str = alloc::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		Ok(body_str.to_string())
	}

	/// fetches the latest randomness from drand's API
	fn fetch_drand() -> Result<String, http::Error> {
		// TODO https://github.com/ideal-lab5/pallet-drand/issues/5
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(1_000));
		let uri: &str = &format!("{}/{}/public/latest", API_ENDPOINT, QUICKNET_CHAIN_HASH);
		let request = http::Request::get(uri);
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;

		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}
		let body = response.body().collect::<Vec<u8>>();
		let body_str = alloc::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		Ok(body_str.to_string())
	}

	/// get the randomness at a specific block height
	/// returns [0u8;32] if it does not exist
	pub fn random_at(block_number: BlockNumberFor<T>) -> [u8; 32] {
		let pulse = Pulses::<T>::get(block_number).unwrap_or(Pulse::default());
		let rand = pulse.randomness.clone();
		let bounded_rand: [u8; 32] = rand.into_inner().try_into().unwrap_or([0u8; 32]);

		bounded_rand
	}

	fn validate_signature_and_parameters(
		payload: &impl SignedPayload<T>,
		signature: &T::Signature,
		block_number: &BlockNumberFor<T>,
	) -> TransactionValidity {
		let signature_valid =
			SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
		if !signature_valid {
			return InvalidTransaction::BadProof.into();
		}
		Self::validate_transaction_parameters(&block_number)
	}

	// fn verify_signature(
	// 	payload: &impl SignedPayload<T>,
	// 	signature: &T::Signature,
	// ) -> DispatchResult {
	// 	// Access the keystore
	// 	let keystore = sp_keystore::Keystore::new().ok_or("Keystore not available")?;

	// 	// Retrieve the public key from the keystore
	// 	let public_keys = keystore.sr25519_public_keys(KEY_TYPE);
	// 	ensure!(!public_keys.is_empty(), "No public keys found in keystore");

	// 	// Verify the signature against each public key
	// 	let is_valid = public_keys
	// 		.iter()
	// 		.any(|public_key| T::Signature::verify(&signature, &data, public_key));

	// 	ensure!(is_valid, "Invalid signature");

	// 	Ok(())
	// }

	fn validate_transaction_parameters(block_number: &BlockNumberFor<T>) -> TransactionValidity {
		// Now let's check if the transaction has any chance to succeed.
		let next_unsigned_at = NextUnsignedAt::<T>::get();
		if &next_unsigned_at > block_number {
			return InvalidTransaction::Stale.into();
		}
		// Let's make sure to reject transactions from the future.
		let current_block = frame_system::Pallet::<T>::block_number();
		if &current_block < block_number {
			return InvalidTransaction::Future.into();
		}

		ValidTransaction::with_tag_prefix("DrandOffchainWorker")
			// We set the priority to the value stored at `UnsignedPriority`.
			.priority(T::UnsignedPriority::get())
			// This transaction does not require anything else to go before into the pool.
			// In theory we could require `previous_unsigned_at` transaction to go first,
			// but it's not necessary in our case.
			// We set the `provides` tag to be the same as `next_unsigned_at`. This makes
			// sure only one transaction produced after `next_unsigned_at` will ever
			// get to the transaction pool and will end up in the block.
			// We can still have multiple transactions compete for the same "spot",
			// and the one with higher priority will replace other one in the pool.
			.and_provides(next_unsigned_at)
			// The transaction is only valid for next block. After that it's
			// going to be revalidated by the pool.
			.longevity(1)
			// It's fine to propagate that transaction to other peers, which means it can be
			// created even by nodes that don't produce blocks.
			// Note that sometimes it's better to keep it for yourself (if you are the block
			// producer), since for instance in some schemes others may copy your solution and
			// claim a reward.
			.propagate(true)
			.build()
	}
}

/// construct a message (e.g. signed by drand)
pub fn message(current_round: RoundNumber, prev_sig: &[u8]) -> Vec<u8> {
	let mut hasher = Sha256::default();
	hasher.update(prev_sig);
	hasher.update(current_round.to_be_bytes());
	hasher.finalize().to_vec()
}

/// something to verify beacon pulses
pub trait Verifier {
	/// verify the given pulse using beacon_config
	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> Result<bool, String>;
}

/// A verifier to check values received from quicknet. It outputs true if valid, false otherwise
///
/// [Quicknet](https://drand.love/blog/quicknet-is-live-on-the-league-of-entropy-mainnet) operates in an unchained mode,
/// so messages contain only the round number. in addition, public keys are in G2 and signatures are in G1
///
/// Values are valid if the pairing equality holds:
///			 $e(sig, g_2) == e(msg_on_curve, pk)$
/// where $sig \in \mathbb{G}_1$ is the signature
///       $g_2 \in \mathbb{G}_2$ is a generator
///       $msg_on_curve \in \mathbb{G}_1$ is a hash of the message that drand signed (hash(round_number))
///       $pk \in \mathbb{G}_2$ is the public key, read from the input public parameters
///
///
pub struct QuicknetVerifier;

impl Verifier for QuicknetVerifier {
	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> Result<bool, String> {
		// decode public key (pk)
		let pk =
			ArkScale::<G2AffineOpt>::decode(&mut beacon_config.public_key.into_inner().as_slice())
				.map_err(|e| format!("Failed to decode public key: {}", e))?;

		// decode signature (sigma)
		let signature =
			ArkScale::<G1AffineOpt>::decode(&mut pulse.signature.into_inner().as_slice())
				.map_err(|e| format!("Failed to decode signature: {}", e))?;

		// m = sha256({}{round})
		let message = message(pulse.round, &vec![]);
		let hasher = <TinyBLS381 as EngineBLS>::hash_to_curve_map();
		// H(m) \in G1
		let message_hash =
			hasher.hash(&message).map_err(|e| format!("Failed to hash message: {}", e))?;

		let mut bytes = Vec::new();
		message_hash
			.serialize_compressed(&mut bytes)
			.map_err(|e| format!("Failed to serialize message hash: {}", e))?;

		let message_on_curve = ArkScale::<G1AffineOpt>::decode(&mut &bytes[..])
			.map_err(|e| format!("Failed to decode message on curve: {}", e))?;

		let g2 = G2AffineOpt::generator();

		let p1 = bls12_381::pairing_opt(-signature.0, g2);
		let p2 = bls12_381::pairing_opt(message_on_curve.0, pk.0);

		Ok(p1 == p2)
	}
}

pub struct UnsafeSkipVerifier;

impl Verifier for UnsafeSkipVerifier {
	fn verify(_beacon_config: BeaconConfiguration, _pulse: Pulse) -> Result<bool, String> {
		Ok(true)
	}
}

impl<T: Config> Randomness<T::Hash, BlockNumberFor<T>> for Pallet<T> {
	// this function hashes together the subject with the latest known randomness from quicknet
	fn random(subject: &[u8]) -> (T::Hash, BlockNumberFor<T>) {
		let block_number_minus_one = <frame_system::Pallet<T>>::block_number() - One::one();

		let mut entropy = T::Hash::default();
		if let Some(pulse) = Pulses::<T>::get(block_number_minus_one) {
			entropy = (subject, block_number_minus_one, pulse.randomness.clone())
				.using_encoded(T::Hashing::hash);
		}

		(entropy, block_number_minus_one)
	}
}
