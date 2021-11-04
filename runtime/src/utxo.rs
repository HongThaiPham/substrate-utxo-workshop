use super::Aura;
use codec::{Decode, Encode};
use frame_support::{
	decl_event, decl_module, decl_storage,
	dispatch::{DispatchResult, Vec},
	ensure,
};
use sp_core::{H256, H512};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::sr25519::{Public, Signature};
use sp_runtime::traits::{BlakeTwo256, Hash, SaturatedConversion};
use sp_std::collections::btree_map::BTreeMap;
use sp_runtime::transaction_validity::{TransactionLongevity, ValidTransaction};

pub trait Trait: system::Trait {
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

/// Single transaction input that refers to one UTXO
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionInput {
	/// Reference to an UTXO to be spent
	pub outpoint: H256,
	/// Proof that transaction owner is authorized to spend referred UTXO &
	/// that the entire transaction is untampered
	pub sigscript: H512, 
}

pub type Value = u128;
/// Single transaction output to create upon transaction dispatch
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionOutput {
	/// Value associated with this output
	pub value: Value, 
	/// Public key associated with this output. In order to spend this output
	/// owner must provide a proof by hashing the whole `Transaction` and
	/// signing it with a corresponding private key.
	pub pubkey: H256, 
}

/// Single transaction to be dispatched
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct Transaction {
	/// UTXOs to be used as inputs for current transaction
	pub inputs: Vec<TransactionInput>,
	/// UTXOs to be created as a result of current transaction dispatch
	pub outputs: Vec<TransactionOutput>
}

decl_storage! {
	trait Store for Module<T: Trait> as Utxo {
		UtxoStore build(|config: &GenesisConfig| {
			config.genesis_utxo
			.iter()
			.cloned()
			.map(|u| (BlakeTwo256::hash_of(&u),u))
			.collect::<Vec<_>>()
		}): map hasher(identity) H256 => Option<TransactionOutput>;


		/// Total reward value to be redistributed among authorities.
		/// It is accumulated from transactions during block execution
		/// and then dispersed to validators on block finalization.
		pub RewardTotal get(fn reward_total): Value;
	}

	add_extra_genesis {
		config(genesis_utxo): Vec<TransactionOutput>
	}
}

// External functions: callable by the end user
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;


		pub fn spend(_origin, transaction: Transaction) -> DispatchResult {
			// check the transaction is valid
			 
			// write to storage
			let reward : Value = 0;
			Self::update_storage(&transaction, reward);

			// emit success event
			Self::deposit_event(Event::TransactionSuccess(transaction));

			Ok(())
		}

		/// Handler called by the system on block finalization
		fn on_finalize() {
			let auth: Vec<_> = Aura::authorities().iter().map(|x| {
				let r: &Public = x.as_ref();
				r.0.into()
			}).collect();
			
			Self::disperse_reward(&auth);
			// match T::BlockAuthor::block_author() {
			// 	// Block author did not provide key to claim reward
			// 	None => Self::deposit_event(Event::RewardsWasted),
			// 	// Block author did provide key, so issue thir reward
			// 	Some(author) => Self::disperse_reward(&author),
			// }
		}
	}

}

decl_event! {
	pub enum Event {
		/// Transaction was executed successfully
		TransactionSuccess(Transaction),
	}
}


impl<T: Trait> Module<T> {
	/// Update storage to reflect changes made by transaction
	/// Where each utxo key is a hash of the entire transaction and its order in the TransactionOutputs vector
	fn update_storage(transaction: &Transaction, reward: Value) -> DispatchResult {
		// Calculate new reward total
		let new_total = <RewardTotal>::get()
			.checked_add(reward)
			.ok_or("Reward overflow")?;
		<RewardTotal>::put(new_total);

		// Removing spent UTXOs
		for input in &transaction.inputs {
			<UtxoStore>::remove(input.outpoint);
		}

		let mut index: u64 = 0;
		for output in &transaction.outputs {
			let hash = BlakeTwo256::hash_of(&(&transaction.encode(), index));
			index = index.checked_add(1).ok_or("output index overflow")?;
			<UtxoStore>::insert(hash, output);
		}
		Ok(())
	}

	/// Redistribute combined reward value to block Author
	fn disperse_reward(authorities: &[H256]) {
		//1. devide reward fairly
		let reward = <RewardTotal>::take();
		let shared_value: Value = reward
			.checked_div(authorities.len() as Value)
			.ok_or("No Authorities")
			.unwrap();

		if shared_value == 0 { return }

		let remainder = reward
			.checked_sub(shared_value * authorities.len() as Value)
			.ok_or("Sub underflow")
			.unwrap();

		<RewardTotal>::put(remainder as Value);

		//2. Create utxo per validator
		for authority in authorities {
			let utxo = TransactionOutput {
				value: shared_value,
				pubkey: *authority,
			};

			let hash = BlakeTwo256::hash_of(&(&utxo, 
											<system::Module<T>>::block_number().saturated_into::<u64>())
										);
			if !<UtxoStore>::contains_key(hash) {
				<UtxoStore>::insert(hash, utxo);
				sp_runtime::print("Transaction reward sent to");
				sp_runtime::print(hash.as_fixed_bytes() as &[u8]);
			} else {
				sp_runtime::print("Transaction reward wasted due to hash colission");
			}
		}
	}
}


/// Tests for this module
#[cfg(test)]
mod tests {
	use super::*;

	use frame_support::{assert_ok, assert_err, impl_outer_origin, parameter_types, weights::Weight};
	use sp_runtime::{testing::Header, traits::IdentityLookup, Perbill};
	use sp_core::testing::{KeyStore, SR25519};
	use sp_core::traits::KeystoreExt;

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	parameter_types! {
			pub const BlockHashCount: u64 = 250;
			pub const MaximumBlockWeight: Weight = 1024;
			pub const MaximumBlockLength: u32 = 2 * 1024;
			pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
	}
	impl system::Trait for Test {
		type Origin = Origin;
		type Call = ();
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type Event = ();
		type BlockHashCount = BlockHashCount;
		type MaximumBlockWeight = MaximumBlockWeight;
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
		type ModuleToIndex = ();
		type AccountData = ();
		type OnNewAccount = ();
		type OnKilledAccount = ();
	}
	impl Trait for Test {
		type Event = ();
	}

	type Utxo = Module<Test>;

}
