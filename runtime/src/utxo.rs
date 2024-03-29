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
			let transaction_validity = Self::validate_transaction(&transaction)?;
			// write to storage
			Self::update_storage(&transaction, transaction_validity.priority as Value)?;

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
	// Strips a transaction of its Signature fields by replacing value with ZERO-initialized fixed hash.
	pub fn get_simple_transaction(transaction: &Transaction) -> Vec<u8> {//&'a [u8] {
		let mut trx = transaction.clone();
		for input in trx.inputs.iter_mut() {
			input.sigscript = H512::zero();
		}

		trx.encode()
	}

	/// Check transaction for validity, errors, & race conditions
	/// Called by both transaction pool and runtime execution
	///
	/// Ensures that:
	/// - inputs and outputs are not empty
	/// - all inputs match to existing, unspent and unlocked outputs
	/// - each input is used exactly once
	/// - each output is defined exactly once and has nonzero value
	/// - total output value must not exceed total input value
	/// - new outputs do not collide with existing ones
	/// - sum of input and output values does not overflow
	/// - provided signatures are valid
	/// - transaction outputs cannot be modified by malicious nodes
	pub fn validate_transaction(transaction: &Transaction) -> Result<ValidTransaction, &'static str> {
		// Check basic requirements
		ensure!(!transaction.inputs.is_empty(), "no inputs");
		ensure!(!transaction.outputs.is_empty(), "no outputs");

		{
			let input_set: BTreeMap<_, ()> =transaction.inputs.iter().map(|input| (input, ())).collect();
			ensure!(input_set.len() == transaction.inputs.len(), "each input must only be used once");
		}
		{
			let output_set: BTreeMap<_, ()> = transaction.outputs.iter().map(|output| (output, ())).collect();
			ensure!(output_set.len() == transaction.outputs.len(), "each output must be defined only once");
		}

		let mut total_input: Value = 0;
		let mut total_output: Value = 0;
		let mut output_index: u64 = 0;
		let simple_transaction = Self::get_simple_transaction(transaction);

		// Variables sent to transaction pool
		let mut missing_utxos = Vec::new();
		let mut new_utxos = Vec::new();
		let mut reward = 0;


		// Check that inputs are valid
		for input in transaction.inputs.iter() {
			if let Some(input_utxo) = <UtxoStore>::get(&input.outpoint) {
				ensure!(sp_io::crypto::sr25519_verify(
					&Signature::from_raw(*input.sigscript.as_fixed_bytes()),
					&simple_transaction,
					&Public::from_h256(input_utxo.pubkey)
				), "signature must be valid" );
				total_input = total_input.checked_add(input_utxo.value).ok_or("input value overflow")?;
			} else {
				missing_utxos.push(input.outpoint.clone().as_fixed_bytes().to_vec());
			}
		}

		// Check that outputs are valid
		for output in transaction.outputs.iter() {
			ensure!(output.value > 0, "output value must be nonzero");
			let hash = BlakeTwo256::hash_of(&(&transaction.encode(), output_index));
			output_index = output_index.checked_add(1).ok_or("output index overflow")?;
			ensure!(!<UtxoStore>::contains_key(hash), "output already exists");
			total_output = total_output.checked_add(output.value).ok_or("output value overflow")?;
			new_utxos.push(hash.as_fixed_bytes().to_vec());
		}

		// If no race condition, check the math
		if missing_utxos.is_empty() {
			ensure!( total_input >= total_output, "output value must not exceed input value");
			reward = total_input.checked_sub(total_output).ok_or("reward underflow")?;
		}

		Ok(ValidTransaction {
			requires: missing_utxos,
			provides: new_utxos,
			priority: reward as u64,
			longevity: TransactionLongevity::max_value(),
			propagate: true,
		})
		
	}

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

	// need to manually import this crate since its no include by default
	use hex_literal::hex;

	const ALICE_PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

	const GENESIS_UTXO: [u8; 32] = hex!("79eabcbd5ef6e958c6a7851b36da07691c19bda1835a08f875aa286911800999");

	// This function basically just builds a genesis storage key/value store according to our desired mockup.
	// We start each test by giving Alice 100 utxo to start with.
	fn new_test_ext() -> sp_io::TestExternalities {

		let keystore = KeyStore::new(); // a key storage to store new key pairs during testing
		let alice_pub_key = keystore.write().sr25519_generate_new(SR25519, Some(ALICE_PHRASE)).unwrap();

		let mut t = system::GenesisConfig::default()
			.build_storage::<Test>()
			.unwrap();

		t.top.extend(
			GenesisConfig {
				genesis_utxo: vec![
					TransactionOutput {
						value: 100,
						pubkey: H256::from(alice_pub_key),
					}
				],
				..Default::default()
			}
			.build_storage()
			.unwrap()
			.top,
		);

		// Print the values to get GENESIS_UTXO
		let mut ext = sp_io::TestExternalities::from(t);
		ext.register_extension(KeystoreExt(keystore));
		ext
	}

	#[test]
	fn test_simple_transaction() {
		new_test_ext().execute_with(|| {
			let alice_pub_key = sp_io::crypto::sr25519_public_keys(SR25519)[0];

			// Alice wants to send herself a new utxo of value 50.
			let mut transaction = Transaction {
				inputs: vec![TransactionInput {
					outpoint: H256::from(GENESIS_UTXO),
					sigscript: H512::zero(),
				}],
				outputs: vec![TransactionOutput {
					value: 50,
					pubkey: H256::from(alice_pub_key),
				}],
			};

			let alice_signature = sp_io::crypto::sr25519_sign(SR25519, &alice_pub_key, &transaction.encode()).unwrap();
			transaction.inputs[0].sigscript = H512::from(alice_signature);
			let new_utxo_hash = BlakeTwo256::hash_of(&(&transaction.encode(), 0 as u64));

			// spend will be ok
			assert_ok!(Utxo::spend(Origin::signed(0), transaction));

			// old utxo is gone
			assert!(!UtxoStore::contains_key(H256::from(GENESIS_UTXO)));

			// new utxo exists and value = 50
			assert!(UtxoStore::contains_key(new_utxo_hash));
			assert_eq!(50, UtxoStore::get(new_utxo_hash).unwrap().value);
		});
	}


}
