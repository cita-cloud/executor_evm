// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::Bytes;
use crate::types::block_number::BlockNumber;
use crate::types::LowerHex;
use crate::types::{clean_0x, Address, H256, U256};
use cita_cloud_proto::blockchain::UnverifiedTransaction as CloudUnverifiedTransaction;
use cita_crypto::{
    pubkey_to_address, PubKey, Signature, HASH_BYTES_LEN, PUBKEY_BYTES_LEN, SIGNATURE_BYTES_LEN,
};
use libproto::blockchain::{
    Crypto as ProtoCrypto, SignedTransaction as ProtoSignedTransaction,
    Transaction as ProtoTransaction, UnverifiedTransaction as ProtoUnverifiedTransaction,
};
use rlp::*;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
pub const STORE_ADDRESS: &str = "ffffffffffffffffffffffffffffffffff010000";
pub const ABI_ADDRESS: &str = "ffffffffffffffffffffffffffffffffff010001";
pub const AMEND_ADDRESS: &str = "ffffffffffffffffffffffffffffffffff010002";

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Error {
    ParseError,
    InvalidHash,
    InvalidSignature,
    InvalidPubKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// Transaction action type.
pub enum Action {
    /// Just store the data.
    #[default]
    Store,
    /// Create creates new contract.
    Create,
    /// Calls contract at given address.
    /// In the case of a transfer, this is the receiver's address.'
    Call(Address),
    /// Store the contract ABI
    AbiStore,
    /// amend data in state
    AmendData,
}

impl Decodable for Action {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_empty() {
            Ok(Action::Create)
        } else {
            let store_addr: Address = Address::from_str(STORE_ADDRESS).unwrap();
            let abi_addr: Address = Address::from_str(ABI_ADDRESS).unwrap();
            let amend_addr: Address = Address::from_str(AMEND_ADDRESS).unwrap();
            let addr: Address = rlp.as_val()?;
            if addr == store_addr {
                Ok(Action::Store)
            } else if addr == abi_addr {
                Ok(Action::AbiStore)
            } else if addr == amend_addr {
                Ok(Action::AmendData)
            } else {
                Ok(Action::Call(addr))
            }
        }
    }
}

impl Encodable for Action {
    fn rlp_append(&self, s: &mut RlpStream) {
        let store_addr: Address = Address::from_str(STORE_ADDRESS).unwrap();
        let abi_addr: Address = Address::from_str(ABI_ADDRESS).unwrap();
        let amend_addr: Address = Address::from_str(AMEND_ADDRESS).unwrap();
        match *self {
            Action::Create => s.append_internal(&""),
            Action::Call(ref addr) => s.append_internal(addr),
            Action::Store => s.append_internal(&store_addr),
            Action::AbiStore => s.append_internal(&abi_addr),
            Action::AmendData => s.append_internal(&amend_addr),
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// crypto type.
pub enum CryptoType {
    #[default]
    Default,
    Reserved,
}

impl Decodable for CryptoType {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.as_val::<u8>()? {
            0 => Ok(CryptoType::Default),
            1 => Ok(CryptoType::Reserved),
            _ => Err(DecoderError::Custom("Unknown Type.")),
        }
    }
}

impl Encodable for CryptoType {
    fn rlp_append(&self, s: &mut RlpStream) {
        match *self {
            CryptoType::Default => s.append_internal(&(0u8)),
            CryptoType::Reserved => s.append_internal(&(1u8)),
        };
    }
}

impl From<ProtoCrypto> for CryptoType {
    fn from(c: ProtoCrypto) -> CryptoType {
        match c {
            ProtoCrypto::DEFAULT => CryptoType::Default,
            ProtoCrypto::RESERVED => CryptoType::Reserved,
        }
    }
}

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Nonce.
    pub nonce: String,
    /// Gas price.
    pub gas_price: U256,
    /// Gas paid up front for transaction execution.
    pub gas: U256,
    /// Action, can be either call or contract create.
    pub action: Action,
    /// Transfered value.
    pub value: U256,
    /// Transaction data.
    pub data: Bytes,
    /// valid before this block number
    pub block_limit: BlockNumber,
    /// Unique chain_id
    // Before it's u32
    pub chain_id: U256,
    /// transaction version
    pub version: u32,
}

impl Decodable for Transaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 9 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let version = d.val_at(8)?;

        Ok(Transaction {
            nonce: d.val_at(0)?,
            gas_price: d.val_at(1)?,
            gas: d.val_at(2)?,
            action: d.val_at(3)?,
            value: d.val_at(4)?,
            data: d.val_at(5)?,
            block_limit: d.val_at(6)?,
            chain_id: if version == 0 {
                d.val_at::<u32>(7)?.into()
            } else {
                d.val_at::<U256>(7)?
            },
            version,
        })
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.rlp_append_unsigned_transaction(s)
    }
}

impl Transaction {
    // Should never return Error
    pub fn create(plain_transaction: &ProtoTransaction) -> Result<Self, Error> {
        if plain_transaction.get_value().len() > 32 {
            return Err(Error::ParseError);
        }

        let version = plain_transaction.get_version();
        Ok(Transaction {
            nonce: plain_transaction.get_nonce().to_owned(),
            gas_price: U256::default(),
            gas: U256::from(plain_transaction.get_quota()),
            action: {
                if version == 0 {
                    let to = clean_0x(plain_transaction.get_to());
                    match to {
                        "" => Action::Create,
                        STORE_ADDRESS => Action::Store,
                        ABI_ADDRESS => Action::AbiStore,
                        AMEND_ADDRESS => Action::AmendData,
                        _ => Action::Call(Address::from_str(to).map_err(|_| Error::ParseError)?),
                    }
                } else {
                    let to = plain_transaction.get_to_v1();
                    if to.is_empty() {
                        Action::Create
                    } else {
                        let to_addr = Address::from_slice(to);
                        match to_addr.lower_hex().as_str() {
                            STORE_ADDRESS => Action::Store,
                            ABI_ADDRESS => Action::AbiStore,
                            AMEND_ADDRESS => Action::AmendData,
                            _ => Action::Call(to_addr),
                        }
                    }
                }
            },
            value: U256::from(plain_transaction.get_value()),
            data: Bytes::from(plain_transaction.get_data()),
            block_limit: plain_transaction.get_valid_until_block(),
            chain_id: if version == 0 {
                plain_transaction.get_chain_id().into()
            } else {
                plain_transaction.get_chain_id_v1().into()
            },
            version,
        })
    }

    pub fn nonce(&self) -> &String {
        &self.nonce
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn gas_price(&self) -> U256 {
        self.gas_price
    }

    // Specify the sender; this won't survive the serialize/deserialize process, but can be cloned.
    pub fn fake_sign(self, from: Address) -> SignedTransaction {
        let signature = Signature::default();
        SignedTransaction {
            transaction: UnverifiedTransaction {
                unsigned: self,
                signature,
                hash: H256::from_low_u64_le(0),
                crypto_type: CryptoType::default(),
            },
            sender: from,
            public: PubKey::default(),
        }
    }

    /// Append object with a without signature into RLP stream
    pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.block_limit);
        if self.version == 0u32 {
            s.append::<u32>(&self.chain_id.low_u32());
        } else {
            s.append::<U256>(&self.chain_id);
        }
        s.append(&self.version);
    }

    /// get the protobuf transaction
    pub fn proto_transaction(&self) -> ProtoTransaction {
        let mut pt = ProtoTransaction::new();
        pt.set_nonce(self.nonce.clone());
        pt.set_valid_until_block(self.block_limit);
        pt.set_data(self.data.clone());
        pt.set_quota(self.gas.as_u64());
        pt.set_value(<[u8; 32]>::from(self.value).to_vec());
        if self.version == 0 {
            pt.set_chain_id(self.chain_id.low_u32());
        } else {
            pt.set_chain_id_v1(<[u8; 32]>::from(self.chain_id).to_vec());
        }
        pt.set_version(self.version);

        if self.version == 0 {
            match self.action {
                Action::Create => pt.clear_to(),
                Action::Call(ref to) => pt.set_to(to.lower_hex()),
                Action::Store => pt.set_to(STORE_ADDRESS.into()),
                Action::AbiStore => pt.set_to(ABI_ADDRESS.into()),
                Action::AmendData => pt.set_to(AMEND_ADDRESS.into()),
            }
        } else {
            match self.action {
                Action::Create => pt.clear_to(),
                Action::Call(ref to) => pt.set_to_v1(to.0.to_vec()),
                Action::Store => pt.set_to_v1(Address::from_str(STORE_ADDRESS).unwrap().0.to_vec()),
                Action::AbiStore => {
                    pt.set_to_v1(Address::from_str(ABI_ADDRESS).unwrap().0.to_vec())
                }
                Action::AmendData => {
                    pt.set_to_v1(Address::from_str(AMEND_ADDRESS).unwrap().0.to_vec())
                }
            }
        }
        pt
    }
}

/// Signed transaction information without verified signature.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedTransaction {
    /// Plain Transaction.
    unsigned: Transaction,
    /// The signature
    signature: Signature,
    /// The Crypto Type
    crypto_type: CryptoType,
    /// Hash of the transaction
    hash: H256,
}

impl Deref for UnverifiedTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.unsigned
    }
}

impl DerefMut for UnverifiedTransaction {
    fn deref_mut(&mut self) -> &mut Transaction {
        &mut self.unsigned
    }
}

impl Decodable for UnverifiedTransaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(UnverifiedTransaction {
            unsigned: d.val_at(0)?,
            signature: d.val_at(1)?,
            crypto_type: d.val_at(2)?,
            hash: d.val_at(3)?,
        })
    }
}

impl Encodable for UnverifiedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.rlp_append_sealed_transaction(s)
    }
}

impl UnverifiedTransaction {
    fn create(utx: &ProtoUnverifiedTransaction, hash: H256) -> Result<Self, Error> {
        if utx.get_signature().len() != SIGNATURE_BYTES_LEN {
            return Err(Error::InvalidSignature);
        }

        Ok(UnverifiedTransaction {
            unsigned: Transaction::create(utx.get_transaction())?,
            signature: Signature::from(utx.get_signature()),
            crypto_type: CryptoType::from(utx.get_crypto()),
            hash,
        })
    }

    /// Append object with a signature into RLP stream
    fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.unsigned);
        s.append(&self.signature);
        s.append(&self.crypto_type);
        s.append(&self.hash);
    }

    ///    Reference to unsigned part of this transaction.
    pub fn as_unsigned(&self) -> &Transaction {
        &self.unsigned
    }

    pub fn hash(&self) -> H256 {
        self.hash
    }

    /// get protobuf unverified transaction
    pub fn proto_unverified(&self) -> ProtoUnverifiedTransaction {
        let mut untx = ProtoUnverifiedTransaction::new();
        let tx = self.unsigned.proto_transaction();

        untx.set_transaction(tx);
        untx.set_signature(self.signature.to_vec());

        match self.crypto_type {
            CryptoType::Default => untx.set_crypto(ProtoCrypto::DEFAULT),
            CryptoType::Reserved => untx.set_crypto(ProtoCrypto::RESERVED),
        }
        untx
    }
}

/// A `UnverifiedTransaction` with successfully recovered `sender`.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    transaction: UnverifiedTransaction,
    sender: Address,
    public: PubKey,
}

/// RLP dose not support struct nesting well
impl Decodable for SignedTransaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 14 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let version = d.val_at(8)?;

        Ok(SignedTransaction {
            transaction: UnverifiedTransaction {
                unsigned: Transaction {
                    nonce: d.val_at(0)?,
                    gas_price: d.val_at(1)?,
                    gas: d.val_at(2)?,
                    action: d.val_at(3)?,
                    value: d.val_at(4)?,
                    data: d.val_at(5)?,
                    block_limit: d.val_at(6)?,
                    chain_id: if version == 0u32 {
                        d.val_at::<u32>(7)?.into()
                    } else {
                        d.val_at(7)?
                    },
                    version,
                },
                signature: d.val_at(9)?,
                crypto_type: d.val_at(10)?,
                hash: d.val_at(11)?,
            },
            sender: d.val_at(12)?,
            public: d.val_at(13)?,
        })
    }
}

/// RLP dose not support struct nesting well
impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(14);

        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.block_limit);
        if self.version == 0u32 {
            s.append::<u32>(&self.chain_id.low_u32());
        } else {
            s.append::<U256>(&self.chain_id);
        }
        s.append(&self.version);

        s.append(&self.signature);
        s.append(&self.crypto_type);
        s.append(&self.hash);
        s.append(&self.sender);
        //TODO: remove it
        s.append(&self.public);
    }
}

impl Deref for SignedTransaction {
    type Target = UnverifiedTransaction;
    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl DerefMut for SignedTransaction {
    fn deref_mut(&mut self) -> &mut UnverifiedTransaction {
        &mut self.transaction
    }
}

impl From<CloudUnverifiedTransaction> for SignedTransaction {
    fn from(ctx: CloudUnverifiedTransaction) -> Self {
        if let Some(raw_tx) = ctx.transaction {
            let action = {
                match hex::encode(raw_tx.to.as_slice()).as_str() {
                    "" => Action::Create,
                    STORE_ADDRESS => Action::Store,
                    ABI_ADDRESS => Action::AbiStore,
                    AMEND_ADDRESS => Action::AmendData,
                    _ => Action::Call(Address::from_slice(raw_tx.to.as_slice())),
                }
            };
            let tx = Transaction {
                nonce: raw_tx.nonce,
                gas_price: U256::one(),
                gas: U256::from(raw_tx.quota),
                action,
                value: U256::from(raw_tx.value.as_slice()),
                data: raw_tx.data,
                block_limit: raw_tx.valid_until_block,
                chain_id: U256::from(raw_tx.chain_id.as_slice()),
                version: raw_tx.version,
            };
            let utx = UnverifiedTransaction {
                unsigned: tx,
                signature: Signature::default(),
                crypto_type: CryptoType::Default,
                hash: H256::from_slice(ctx.transaction_hash.as_slice()),
            };
            return SignedTransaction {
                transaction: utx,
                sender: Address::from_slice(ctx.witness.unwrap().sender.as_slice()), // tx must have sender
                public: PubKey::default(),
            };
        }

        unreachable!()
    }
}

impl SignedTransaction {
    /// Try to verify transaction and recover sender.
    pub fn create(stx: &ProtoSignedTransaction) -> Result<Self, Error> {
        if stx.get_tx_hash().len() != HASH_BYTES_LEN {
            return Err(Error::InvalidHash);
        }

        if stx.get_signer().len() != PUBKEY_BYTES_LEN {
            return Err(Error::InvalidPubKey);
        }

        let tx_hash = H256::from_slice(stx.get_tx_hash());
        let public = PubKey::from_slice(stx.get_signer());
        let sender = pubkey_to_address(&public);
        Ok(SignedTransaction {
            transaction: UnverifiedTransaction::create(stx.get_transaction_with_sig(), tx_hash)?,
            sender,
            public,
        })
    }

    /// Returns the cached tx_hash.
    pub fn get_transaction_hash(&self) -> H256 {
        self.transaction.hash()
    }

    /// Returns transaction sender.
    pub fn sender(&self) -> &Address {
        &self.sender
    }

    /// Returns a public key of the sender.
    pub fn public_key(&self) -> &PubKey {
        &self.public
    }

    ///get protobuf of signed transaction
    pub fn protobuf(&self) -> ProtoSignedTransaction {
        let mut stx = ProtoSignedTransaction::new();
        let utx = self.transaction.proto_unverified();
        stx.set_transaction_with_sig(utx);
        stx.set_tx_hash(self.hash().as_bytes().to_vec());
        stx.set_signer(self.public.as_bytes().to_vec());
        stx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlp;

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_encode_and_decode() {
        let mut stx = SignedTransaction::default();
        stx.data = vec![1; 200];
        let stx_rlp = rlp::encode(&stx);
        let stx: SignedTransaction = rlp::decode(&stx_rlp).unwrap();
        let stx_encoded = rlp::encode(&stx).to_vec();

        assert_eq!(stx_rlp, stx_encoded);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_protobuf() {
        let mut stx = SignedTransaction::default();
        stx.gas = U256::from(u64::MAX / 100000);
        let stx_proto = stx.protobuf();
        let stx = SignedTransaction::create(&stx_proto).unwrap();
        let stx_rlp = rlp::encode(&stx).to_vec();
        let stx: SignedTransaction = rlp::decode(&stx_rlp).unwrap();
        let stx_encoded = rlp::encode(&stx).to_vec();

        assert_eq!(stx_rlp, stx_encoded);
    }

    #[test]
    fn invalid_value() {
        let mut plain_transaction = ProtoTransaction::new();
        plain_transaction.set_value(vec![0; 100]);

        let res = Transaction::create(&plain_transaction);

        assert!(res.is_err());
    }
}
