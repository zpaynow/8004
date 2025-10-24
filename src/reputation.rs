use crate::{Eip8004, hash_to_bytes32, ipfs, parse_address, str_to_bytes32};
use alloy::{
    primitives::{Address, Bytes, Signature, U256, eip191_hash_message, keccak256},
    providers::ProviderBuilder,
    signers::{Signer, local::PrivateKeySigner},
    sol,
    sol_types::SolValue,
};
use anyhow::{Result, anyhow};
use chrono::prelude::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ReputationRegistry,
    "abi/ReputationRegistry.abi.json"
);

sol!(
    #[derive(Debug)]
    struct FeedbackOnchainAuth {
        uint256 agentId;
        address clientAddress;
        uint64 indexLimit;
        uint256 expiry;
        uint256 chainId;
        address identityRegistry;
        address signerAddress;
        bytes memory signature;
    }
);

/// The feedback, which can upload to ipfs and onchain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Feedback {
    /// agent registration
    /// e.g. "eip155:1:{identityRegistry}"
    pub agent_registry: String,
    /// agent id
    pub agent_id: i64,
    /// client address info
    /// e.g. "eip155:1:{clientAddress}"
    pub client_address: String,
    /// the auth signed value with hex style
    pub feedback_auth: String,
    /// the score
    pub socre: u8,
    /// the feedback created time
    pub created_at: Option<NaiveDateTime>,
    /// tag defined by developer
    pub tag1: Option<String>,
    /// tag defined by developer
    pub tag2: Option<String>,
    /// defined by developer, e.g. as-defined-by-A2A
    pub skill: Option<String>,
    /// defined by developer, e.g. as-defined-by-A2A
    pub context: Option<String>,
    /// defined by developer, e.g. as-defined-by-A2A
    pub task: Option<String>,
    /// As per MCP: "prompts", "resources", "tools" or "completions"
    pub capability: Option<String>,
    /// As per MCP: the name of the prompt, resource or tool
    pub name: Option<String>,
    /// x402 proof of payment
    #[serde(rename = "proof_of_payment")]
    pub proof_of_payment: Option<ProofOfPayment>,
}

impl Feedback {
    /// serialize metadata to json string and hash it
    pub fn to_json_and_hash(&self) -> (String, String) {
        let content = serde_json::to_string(self).unwrap_or_default();
        let hash = keccak256(&content);
        (content, hex::encode(hash))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackAuth {
    pub agent_id: i64,
    pub client_address: String,
    pub index_limit: u64,
    pub expiry: i64,
    pub chain_id: i64,
    pub identity_registry: String,
    pub signer_address: String,
    /// EIP-191 or ERC-1271 signature with above fields
    pub signature: Option<String>,
}

impl FeedbackOnchainAuth {
    /// Convert from FeedbackAuth
    pub fn from_feedback_auth(auth: FeedbackAuth) -> Result<Self> {
        let client_address = parse_address(&auth.client_address)?;
        let identity_registry = parse_address(&auth.identity_registry)?;
        let signer_address = parse_address(&auth.signer_address)?;

        let signature = if let Some(sig) = auth.signature {
            let sig_bytes = hex::decode(sig.trim_start_matches("0x"))?;
            Bytes::from(sig_bytes)
        } else {
            Bytes::default()
        };

        Ok(Self {
            agentId: U256::from(auth.agent_id),
            clientAddress: client_address,
            indexLimit: auth.index_limit,
            expiry: U256::from(auth.expiry),
            chainId: U256::from(auth.chain_id),
            identityRegistry: identity_registry,
            signerAddress: signer_address,
            signature,
        })
    }

    /// from encode hex string, back to FeedbackOnchainAuth
    /// Decodes ABI-encoded bytes
    pub fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim_start_matches("0x"))?;
        let decoded = Self::abi_decode(&bytes)?;
        Ok(decoded)
    }

    /// to FeedbackOnchainAuth, and then encode to hex string
    pub fn to_string(&self) -> String {
        let bytes = self.to_bytes();
        format!("0x{}", hex::encode(bytes))
    }

    /// Encode to ABI bytes
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.abi_encode())
    }

    /// Sign the FeedbackOnchainAuth with EIP-191
    /// Creates a message hash from the struct fields (excluding signature) and signs it
    /// Returns the signature as a hex string with "0x" prefix
    pub async fn sign(&self, signer: &PrivateKeySigner) -> Result<String> {
        // Create message to sign by encoding the struct fields (without signature)
        let message = self.encode_for_signing();

        // Hash with EIP-191 prefix: "\x19Ethereum Signed Message:\n" + len(message) + message
        let message_hash = eip191_hash_message(&message);

        // Sign the message hash
        let signature = signer.sign_hash(&message_hash).await?;

        // Return as hex string
        Ok(format!("0x{}", hex::encode(signature.as_bytes())))
    }

    /// Encode the struct fields for signing (excluding signature field)
    fn encode_for_signing(&self) -> Vec<u8> {
        // Encode all fields except signature using ABI encoding
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.agentId.to_be_bytes::<32>());
        encoded.extend_from_slice(self.clientAddress.as_slice());
        encoded.extend_from_slice(&self.indexLimit.to_be_bytes());
        encoded.extend_from_slice(&self.expiry.to_be_bytes::<32>());
        encoded.extend_from_slice(&self.chainId.to_be_bytes::<32>());
        encoded.extend_from_slice(self.identityRegistry.as_slice());
        encoded.extend_from_slice(self.signerAddress.as_slice());
        encoded
    }

    /// Verify the signature with EIP-191
    /// Recovers the signer from the signature and compares with signerAddress
    /// Note: This only handles EIP-191 verification, not ERC-1271 smart contract signatures
    pub fn verify(&self) -> Result<bool> {
        // Check if signature exists and has valid length (65 bytes)
        if self.signature.len() != 65 {
            return Ok(false);
        }

        // Parse signature bytes (r: 32 bytes, s: 32 bytes, v: 1 byte)
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature[..64]);

        // Get the v value (recovery id)
        let v = self.signature[64];

        // Normalize v to 0 or 1 (some implementations use 27/28)
        let parity = if v >= 27 { v - 27 } else { v };

        // Create signature
        let signature = Signature::from_bytes_and_parity(&sig_bytes, parity != 0);

        // Create message to verify
        let message = self.encode_for_signing();

        // Hash with EIP-191 prefix
        let message_hash = eip191_hash_message(&message);

        // Recover signer address from signature
        let recovered_address = signature.recover_address_from_prehash(&message_hash)?;

        // Compare with signerAddress
        Ok(recovered_address == self.signerAddress)
    }
}

/// Proof of payment, this can be used for x402 proof of payment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOfPayment {
    /// from(payer) address
    pub from_address: String,
    /// to(payee) address
    pub to_address: String,
    /// the chain id
    pub chain_id: String,
    /// the tx hash
    pub tx_hash: String,
}

impl Eip8004 {
    /// used as FeedbackAuth's index_limit
    pub async fn get_feedback_index(&self, agent: i64, client: &str) -> Result<u64> {
        let client = parse_address(client)?;
        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let index = contract
            .getLastIndex(U256::from(agent), client)
            .call()
            .await?;

        Ok(index)
    }

    /// The agentId must be a validly registered agent.
    /// The score MUST be between 0 and 100. tag1, tag2, and uri are OPTIONAL.
    /// feedbackAuth is a tuple with the structure
    /// (agentId, clientAddress, indexLimit, expiry, chainId, identityRegistry, signerAddress)
    /// signed using EIP-191 or ERC-1271 (if clientAddress is a smart contract).
    /// The signerAddress field identifies the agent owner or operator who signed.
    /// Return the index and tx hash
    pub async fn give_feedback_with_ipfs(&self, mut feedback: Feedback) -> Result<(u64, String)> {
        self.check_reputation()?;

        // if created_at is missing, add it
        if feedback.created_at.is_none() {
            feedback.created_at = Some(Utc::now().naive_utc());
        }

        // Upload feedback to ipfs
        let file = serde_json::to_string(&feedback)?;
        let uri = ipfs::upload(&self.clone_ipfs()?, file).await?;

        // Call give_feedback_with_uri
        self.give_feedback(&uri, "", &feedback).await
    }

    /// Feedback with given off-chain uri and file hash, return the index and tx hash
    pub async fn give_feedback(
        &self,
        uri: &str,
        hash: &str,
        feedback: &Feedback,
    ) -> Result<(u64, String)> {
        self.check_reputation()?;
        let agent = feedback.agent_id;
        let client = parse_address(&feedback.client_address)?;

        let signer = self.clone_signer()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        // fetch feedback index
        let index = contract
            .getLastIndex(U256::from(agent), client)
            .call()
            .await?;

        // Convert tags to bytes32
        let tag1_bytes = str_to_bytes32(&feedback.tag1);
        let tag2_bytes = str_to_bytes32(&feedback.tag2);
        let file_hash = hash_to_bytes32(hash);

        // Parse feedback_auth as bytes
        let feedback_auth = FeedbackOnchainAuth::from_str(&feedback.feedback_auth)?;

        let call = contract.giveFeedback(
            U256::from(feedback.agent_id),
            feedback.socre,
            tag1_bytes,
            tag2_bytes,
            uri.to_owned(),
            file_hash,
            feedback_auth.to_bytes(),
        );

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        Ok((index, format!("{:?}", receipt.transaction_hash)))
    }

    /// Revoke the feedback by agent and client address
    pub async fn revoke_feedback(&self, agent: i64, client: &str, index: u64) -> Result<String> {
        self.check_reputation()?;
        let client = parse_address(client)?;

        let signer = self.clone_signer()?;
        let signer_address = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        if client != signer_address {
            return Err(anyhow!("Sender is not client"));
        }

        let call = contract.revokeFeedback(U256::from(agent), index);

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        Ok(format!("{:?}", receipt.transaction_hash))
    }

    /// Append more feedback to agent with ipfs
    pub async fn append_response_with_ipfs(
        &self,
        agent: i64,
        client: &str,
        index: u64,
        response: String,
    ) -> Result<String> {
        // Upload feedback to ipfs
        let uri = ipfs::upload(&self.clone_ipfs()?, response).await?;

        self.append_response(agent, client, index, &uri, "").await
    }

    /// Append more feedback to agent
    pub async fn append_response(
        &self,
        agent: i64,
        client: &str,
        index: u64,
        response_uri: &str,
        response_hash: &str,
    ) -> Result<String> {
        self.check_reputation()?;
        let client = parse_address(client)?;

        let signer = self.clone_signer()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let response_hash = hash_to_bytes32(response_hash);

        let call = contract.appendResponse(
            U256::from(agent),
            client,
            index,
            response_uri.to_owned(),
            response_hash,
        );

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        Ok(format!("{:?}", receipt.transaction_hash))
    }

    /// Get agent's summary
    /// agentId is the only mandatory parameter; others are optional filters.
    /// Without filtering by clientAddresses, results are subject to Sybil/spam attacks.
    /// See Security Considerations for details
    pub async fn get_summary(
        &self,
        agent: i64,
        clients: Option<Vec<String>>,
        tag1: Option<String>,
        tag2: Option<String>,
    ) -> Result<(u64, u8)> {
        self.check_reputation()?;

        let clients = if let Some(clients) = clients {
            let mut new_clients = vec![];
            for c in clients.iter() {
                new_clients.push(parse_address(c)?);
            }
            new_clients
        } else {
            self.get_clients(agent).await?
        };

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let tag1_bytes = str_to_bytes32(&tag1);
        let tag2_bytes = str_to_bytes32(&tag2);

        let result = contract
            .getSummary(U256::from(agent), clients, tag1_bytes, tag2_bytes)
            .call()
            .await?;

        Ok((result.count, result.averageScore))
    }

    /// Get client's feedback for agent, returns score, tag1, tag2, is_revoked
    pub async fn read_feedback(
        &self,
        agent: i64,
        client: &str,
        index: u64,
    ) -> Result<(u8, [u8; 32], [u8; 32], bool)> {
        self.check_reputation()?;

        // Parse client address - support both raw address and "eip155:1:{address}" format
        let client = parse_address(client)?;

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let result = contract
            .readFeedback(U256::from(agent), client, index)
            .call()
            .await?;

        Ok((result.score, result.tag1.0, result.tag2.0, result.isRevoked))
    }

    /// agentId is the only mandatory parameter; others are optional filters. Revoked feedback are omitted.
    /// Returns (client_addresses, scores, tag1s, tag2s, revoked_statuses)
    pub async fn read_all_feedback(
        &self,
        agent: i64,
        clients: Option<Vec<String>>,
        tag1: Option<String>,
        tag2: Option<String>,
        include_revoked: bool,
    ) -> Result<(
        Vec<Address>,
        Vec<u8>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        Vec<bool>,
    )> {
        self.check_reputation()?;

        let clients = if let Some(clients) = clients {
            let mut new_clients = vec![];
            for c in clients.iter() {
                new_clients.push(parse_address(c)?);
            }
            new_clients
        } else {
            self.get_clients(agent).await?
        };

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let tag1_bytes = str_to_bytes32(&tag1);
        let tag2_bytes = str_to_bytes32(&tag2);

        let result = contract
            .readAllFeedback(
                U256::from(agent),
                clients,
                tag1_bytes,
                tag2_bytes,
                include_revoked,
            )
            .call()
            .await?;

        // Convert FixedBytes to [u8; 32] arrays
        let tag1s: Vec<[u8; 32]> = result.tag1s.iter().map(|t| t.0).collect();
        let tag2s: Vec<[u8; 32]> = result.tag2s.iter().map(|t| t.0).collect();

        Ok((
            result.clients,
            result.scores,
            tag1s,
            tag2s,
            result.revokedStatuses,
        ))
    }

    /// Get response count for a specific feedback, optionally filtered by responders
    pub async fn get_response_count(
        &self,
        agent: i64,
        client: &str,
        index: u64,
        responders: Vec<String>,
    ) -> Result<u64> {
        self.check_reputation()?;

        let client = parse_address(client)?;

        let mut responder_addresses = vec![];
        for r in responders.iter() {
            responder_addresses.push(parse_address(r)?);
        }

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let count = contract
            .getResponseCount(U256::from(agent), client, index, responder_addresses)
            .call()
            .await?;

        Ok(count)
    }

    /// List all clients of agent
    pub async fn get_clients(&self, agent: i64) -> Result<Vec<Address>> {
        self.check_reputation()?;
        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let result = contract.getClients(U256::from(agent)).call().await?;

        Ok(result)
    }
}
