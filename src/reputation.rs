use crate::{Eip8004, ipfs};
use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256, keccak256},
    providers::ProviderBuilder,
    sol,
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

/// Parse address from either raw format or "eip155:chainId:{address}" format
fn parse_address(addr: &str) -> Result<Address> {
    if addr.starts_with("eip155:") {
        // Format: "eip155:1:{address}"
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() == 3 {
            parts[2]
                .parse()
                .map_err(|e| anyhow!("Invalid address format: {}", e))
        } else {
            Err(anyhow!("Invalid eip155 format: {}", addr))
        }
    } else {
        addr.parse().map_err(|e| anyhow!("Invalid address: {}", e))
    }
}

/// Convert optional string to bytes32 using keccak256 hash, empty string becomes zero bytes
fn str_to_bytes32(s: &Option<String>) -> FixedBytes<32> {
    if let Some(s) = s {
        if s.is_empty() {
            FixedBytes::from([0u8; 32])
        } else {
            FixedBytes::from(keccak256(s.as_bytes()).0)
        }
    } else {
        FixedBytes::from([0u8; 32])
    }
}

/// Convert optional string to bytes32 using keccak256 hash, empty string becomes zero bytes
fn hash_to_bytes32(s: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let code = hex::decode(s.trim_start_matches("0x")).unwrap_or(vec![0u8; 32]);
    bytes.copy_from_slice(&code);
    FixedBytes::from(bytes)
}

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
        let uri = ipfs::upload(&self.ipfs, file).await?;

        // Call give_feedback_with_uri
        self.give_feedback_with_uri(&uri, "", &feedback).await
    }

    /// Feedback with given off-chain uri and file hash, return the index and tx hash
    pub async fn give_feedback_with_uri(
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
        let auth_code =
            hex::decode(feedback.feedback_auth.trim_start_matches("0x")).unwrap_or_default();
        let feedback_auth = Bytes::from(auth_code);

        let call = contract.giveFeedback(
            U256::from(feedback.agent_id),
            feedback.socre,
            tag1_bytes,
            tag2_bytes,
            uri.to_owned(),
            file_hash,
            feedback_auth,
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
    pub async fn get_summary(
        &self,
        agent: i64,
        tag1: Option<String>,
        tag2: Option<String>,
    ) -> Result<(u64, u8)> {
        self.check_reputation()?;

        let clients = self.get_clients(agent).await?;

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

    /// List all clients of agent
    pub async fn get_clients(&self, agent: i64) -> Result<Vec<Address>> {
        self.check_reputation()?;
        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ReputationRegistry::new(self.reputation, provider);

        let result = contract.getClients(U256::from(agent)).call().await?;

        Ok(result)
    }
}
