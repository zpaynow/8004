use crate::{Eip8004, ipfs};
use alloy::{
    primitives::{Bytes, U256},
    providers::ProviderBuilder,
    sol,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IdentityRegistry,
    "abi/IdentityRegistry.abi.json"
);

/// Agent metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// Protocol version
    /// e.g. "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
    #[serde(rename = "type")]
    pub mtype: String,
    /// EIP712 name, e.g. "name": "myAgentName"
    pub name: String,
    /// EIP712 description,
    /// e.g. "description": "A natural language description of the Agent,
    /// which MAY include what it does, how it works, pricing, and interaction methods"
    pub description: String,
    /// EIP712 image,
    /// e.g. "image": "https://example.com/agentimage.png"
    pub image: String,
    /// Endpoints list
    pub endpoints: Vec<MetadataEndpoint>,
    /// Registrations list
    pub registrations: Vec<MetadataRegistration>,
    /// The trust mode,
    /// e.g. "supportedTrust": [ "reputation", "crypto-economic", "tee-attestation"]
    pub supported_trust: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataEndpoint {
    /// e.g. "name": "A2A", "MCP", "OASF", "ENS", "DID", "agentWallet"
    pub name: String,
    /// e.g. "endpoint": "https://agent.example/.well-known/agent-card.json"
    pub endpoint: String,
    /// e.g. "version": "0.3.0"
    pub version: Option<String>,
    /// e.g. "capabilities": {}, // OPTIONAL, as per MCP spec
    pub capabilities: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataRegistration {
    /// e.g. "agentId": 22
    pub agent_id: i64,
    /// Registry info and address
    /// e.g. "agentRegistry": "eip155:1:{identityRegistry}"
    pub agent_registry: String,
}

impl Eip8004 {
    /// register an agent with ipfs, will release the metadata to ipfs
    /// and then onchain with some metadata key value, return the agent id and tx hash
    pub async fn register_agent_with_ipfs(
        &self,
        metadata: Metadata,
        onchain: &[(String, String)],
    ) -> Result<(i64, String)> {
        let file = serde_json::to_string(&metadata)?;
        let uri = ipfs::upload(&self.ipfs, file).await?;
        self.register_agent_with_uri(&uri, onchain).await
    }

    /// register an agent with given uri and metadata key value, return the agent id and tx hash
    pub async fn register_agent_with_uri(
        &self,
        uri: &str,
        onchain: &[(String, String)],
    ) -> Result<(i64, String)> {
        self.check_identity()?;
        let signer = self.clone_signer()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = IdentityRegistry::new(self.identity, provider);

        let metadata: Vec<_> = onchain
            .iter()
            .map(|(k, v)| IIdentityRegistry::MetadataEntry {
                key: k.to_owned(),
                value: Bytes::from(v.as_bytes().to_vec()),
            })
            .collect();
        let call = contract.register_1(uri.to_owned(), metadata);

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        let tx_hash = format!("{:?}", receipt.transaction_hash);

        // Parse the Registered event from logs to get agent ID
        for log in receipt.inner.logs() {
            if let Ok(decoded_log) = log.log_decode::<IdentityRegistry::Registered>() {
                let agent_id = decoded_log.inner.agentId.to::<i64>();
                return Ok((agent_id, tx_hash));
            }
        }

        Err(anyhow::anyhow!("Registered event not found in receipt"))
    }

    /// update agent onchain metadata key value, return the tx hash
    pub async fn update_agent_metadata(
        &self,
        agent: i64,
        key: String,
        value: String,
    ) -> Result<String> {
        self.check_identity()?;
        let signer = self.clone_signer()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = IdentityRegistry::new(self.identity, provider);

        let call = contract.setMetadata(
            U256::from(agent),
            key,
            Bytes::from(value.as_bytes().to_vec()),
        );

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        Ok(format!("{:?}", receipt.transaction_hash))
    }

    /// get agent onchain metadata given key, return the value
    pub async fn get_agent_metadata(&self, agent: i64, key: &str) -> Result<String> {
        self.check_identity()?;
        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = IdentityRegistry::new(self.identity, provider);

        let value: Bytes = contract
            .getMetadata(U256::from(agent), key.to_owned())
            .call()
            .await?;

        Ok(String::from_utf8(value.to_vec())?)
    }
}
