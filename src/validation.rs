use crate::{Eip8004, hash_to_bytes32, ipfs, parse_address, str_to_bytes32};
use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
    sol,
};
use anyhow::Result;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ValidationRegistry,
    "abi/ValidationRegistry.abi.json"
);

impl Eip8004 {
    /// Submit a validation request with IPFS upload
    /// Upload the request to IPFS and then submit to the validation contract
    /// Returns the transaction hash
    pub async fn validation_request_with_ipfs(
        &self,
        validator: &str,
        agent: i64,
        request: &str,
    ) -> Result<String> {
        // Upload request to ipfs
        let uri = ipfs::upload(&self.ipfs, request.to_owned()).await?;

        self.validation_request(validator, agent, &uri, "").await
    }

    /// Submit a validation request to the contract
    /// Returns the transaction hash
    pub async fn validation_request(
        &self,
        validator: &str,
        agent: i64,
        request_uri: &str,
        request_hash: &str,
    ) -> Result<String> {
        self.check_validation()?;

        let validator = parse_address(validator)?;
        let request_hash = hash_to_bytes32(request_hash);

        let signer = self.clone_signer()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = ValidationRegistry::new(self.validation, provider);

        let call = contract.validationRequest(
            validator,
            U256::from(agent),
            request_uri.to_owned(),
            request_hash,
        );

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        Ok(format!("{:?}", receipt.transaction_hash))
    }

    /// Submit a validation response with IPFS upload
    /// Upload the response to IPFS and then submit to the validation contract
    /// Returns the transaction hash
    pub async fn validation_response_with_ipfs(
        &self,
        request_hash: &str,
        response: u8,
        response_content: &str,
        tag: Option<String>,
    ) -> Result<String> {
        // Upload response to ipfs
        let uri = ipfs::upload(&self.ipfs, response_content.to_owned()).await?;

        self.validation_response(request_hash, response, &uri, "", tag)
            .await
    }

    /// Submit a validation response to the contract
    /// Returns the transaction hash
    pub async fn validation_response(
        &self,
        request_hash: &str,
        response: u8,
        response_uri: &str,
        response_hash: &str,
        tag: Option<String>,
    ) -> Result<String> {
        self.check_validation()?;

        let request_hash = hash_to_bytes32(request_hash);
        let response_hash = hash_to_bytes32(response_hash);
        let tag_bytes = str_to_bytes32(&tag);

        let signer = self.clone_signer()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(self.rpc.clone());
        let contract = ValidationRegistry::new(self.validation, provider);

        let call = contract.validationResponse(
            request_hash,
            response,
            response_uri.to_owned(),
            response_hash,
            tag_bytes,
        );

        // Send the transaction
        let pending_tx = call.send().await?;
        let receipt = pending_tx.get_receipt().await?;
        Ok(format!("{:?}", receipt.transaction_hash))
    }

    /// Get the validation status for a specific request
    /// Returns (validator_address, agent_id, response, tag, last_update)
    pub async fn get_validation_status(
        &self,
        request_hash: &str,
    ) -> Result<(Address, i64, u8, [u8; 32], u64)> {
        self.check_validation()?;

        let request_hash = hash_to_bytes32(request_hash);

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ValidationRegistry::new(self.validation, provider);

        let result = contract.getValidationStatus(request_hash).call().await?;

        Ok((
            result.validatorAddress,
            result.agentId.to::<i64>(),
            result.response,
            result.tag.0,
            result.lastUpdate.to::<u64>(),
        ))
    }

    /// Returns aggregated validation statistics for an agent
    /// agentId is the only mandatory parameter; validatorAddresses and tag are optional filters
    /// Returns (count, average_response)
    pub async fn get_validation_summary(
        &self,
        agent: i64,
        validators: Option<Vec<String>>,
        tag: Option<String>,
    ) -> Result<(u64, u8)> {
        self.check_validation()?;

        let validator_addresses = if let Some(validators) = validators {
            let mut addrs = vec![];
            for v in validators.iter() {
                addrs.push(parse_address(v)?);
            }
            addrs
        } else {
            vec![]
        };

        let tag_bytes = str_to_bytes32(&tag);

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ValidationRegistry::new(self.validation, provider);

        let result = contract
            .getSummary(U256::from(agent), validator_addresses, tag_bytes)
            .call()
            .await?;

        Ok((result.count, result.avgResponse))
    }

    /// Get all validation request hashes for a specific agent
    /// Returns a list of request hashes as hex strings
    pub async fn get_agent_validations(&self, agent: i64) -> Result<Vec<String>> {
        self.check_validation()?;

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ValidationRegistry::new(self.validation, provider);

        let request_hashes = contract
            .getAgentValidations(U256::from(agent))
            .call()
            .await?;

        // Convert FixedBytes<32> to hex strings
        let hashes: Vec<String> = request_hashes
            .iter()
            .map(|h| format!("0x{}", hex::encode(h.0)))
            .collect();

        Ok(hashes)
    }

    /// Get all validation request hashes for a specific validator
    /// Returns a list of request hashes as hex strings
    pub async fn get_validator_requests(&self, validator: &str) -> Result<Vec<String>> {
        self.check_validation()?;

        let validator = parse_address(validator)?;

        let provider = ProviderBuilder::new().connect_http(self.rpc.clone());
        let contract = ValidationRegistry::new(self.validation, provider);

        let request_hashes = contract.getValidatorRequests(validator).call().await?;

        // Convert FixedBytes<32> to hex strings
        let hashes: Vec<String> = request_hashes
            .iter()
            .map(|h| format!("0x{}", hex::encode(h.0)))
            .collect();

        Ok(hashes)
    }
}
