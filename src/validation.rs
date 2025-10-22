use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ValidationRegistry,
    "abi/ValidationRegistry.abi.json"
);

impl Eip8004 {
    pub async fn validation_request(&self, validator: Address, agent: i64, request_uri: String, request_hash: B256) -> Result<()> {
        todo!()
    }

    pub async fn validation_response(&self, request_hash: B256, response: i64, response_uri: String, response_hash: B256, tag: B256) -> Result<()> {
        todo!()
    }

    pub async fn get_validation_status(&self, request_hash: B256) -> Result<()> {
        //
    }

    pub async fn get_summary(&self, agent: i64, validators: &[Address], tag: B256) -> Result<()> {
        //
    }
}
