use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ReputationRegistry,
    "abi/ReputationRegistry.abi.json"
);

impl Eip8004 {
    pub async fn give_feedback(&self, agent: i64, score: u8, tag1: B256, tag2: B256, file_uri: String, file_hash: B256, auth: String) -> Result<()> {
        todo!()
    }

    pub async fn revoke_feedback(&self, agent: i64, index: i64) -> Result<()> {
        todo!()
    }

    pub async fn append_response(&self, agent: i64, client: Address, index: i64, response_uri: String, response_hash: B256) -> Result<()> {
        todo!()
    }

    pub async fn get_summary(&self, agent: i64, clients: &[Address], tag1: B256, tag2: B256) -> Result<()> {
        todo!()
    }

    pub async fn read_feedback(&self, agent: i64, client: Address, index: i64) -> Result<()> {
        todo!()
    }

    pub async fn read_all_feedback(&self, clients: &[Address], tag1: B256, tag2: B256, include_revoked: bool) -> Result<()> {
        todo!()
    }
}
