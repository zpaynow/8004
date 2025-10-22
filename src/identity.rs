use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IdentityRegistry,
    "abi/IdentityRegistry.abi.json"
);

impl Eip8004 {
    pub async fn register_agent(&self, uri: &str, metadata: &[(String, String)]) -> Result<> {
        todo!()
    }

    pub async fn update_agent(&self, agent: i64, key: String, value: String) -> Result<()> {
        todo!()
    }

    pub async fn get_agent(&self, agent: i64, key: &str) -> Result<()> {
        todo!()
    }
}
