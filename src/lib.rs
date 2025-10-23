mod ipfs;

mod identity;
pub use identity::*;

mod reputation;
pub use reputation::*;

// mod validation;
// pub use validation::*;

use alloy::{
    primitives::Address, signers::local::PrivateKeySigner, transports::http::reqwest::Url,
};
use anyhow::{Result, anyhow};

/// Main EIP-8004 struct and interact with contracts and resource
#[derive(Clone)]
pub struct Eip8004 {
    rpc: Url,
    signer: Option<PrivateKeySigner>,
    ipfs: Option<String>,
    identity: Address,
    reputation: Address,
    validation: Address,
}

impl Eip8004 {
    pub fn new(rpc: &str) -> Result<Self> {
        let rpc = rpc.parse()?;
        Ok(Self {
            rpc,
            signer: None,
            ipfs: None,
            identity: Address::default(),
            reputation: Address::default(),
            validation: Address::default(),
        })
    }

    pub fn with_signer(mut self, signer: &str) -> Result<Self> {
        let signer = signer.parse()?;
        self.signer = Some(signer);
        Ok(self)
    }

    pub fn clone_signer(&self) -> Result<PrivateKeySigner> {
        if let Some(signer) = &self.signer {
            Ok(signer.clone())
        } else {
            Err(anyhow!("No signer"))
        }
    }

    pub fn with_ipfs(mut self, ipfs: &str) -> Result<Self> {
        self.ipfs = Some(ipfs.to_owned());
        Ok(self)
    }

    pub fn with_identity(mut self, identity: &str) -> Result<Self> {
        let identity: Address = identity.parse()?;
        self.identity = identity;
        Ok(self)
    }

    pub fn clone_with_identity(&self, identity: &str) -> Result<Self> {
        let identity: Address = identity.parse()?;
        let mut new = self.clone();
        new.identity = identity;
        Ok(new)
    }

    pub fn check_identity(&self) -> Result<()> {
        if self.identity == Address::default() {
            Err(anyhow!("No identity address"))
        } else {
            Ok(())
        }
    }

    pub fn with_reputation(mut self, reputation: &str) -> Result<Self> {
        let reputation: Address = reputation.parse()?;
        self.reputation = reputation;
        Ok(self)
    }

    pub fn clone_with_reputation(&self, reputation: &str) -> Result<Self> {
        let reputation: Address = reputation.parse()?;
        let mut new = self.clone();
        new.reputation = reputation;
        Ok(new)
    }

    pub fn check_reputation(&self) -> Result<()> {
        if self.reputation == Address::default() {
            Err(anyhow!("No reputation address"))
        } else {
            Ok(())
        }
    }

    pub fn with_validation(mut self, validation: &str) -> Result<Self> {
        let validation: Address = validation.parse()?;
        self.validation = validation;
        Ok(self)
    }

    pub fn clone_with_validation(&self, validation: &str) -> Result<Self> {
        let validation: Address = validation.parse()?;
        let mut new = self.clone();
        new.validation = validation;
        Ok(new)
    }

    pub fn check_validation(&self) -> Result<()> {
        if self.validation == Address::default() {
            Err(anyhow!("No validation address"))
        } else {
            Ok(())
        }
    }
}
