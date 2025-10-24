use anyhow::Result;
use eip8004::{Eip8004, Metadata, MetadataEndpoint, ipfs};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== EIP-8004 Identity Registry Example ===\n");

    // Initialize the SDK
    // Replace these with your actual values
    let rpc_url = std::env::var("RPC_URL").unwrap();
    let private_key = std::env::var("PRIVATE_KEY").unwrap();
    let ipfs_url = std::env::var("IPFS_URL").unwrap();
    let identity_address = std::env::var("IDENTITY_ADDRESS").unwrap();

    println!("Initializing EIP-8004 SDK...");
    let _eip8004 = Eip8004::new(&rpc_url)?
        .with_signer(&private_key)?
        .with_ipfs(&ipfs_url)?
        .with_identity(&identity_address)?;

    println!("✓ SDK initialized successfully\n");

    // Create agent metadata
    println!("Creating agent metadata...");
    let metadata = Metadata {
        mtype: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1".to_string(),
        name: "ZeroPay".to_string(),
        description: "The Open Payment Gateway for Humans and AI Agents. https://zpaynow.com".to_string(),
        image: "https://zpaynow.com/logo.png".to_string(),
        endpoints: vec![MetadataEndpoint {
            name: "A2A".to_owned(),
            endpoint: "https://agent.example/.well-known/agent-card.json".to_owned(),
            version: Some("1.0.0".to_string()),
            capabilities: None,
        }],
        registrations: vec![],
        supported_trust: vec!["reputation".to_string()],
    };

    println!("Metadata created:");
    println!("  Name: {}", metadata.name);
    println!("  Endpoints: {} configured\n", metadata.endpoints.len());

    Ok(())
}
