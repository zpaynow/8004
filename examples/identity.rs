use eip8004::{Eip8004, Metadata, MetadataEndpoint};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== EIP-8004 Identity Registry Example ===\n");

    // Initialize the SDK
    // Replace these with your actual values
    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://eth-sepolia.g.alchemy.com/v2/demo".to_string());
    let private_key = std::env::var("PRIVATE_KEY")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000000000000000000000000001".to_string());
    let ipfs_url = std::env::var("IPFS_URL")
        .unwrap_or_else(|_| "https://ipfs.infura.io:5001".to_string());
    let identity_address = std::env::var("IDENTITY_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

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
        name: "Example AI Agent".to_string(),
        description: "A demonstration agent showcasing EIP-8004 identity features.".to_string(),
        image: "https://example.com/agent-avatar.png".to_string(),
        endpoints: vec![
            MetadataEndpoint {
                name: "MCP".to_string(),
                endpoint: "https://agent.example.com/.well-known/mcp".to_string(),
                version: Some("1.0.0".to_string()),
                capabilities: None,
            },
        ],
        registrations: vec![],
        supported_trust: vec!["reputation".to_string()],
    };

    println!("Metadata created:");
    println!("  Name: {}", metadata.name);
    println!("  Endpoints: {} configured\n", metadata.endpoints.len());

    println!("\n=== Example Configuration ===");
    println!("To run with your configuration:");
    println!("  export RPC_URL='https://your-rpc-endpoint'");
    println!("  export PRIVATE_KEY='0x...'");
    println!("  export IDENTITY_ADDRESS='0x...'");

    Ok(())
}
