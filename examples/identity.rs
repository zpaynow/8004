use eip8004::{Eip8004, Metadata, MetadataEndpoint, ipfs};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    println!("=== EIP-8004 Identity Registry Example ===\n");

    // Initialize the SDK
    // Replace these with your actual values
    let rpc_url = std::env::var("RPC_URL").unwrap();
    let private_key = std::env::var("PRIVATE_KEY").unwrap();
    let identity_address = std::env::var("IDENTITY").unwrap();

    println!("Initializing EIP-8004 SDK...");
    let eip8004 = Eip8004::new(&rpc_url)
        .unwrap()
        .with_signer(&private_key)
        .unwrap()
        .with_identity(&identity_address)
        .unwrap();

    println!("✓ SDK initialized successfully\n");

    // Create agent metadata
    println!("Creating agent metadata...");
    let metadata = Metadata {
        mtype: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1".to_string(),
        name: "ZeroPay".to_string(),
        description: "The Open Payment Gateway for Humans and AI Agents. https://zpaynow.com"
            .to_string(),
        image: "https://zpaynow.com/logo.png".to_string(),
        endpoints: vec![MetadataEndpoint {
            name: "A2A".to_owned(),
            endpoint: "https://api.zpaynow.com/x402/support".to_owned(),
            version: Some("1.0.0".to_string()),
            capabilities: None,
        }],
        registrations: vec![],
        supported_trust: vec!["reputation".to_string()],
    };

    // Upload to IPFS, we are using Pinata.cloud
    println!("Uploading to IPFS...");
    let ipfs_jwt = std::env::var("PINATA_JWT").unwrap();

    let (content, _hash) = metadata.to_json_and_hash();
    let ipfs_url =
        ipfs::upload_with_pinata(&ipfs_jwt, "zeropay_metadata".to_owned(), None, content)
            .await
            .unwrap();

    // Register to chain
    println!("Registering onchain...");
    let (agent, tx) = eip8004.register_agent(&ipfs_url, &[]).await.unwrap();

    println!("Agent registered:");
    println!("  Agent: {}", agent);
    println!("  IPFS : {}", ipfs_url);
    println!("  Tx   : {}", tx);
}
