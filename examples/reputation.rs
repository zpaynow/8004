use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use eip8004::{Eip8004, Feedback, FeedbackAuth, FeedbackOnchainAuth};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== EIP-8004 Reputation Registry Example ===\n");

    // Initialize the SDK
    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://eth-sepolia.g.alchemy.com/v2/demo".to_string());
    let private_key = std::env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        "0x0000000000000000000000000000000000000000000000000000000000000001".to_string()
    });
    let reputation_address = std::env::var("REPUTATION_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    println!("Initializing SDK...");
    let eip8004 = Eip8004::new(&rpc_url)?
        .with_signer(&private_key)?
        .with_reputation(&reputation_address)?;

    println!("✓ SDK initialized\n");

    // Example: Create and sign feedback auth
    println!("=== Creating Feedback Auth ===");
    let agent_id = 123;
    let client_address = "0x1234567890123456789012345678901234567890";

    println!("Creating feedback auth for:");
    println!("  Agent ID: {}", agent_id);
    println!("  Client: {}\n", client_address);

    let auth = FeedbackAuth {
        agent_id,
        client_address: format!("eip155:1:{}", client_address),
        index_limit: 100,
        expiry: 1735689600, // Jan 1, 2025
        chain_id: 1,
        identity_registry: "eip155:1:0x0000000000000000000000000000000000000000".to_string(),
        signer_address: "eip155:1:0x0000000000000000000000000000000000000000".to_string(),
        signature: None,
    };

    println!("Converting to onchain format...");
    let mut onchain_auth = FeedbackOnchainAuth::from_feedback_auth(auth)?;
    println!("✓ Converted successfully");

    println!("\nSigning with private key...");
    let signer: PrivateKeySigner = private_key.parse()?;
    let signature = onchain_auth.sign(&signer).await?;
    println!("✓ Signed successfully");
    println!("  Signature: {}...", &signature[..20]);

    let auth_hex = onchain_auth.to_string();
    println!("  Auth hex: {}...\n", &auth_hex[..20]);

    // Example: Give feedback
    println!("=== Creating Feedback ===");
    let feedback = Feedback {
        agent_registry: "eip155:1:0x0000000000000000000000000000000000000000".to_string(),
        agent_id,
        client_address: format!("eip155:1:{}", client_address),
        feedback_auth: auth_hex,
        socre: 95,
        created_at: None,
        tag1: Some("performance".to_string()),
        tag2: Some("reliability".to_string()),
        skill: Some("data-analysis".to_string()),
        context: None,
        task: None,
        capability: Some("tools".to_string()),
        name: Some("analyze_data".to_string()),
        proof_of_payment: None,
    };

    println!("Feedback created:");
    println!("  Score: {}", feedback.socre);
    println!("  Tag1: {:?}", feedback.tag1);
    println!("  Tag2: {:?}", feedback.tag2);
    println!("  Skill: {:?}", feedback.skill);

    // Uncomment to submit feedback
    /*
    println!("\nSubmitting feedback...");
    match eip8004.give_feedback_with_ipfs(feedback).await {
        Ok((index, tx_hash)) => {
            println!("✓ Feedback submitted!");
            println!("  Index: {}", index);
            println!("  Transaction: {}", tx_hash);
        }
        Err(e) => {
            eprintln!("✗ Failed to submit feedback: {}", e);
        }
    }
    */

    println!("\n=== Reading Feedback (Example) ===");
    println!("To read feedback:");
    println!("  let (score, tag1, tag2, is_revoked) = eip8004");
    println!("      .read_feedback(agent_id, client_address, 0)");
    println!("      .await?;");

    println!("\n=== Getting Summary (Example) ===");
    println!("To get reputation summary:");
    println!("  let (count, avg_score) = eip8004");
    println!("      .get_summary(agent_id, None, None, None)");
    println!("      .await?;");

    println!("\n=== Configuration ===");
    println!("Set environment variables:");
    println!("  export RPC_URL='https://your-rpc-endpoint'");
    println!("  export PRIVATE_KEY='0x...'");
    println!("  export REPUTATION_ADDRESS='0x...'");

    Ok(())
}
