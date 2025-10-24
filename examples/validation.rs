use anyhow::Result;
use eip8004::Eip8004;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== EIP-8004 Validation Registry Example ===\n");

    // Initialize the SDK
    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://eth-sepolia.g.alchemy.com/v2/demo".to_string());
    let private_key = std::env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        "0x0000000000000000000000000000000000000000000000000000000000000001".to_string()
    });
    let validation_address = std::env::var("VALIDATION_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    println!("Initializing SDK...");
    let _eip8004 = Eip8004::new(&rpc_url)?
        .with_signer(&private_key)?
        .with_validation(&validation_address)?;

    println!("✓ SDK initialized\n");

    // Example: Request validation
    println!("=== Requesting Validation ===");
    let agent_id = 123;
    let validator_address = "0x1234567890123456789012345678901234567890";

    println!("Validation request parameters:");
    println!("  Agent ID: {}", agent_id);
    println!("  Validator: {}", validator_address);

    let request_content = r#"{
        "type": "capability-validation",
        "agent_id": 123,
        "capabilities": [
            "data-analysis",
            "natural-language-processing"
        ],
        "test_criteria": [
            "Accuracy > 95%",
            "Response time < 1s",
            "Compliance with safety guidelines"
        ],
        "expiry": 1735689600
    }"#;

    println!("\nRequest content:");
    println!("{}\n", request_content);

    // Uncomment to submit request
    /*
    println!("Submitting validation request...");
    match eip8004.validation_request_with_ipfs(
        validator_address,
        agent_id,
        request_content,
    ).await {
        Ok(tx_hash) => {
            println!("✓ Validation request submitted!");
            println!("  Transaction: {}", tx_hash);
        }
        Err(e) => {
            eprintln!("✗ Failed to submit request: {}", e);
        }
    }
    */

    // Example: Respond to validation
    println!("=== Responding to Validation ===");
    let request_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    println!("Response parameters:");
    println!("  Request hash: {}...", &request_hash[..20]);
    println!("  Score: 85");
    println!("  Tag: certification");

    let response_content = r#"{
        "type": "validation-response",
        "status": "passed",
        "score": 85,
        "tests_performed": [
            {
                "name": "accuracy-test",
                "result": "passed",
                "score": 96
            },
            {
                "name": "response-time-test",
                "result": "passed",
                "average": "0.7s"
            }
        ],
        "validator_notes": "Agent meets all specified criteria",
        "timestamp": 1234567890
    }"#;

    println!("\nResponse content:");
    println!("{}\n", response_content);

    // Uncomment to submit response
    /*
    println!("Submitting validation response...");
    match eip8004.validation_response_with_ipfs(
        request_hash,
        85,
        response_content,
        Some("certification".to_string()),
    ).await {
        Ok(tx_hash) => {
            println!("✓ Validation response submitted!");
            println!("  Transaction: {}", tx_hash);
        }
        Err(e) => {
            eprintln!("✗ Failed to submit response: {}", e);
        }
    }
    */

    // Example: Get validation status
    println!("=== Getting Validation Status ===");
    println!("To check validation status:");
    println!("  let (validator, agent_id, response, tag, last_update) = eip8004");
    println!("      .get_validation_status(request_hash)");
    println!("      .await?;");

    // Example: Get validation summary
    println!("\n=== Getting Validation Summary ===");
    println!("To get validation summary for an agent:");
    println!("  let (count, avg_response) = eip8004");
    println!("      .get_validation_summary(");
    println!("          agent_id,");
    println!("          Some(vec![validator_address.to_string()]),");
    println!("          Some(\"certification\".to_string()),");
    println!("      )");
    println!("      .await?;");

    // Example: List validations
    println!("\n=== Listing Validations ===");
    println!("To get all validations for an agent:");
    println!("  let hashes = eip8004");
    println!("      .get_agent_validations(agent_id)");
    println!("      .await?;");

    println!("\nTo get all requests for a validator:");
    println!("  let hashes = eip8004");
    println!("      .get_validator_requests(validator_address)");
    println!("      .await?;");

    println!("\n=== Configuration ===");
    println!("Set environment variables:");
    println!("  export RPC_URL='https://your-rpc-endpoint'");
    println!("  export PRIVATE_KEY='0x...'");
    println!("  export VALIDATION_ADDRESS='0x...'");

    Ok(())
}
