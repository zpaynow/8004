# EIP-8004 Rust SDK

A comprehensive Rust implementation of [EIP-8004](https://eips.ethereum.org/EIPS/eip-8004) - Trustless Agents. Discover agents and establish trust through reputation and validation.

## Overview

This SDK provides a complete implementation for interacting with EIP-8004 smart contracts, enabling decentralized agent identity, reputation, and validation systems on Ethereum-compatible blockchains.

## Features

- **Identity Registry**: Register and manage agent identities with metadata
- **Reputation System**: Give and receive feedback, track reputation scores
- **Validation Registry**: Request and respond to agent validations
- **IPFS Integration**: Upload and retrieve metadata from IPFS
- **EIP-191 Signing**: Sign and verify feedback authentication
- **Type-Safe**: Built with Alloy for robust type safety

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
eip8004 = "0.1.0"
```

## Quick Start

```rust
use eip8004::{Eip8004, Metadata, MetadataEndpoint, MetadataRegistration};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize with RPC endpoint
    let eip8004 = Eip8004::new("https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY")?
        .with_signer("your_private_key")?
        .with_ipfs("https://ipfs.infura.io:5001")?
        .with_identity("0xIdentityRegistryAddress")?
        .with_reputation("0xReputationRegistryAddress")?
        .with_validation("0xValidationRegistryAddress")?;

    // Register an agent
    let metadata = Metadata {
        mtype: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1".to_string(),
        name: "My AI Agent".to_string(),
        description: "An intelligent agent for task automation".to_string(),
        image: "https://example.com/agent.png".to_string(),
        endpoints: vec![
            MetadataEndpoint {
                name: "MCP".to_string(),
                endpoint: "https://agent.example.com/mcp".to_string(),
                version: Some("1.0.0".to_string()),
                capabilities: None,
            }
        ],
        registrations: vec![],
        supported_trust: vec!["reputation".to_string()],
    };

    let (agent_id, tx_hash) = eip8004
        .register_agent_with_ipfs(metadata, &[])
        .await?;

    println!("Agent registered! ID: {}, TX: {}", agent_id, tx_hash);

    Ok(())
}
```

## Module Documentation

### Identity Registry

Manage agent identities and metadata.

#### Register an Agent

```rust
// With IPFS metadata upload
let (agent_id, tx_hash) = eip8004
    .register_agent_with_ipfs(metadata, &[])
    .await?;

// With existing URI
let (agent_id, tx_hash) = eip8004
    .register_agent("ipfs://QmHash...", &[
        ("key1".to_string(), "value1".to_string()),
        ("key2".to_string(), "value2".to_string()),
    ])
    .await?;
```

#### Update Agent Metadata

```rust
let tx_hash = eip8004
    .update_agent_metadata(agent_id, "endpoint".to_string(), "https://new-endpoint.com".to_string())
    .await?;
```

#### Get Agent Metadata

```rust
let value = eip8004
    .get_agent_metadata(agent_id, "endpoint")
    .await?;
```

### Reputation Registry

Track and manage agent reputation through feedback.

#### Give Feedback

```rust
use eip8004::{Feedback, FeedbackAuth};

let feedback = Feedback {
    agent_registry: "eip155:1:0xIdentityAddress".to_string(),
    agent_id: 123,
    client_address: "eip155:1:0xClientAddress".to_string(),
    feedback_auth: "0x...signed_auth...".to_string(),
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

let (index, tx_hash) = eip8004
    .give_feedback_with_ipfs(feedback)
    .await?;
```

#### Create and Sign Feedback Auth

```rust
use eip8004::{FeedbackAuth, FeedbackOnchainAuth};
use alloy::signers::local::PrivateKeySigner;

// Get the current feedback index for the client
let index = eip8004.get_feedback_index(agent_id, "eip155:1:0xClientAddress").await?;

// Create feedback auth
let auth = FeedbackAuth {
    agent_id: 123,
    client_address: "eip155:1:0xClientAddress".to_string(),
    index_limit: index + 10, // Allow up to 10 more feedback
    expiry: 1735689600, // Unix timestamp
    chain_id: 1,
    identity_registry: "eip155:1:0xIdentityAddress".to_string(),
    signer_address: "eip155:1:0xSignerAddress".to_string(),
    signature: None,
};

// Convert to onchain format
let mut onchain_auth = FeedbackOnchainAuth::from_feedback_auth(auth)?;

// Sign it
let signer: PrivateKeySigner = "your_private_key".parse()?;
let signature = onchain_auth.sign(&signer).await?;

// Get hex string for use in Feedback
let auth_hex = onchain_auth.to_string();
```

#### Read Feedback

```rust
// Read single feedback
let (score, tag1, tag2, is_revoked) = eip8004
    .read_feedback(agent_id, "0xClientAddress", 0)
    .await?;

// Read all feedback for an agent
let (clients, scores, tag1s, tag2s, revoked) = eip8004
    .read_all_feedback(
        agent_id,
        None, // All clients
        None, // No tag1 filter
        None, // No tag2 filter
        false, // Exclude revoked
    )
    .await?;
```

#### Get Reputation Summary

```rust
let (count, average_score) = eip8004
    .get_summary(
        agent_id,
        Some(vec!["0xClient1".to_string(), "0xClient2".to_string()]),
        Some("performance".to_string()),
        None,
    )
    .await?;

println!("Total feedback: {}, Average score: {}", count, average_score);
```

#### Revoke Feedback

```rust
let tx_hash = eip8004
    .revoke_feedback(agent_id, "0xClientAddress", feedback_index)
    .await?;
```

#### Append Response to Feedback

```rust
let tx_hash = eip8004
    .append_response_with_ipfs(
        agent_id,
        "0xClientAddress",
        feedback_index,
        "Thank you for the feedback! We've improved based on your suggestions.".to_string(),
    )
    .await?;
```

#### Get Response Count

```rust
let count = eip8004
    .get_response_count(
        agent_id,
        "0xClientAddress",
        feedback_index,
        vec!["0xResponder1".to_string()],
    )
    .await?;
```

### Validation Registry

Request and manage agent validations.

#### Request Validation

```rust
// With IPFS upload
let tx_hash = eip8004
    .validation_request_with_ipfs(
        "0xValidatorAddress",
        agent_id,
        "Please validate this agent's capabilities",
    )
    .await?;

// With existing URI
let tx_hash = eip8004
    .validation_request(
        "0xValidatorAddress",
        agent_id,
        "ipfs://QmHash...",
        "0x...", // Request hash
    )
    .await?;
```

#### Submit Validation Response

```rust
// With IPFS upload
let tx_hash = eip8004
    .validation_response_with_ipfs(
        "0xRequestHash",
        85, // Response score
        "Validation complete. Agent passed all tests.",
        Some("certification".to_string()),
    )
    .await?;

// With existing URI
let tx_hash = eip8004
    .validation_response(
        "0xRequestHash",
        85,
        "ipfs://QmHash...",
        "0x...", // Response hash
        Some("certification".to_string()),
    )
    .await?;
```

#### Get Validation Status

```rust
let (validator, agent_id, response, tag, last_update) = eip8004
    .get_validation_status("0xRequestHash")
    .await?;

println!("Validator: {:?}, Response: {}", validator, response);
```

#### Get Validation Summary

```rust
let (count, avg_response) = eip8004
    .get_validation_summary(
        agent_id,
        Some(vec!["0xValidator1".to_string()]),
        Some("certification".to_string()),
    )
    .await?;
```

#### List Validations

```rust
// Get all validations for an agent
let request_hashes = eip8004
    .get_agent_validations(agent_id)
    .await?;

// Get all requests for a validator
let request_hashes = eip8004
    .get_validator_requests("0xValidatorAddress")
    .await?;
```

## IPFS Integration

The SDK includes built-in IPFS support for uploading metadata:

```rust
use eip8004::ipfs;

// Upload content to IPFS
let cid = ipfs::upload(
    &Some("https://ipfs.infura.io:5001".to_string()),
    "Your content here".to_string(),
).await?;

println!("Uploaded to IPFS: {}", cid);
```

## Address Formats

The SDK supports two address formats:

1. **Raw Ethereum address**: `0x1234...`
2. **EIP-155 format**: `eip155:1:0x1234...` (includes chain ID)

Both formats are automatically parsed by the SDK.

## Error Handling

All functions return `Result<T, anyhow::Error>` for comprehensive error handling:

```rust
match eip8004.register_agent_with_ipfs(metadata, &[]).await {
    Ok((agent_id, tx_hash)) => {
        println!("Success! Agent ID: {}", agent_id);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Examples

Check the `examples/` directory for complete working examples:

- `identity.rs` - Identity registry operations
- `reputation.rs` - Reputation and feedback management
- `validation.rs` - Validation workflows

Run an example:

```bash
cargo run --example identity
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## References

- [EIP-8004 Specification](https://eips.ethereum.org/EIPS/eip-8004)
- [Alloy Documentation](https://alloy.rs)
