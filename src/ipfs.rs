use alloy::transports::http::reqwest;
use anyhow::{Result, anyhow};

const DEFAULT_IPFS_URL: &str = "https://ipfs.io";

/// Upload content as a file to ipfs, and return the path with ipfs://cid
pub async fn upload(url: &str, content: String) -> Result<String> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v0/add", url))
        .header("Content-Type", "application/octet-stream")
        .body(content)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "IPFS upload failed with status {}: {}",
            status,
            error_body
        ));
    }

    let response_text = response.text().await?;

    // Parse the JSON response to extract the CID (hash)
    let json: serde_json::Value = serde_json::from_str(&response_text)?;

    let cid = json
        .get("Hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Failed to extract CID from IPFS response"))?;

    Ok(format!("ipfs://{}", cid))
}

/// Read content from IPFS using a CID
/// The cid parameter can be either a raw CID or an ipfs:// URL
pub async fn read(url: &Option<String>, cid: &str) -> Result<String> {
    let ipfs_url = url.as_deref().unwrap_or(DEFAULT_IPFS_URL);

    // Strip ipfs:// prefix if present
    let cid = cid.trim_start_matches("ipfs://");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/ipfs/{}", ipfs_url, cid))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "IPFS read failed with status {}: {}",
            status,
            error_body
        ));
    }

    let content = response.text().await?;
    Ok(content)
}

/// curl --request POST \
/// --url https://uploads.pinata.cloud/v3/files \
/// --header 'Authorization: Bearer <token>' \
/// --header 'Content-Type: multipart/form-data' \
/// --form network=private \
/// --form 'name=<string>' \
/// --form 'group_id=<string>' \
/// --form 'keyvalues={}' \
/// --form car=true \
/// --form file=@example-file
/// response:
/// {
///     "data": {
///         "id": "<string>",
///         "name": "<string>",
///         "cid": "<string>",
///         "created_at": "<string>",
///         "size": 123,
///         "number_of_files": 123,
///         "mime_type": "<string>",
///         "user_id": "<string>",
///         "group_id": "<string>",
///         "is_duplicate": true
///     }
/// }
pub async fn upload_with_pinata(
    jwt: &str,
    name: String,
    group: Option<String>,
    content: String,
) -> Result<String> {
    let url = "https://uploads.pinata.cloud/v3/files";

    // Create multipart form
    let file_part = reqwest::multipart::Part::text(content)
        .file_name(format!("{name}.json"))
        .mime_str("text/plain")?;

    let mut form = reqwest::multipart::Form::new()
        .text("network", "public")
        .text("name", name)
        .text("keyvalues", "{}")
        .text("car", "true")
        .part("file", file_part);
    if let Some(group) = group {
        form = form.text("group_id", group);
    }

    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Pinata upload failed with status {}: {}",
            status,
            error_body
        ));
    }

    let response_text = response.text().await?;

    // Parse the JSON response to extract the CID from the nested data structure
    let json: serde_json::Value = serde_json::from_str(&response_text)?;

    let cid = json
        .get("data")
        .and_then(|data| data.get("cid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Failed to extract CID from Pinata response"))?;

    Ok(format!("ipfs://{}", cid))
}
