//! # Aliyun DNS API Client
//!
//! This crate provides a simple and easy-to-use API client for managing domain records through the Aliyun DNS API.
//!
//! ## Overview
//!
//! The main entry point for interacting with the Aliyun DNS API is the `AliyunDns` struct.
//! It provides methods for adding, updating, deleting, and querying domain records.
//!
//! ## Features
//!
//! - Add a new domain record
//! - Delete a domain record
//! - Delete subdomain records
//! - Update a domain record
//! - Query domain records
//!
//! ## Usage
//!
//! Add the `aliyun_dns` crate to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! aliyun_dns = "0.1.0"
//! ```
//!
//! Then, in your code, create a new `AliyunDns` instance with your Aliyun API Access Key ID and Secret, and start using the provided methods.
//!
//! ```rust
//! use aliyun_dns::AliyunDns;
//!
//! let access_key_id = "your_access_key_id";
//! let access_key_secret = "your_access_key_secret";
//! let aliyun_dns = AliyunDns::new(access_key_id.to_string(), access_key_secret.to_string());
//!
//! // Use the provided methods to interact with the API
//! ```
//!
//! ## Example
//!
//! This example demonstrates how to query domain records using the `AliyunDns` API client.
//!
//! ```rust,no_run
//! use aliyun_dns::AliyunDns;
//!
//! #[tokio::main]
//! async fn main() {
//!     let access_key_id = "your_access_key_id";
//!     let access_key_secret = "your_access_key_secret";
//!     let aliyun_dns = AliyunDns::new(access_key_id.to_string(), access_key_secret.to_string());
//!
//!     match aliyun_dns.query_domain_records("example.com").await {
//!         Ok(response) => {
//!             println!("Total domain records: {}", response.total_count);
//!             for record in response.domain_records.records {
//!                 println!("Record: {:#?}", record);
//!             }
//!         }
//!         Err(e) => eprintln!("Error: {}", e),
//!     }
//! }
//! ```
//!
//! For more examples, please refer to the [`examples`](https://github.com/edsky/aliyun_dns/tree/main/examples) directory in the repository.
//!
//! ## License
//!
//! This crate is licensed under the MIT License.
//!
//! For more information, see the [`LICENSE`](https://github.com/edsky/aliyun_dns/blob/main/LICENSE) file in the repository.
//!
//! [![GitHub license](https://img.shields.io/github/license/edsky/aliyun_dns)](https://github.com/edsky/aliyun_dns/blob/main/LICENSE)
//!
//! ## Contributing
//!
//! Contributions are welcome! Please feel free to submit issues and pull requests.
//!
//! ## Additional Documentation
//!
//! The full API documentation can be found [here](https://github.com/edsky/aliyun_dns/).
//!
//! For more information on the Aliyun DNS API, please refer to the [official Aliyun DNS API documentation](https://www.alibabacloud.com/help/doc-detail/29739.htm).
//!
//! ## Disclaimer
//!
//! This crate is not officially affiliated with or endorsed by Alibaba Cloud or Aliyun.
//!
//! It is a third-party implementation and the maintainers of this crate are not responsible for any issues that may arise from its use.
//!
//! Please use this crate at your own risk and make sure to comply with Alibaba Cloud's terms of service.
//!
//! ## Changelog
//!
//! To see the changes made between different versions of this crate, please refer to the CHANGELOG.md file in the repository.
//!
//! ## Support
//!
//! If you encounter any issues or have questions about this crate, please open an issue on the GitHub repository.
//!
//! ## Related Projects
//!
//! - Aliyun SDK for Rust: Official Alibaba Cloud SDK for the Rust programming language (in development)
//! - Aliyun CLI: Official command-line interface for Alibaba Cloud services
//!
//! ## Acknowledgements
//!
//! This crate was developed with the help of the following resources:
//!
//! - Aliyun DNS API documentation
//! - serde: A Rust library for serializing and deserializing data structures efficiently and generically
//! - reqwest: An ergonomic, batteries-included HTTP client for Rust
//!
//! We would like to express our gratitude to the developers and maintainers of these projects, as well as the Rust community as a whole, for their support and inspiration.
//!
//! Happy coding! 🦀

// Include the rest of the crate's implementation here.
use anyhow::{Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::{Client, Response};
use serde::Deserialize;
use sha1::Sha1;
use std::collections::HashMap;
use url::Url;
use base64::Engine;

/// An enum representing the API response, containing either a successful result or an error.
///
/// This is used internally by the `aliyun_dns` crate and is not part of the public API.
#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
#[serde(untagged)] // Use untagged enum to handle different response structures
enum ApiResponse<T> {
    Success(T),
    Error {
        #[serde(rename = "RequestId")]
        request_id: String,

        #[serde(rename = "Code", default)]
        error_code: Option<String>,

        #[serde(rename = "Message", default)]
        error_message: Option<String>,
    },
}

/// A struct representing a domain record.
#[derive(Debug, Deserialize)]
pub struct DomainRecord {
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "Line")]
    pub line: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Locked")]
    pub locked: bool,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "RecordId")]
    pub record_id: String,
    #[serde(rename = "TTL")]
    pub ttl: u32,
}

/// A struct representing the response for querying domain records.
#[derive(Debug, Deserialize)]
pub struct DomainRecordsResponse {
    #[serde(rename = "TotalCount")]
    pub total_count: u32,
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "PageSize")]
    pub page_size: u32,
    #[serde(rename = "DomainRecords")]
    pub domain_records: DomainRecords,
}

/// A struct containing the domain records returned in the response.
#[derive(Debug, Deserialize)]
pub struct DomainRecords {
    #[serde(rename = "Record")]
    pub records: Vec<DomainRecord>,
}

/// A struct representing the response for deleting subdomain records.
#[derive(Debug, Deserialize)]
pub struct DeleteSubDomainRecordsResponse {
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "TotalCount")]
    pub total_count: String,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

/// A struct representing the response for adding, updating, or deleting a domain record.
#[derive(Debug, Deserialize)]
pub struct RecordResponse {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "RecordId")]
    pub record_id: String,
}

/// A struct representing the AliyunDns API client.
pub struct AliyunDns {
    access_key_id: String,
    access_key_secret: String,
    client: Client,
}

// Implement methods for AliyunDns struct
impl AliyunDns {
    /// Creates a new `AliyunDns` client with the provided access key ID and access key secret.
    ///
    /// # Arguments
    ///
    /// * `access_key_id` - The access key ID for the Aliyun API.
    /// * `access_key_secret` - The access key secret for the Aliyun API.
    ///
    /// # Examples
    ///
    /// ```
    /// use aliyun_dns::AliyunDns;
    ///
    /// let aliyun_dns = AliyunDns::new("your_access_key_id", "your_access_key_secret");
    /// ```
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        let client = Client::new();
        AliyunDns {
            access_key_id,
            access_key_secret,
            client,
        }
    }

    /// Adds a new domain record.
    ///
    /// # Arguments
    ///
    /// * `domain_name` - The domain name for which the record should be added.
    /// * `sub_domain` - The subdomain of the domain.
    /// * `record_type` - The type of the record (e.g., "A", "CNAME", "MX", etc.).
    /// * `record_value` - The value of the record (e.g., an IP address or a hostname).
    ///
    /// # Returns
    ///
    /// A `Result` containing a `RecordResponse` if the operation is successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use aliyun_dns::{AliyunDns, RecordResponse};
    ///
    /// let aliyun_dns = AliyunDns::new("your_access_key_id", "your_access_key_secret");
    /// let result: Result<RecordResponse, _> = aliyun_dns.add_domain_record("example.com", "www", "A", "192.0.2.1").await;
    /// ```
    pub async fn add_domain_record(
        &self,
        domain_name: &str,
        sub_domain: &str,
        record_type: &str,
        record_value: &str
    ) -> Result<RecordResponse> {
        let action = "AddDomainRecord";
        let mut params = HashMap::new();
        params.insert("DomainName", domain_name);
        params.insert("RR", sub_domain);
        params.insert("Type", record_type);
        params.insert("Value", record_value);
        
        self.send_request(action, params).await
    }

    /// Deletes all subdomain records.
    ///
    /// # Arguments
    ///
    /// * `domain_name` - The domain name for which the subdomain records should be deleted.
    /// * `rr` - The subdomain prefix (e.g., "www" for "www.example.com").
    ///
    /// # Returns
    ///
    /// A `Result` containing a `DeleteSubDomainRecordsResponse` if the operation is successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use aliyun_dns::{AliyunDns, DeleteSubDomainRecordsResponse};
    ///
    /// let aliyun_dns = AliyunDns::new("your_access_key_id", "your_access_key_secret");
    /// let result: Result<DeleteSubDomainRecordsResponse, _> = aliyun_dns.delete_subdomain_records("example.com", "www").await;
    /// ```
    pub async fn delete_subdomain_records(
        &self,
        domain_name: &str,
        rr: &str,
    ) -> Result<DeleteSubDomainRecordsResponse> {
        let action = "DeleteSubDomainRecords";
        let mut params = HashMap::new();
        params.insert("DomainName", domain_name);
        params.insert("RR", rr);
        
        self.send_request(action, params).await
    }

    /// Deletes a specific domain record by its ID.
    ///
    /// # Arguments
    ///
    /// * `record_id` - The ID of the domain record to be deleted.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `RecordResponse` if the operation is successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use aliyun_dns::{AliyunDns, RecordResponse};
    ///
    /// let aliyun_dns = AliyunDns::new("your_access_key_id", "your_access_key_secret");
    /// let result: Result<RecordResponse, _> = aliyun_dns.delete_domain_record("record_id").await;
    /// ```
    pub async fn delete_domain_record(
        &self,
        record_id: &str,
    ) -> Result<RecordResponse> {
        let action = "DeleteDomainRecord";
        let mut params = HashMap::new();
        params.insert("RecordId", record_id);
        
        self.send_request(action, params).await
    }

    /// Updates a domain record with new values.
    ///
    /// # Arguments
    ///
    /// * `record_id` - The ID of the domain record to be updated.
    /// * `sub_domain` - The updated subdomain of the domain.
    /// * `record_type` - The updated type of the record (e.g., "A", "CNAME", "MX", etc.).
    /// * `value` - The updated value of the record (e.g., an IP address or a hostname).
    ///
    /// # Returns
    ///
    /// A `Result` containing a `RecordResponse` if the operation is successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use aliyun_dns::{AliyunDns, RecordResponse};
    ///
    /// let aliyun_dns = AliyunDns::new("your_access_key_id", "your_access_key_secret");
    /// let result: Result<RecordResponse, _> = aliyun_dns.update_domain_record("record_id", "www", "A", "192.0.2.1").await;
    /// ```
    pub async fn update_domain_record(
        &self,
        record_id: &str,
        sub_domain: &str,
        record_type: &str,
        value: &str,
    ) -> Result<RecordResponse> {
        let action = "UpdateDomainRecord";
        let mut params = HashMap::new();
        params.insert("RecordId", record_id);
        params.insert("RR", sub_domain);
        params.insert("Type", record_type);
        params.insert("Value", value);
        
        self.send_request(action, params).await
    }

    /// Queries the domain records for a specific domain name.
    ///
    /// # Arguments
    ///
    /// * `domain_name` - The domain name for which the records should be queried.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `DomainRecordsResponse` if the operation is successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use my_crate::{AliyunDns, DomainRecordsResponse};
    ///
    /// let aliyun_dns = AliyunDns::new("your_access_key_id", "your_access_key_secret");
    /// let result: Result<DomainRecordsResponse, _> = aliyun_dns.query_domain_records("example.com").await;
    /// ```
    pub async fn query_domain_records(&self, domain_name: &str) -> Result<DomainRecordsResponse> {
        let action = "DescribeDomainRecords";
        let mut params = HashMap::new();
        params.insert("DomainName", domain_name);
        self.send_request(action, params).await
    }

    /// Sends an API request with the specified action and parameters.
    ///
    /// # Arguments
    ///
    /// * `action` - The API action to perform.
    /// * `params` - A map containing the API parameters for the request.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized response if the operation is successful, or an error if the operation fails.
    ///
    /// This function is used internally by the `aliyun_dns` crate and is not part of the public API.
    async fn send_request<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        mut params: HashMap<&str, &str>,
    ) -> Result<T> {
        let url = "https://alidns.aliyuncs.com/";
        let nonce = format!("{}", rand::random::<u64>());
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        params.insert("AccessKeyId", &self.access_key_id);
        params.insert("Action", action);
        params.insert("Format", "JSON");
        params.insert("Version", "2015-01-09");
        params.insert("SignatureMethod", "HMAC-SHA1");
        params.insert("SignatureVersion", "1.0");
        params.insert("SignatureNonce", &nonce);
        params.insert("Timestamp", &now);

        let signature = self.sign_request(&params);
        let mut url = Url::parse(url).unwrap();
        url.query_pairs_mut().extend_pairs(params.into_iter());
        url.query_pairs_mut().append_pair("Signature", &signature);

        let response = self.client.get(url).send().await?;
        self.handle_response(response).await
    }

    /// Signs the API request with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - A map containing the API parameters for the request.
    ///
    /// # Returns
    ///
    /// A `String` containing the signed request.
    ///
    /// This function is used internally by the `aliyun_dns` crate and is not part of the public API.
    fn sign_request(&self, params: &HashMap<&str, &str>) -> String {
        let mut keys: Vec<&str> = params.keys().map(AsRef::as_ref).collect();
        keys.sort();
        let canonical_query_string = keys
            .iter()
            .map(|key| {
                format!(
                    "{}={}",
                    percent_encode(key),
                    percent_encode(params.get(key).unwrap())
                )
            })
            .collect::<Vec<String>>()
            .join("&");

        let string_to_sign = format!(
            "GET&{}&{}",
            percent_encode("/"),
            percent_encode(&canonical_query_string)
        );
        let signature_key = format!("{}&", self.access_key_secret);
        let mut mac = Hmac::<Sha1>::new_from_slice(signature_key.as_bytes()).unwrap();
        mac.update(string_to_sign.as_bytes());
        let result = mac.finalize();
        let signature = base64::engine::general_purpose::STANDARD.encode(result.into_bytes());
    
        signature
    }

    /// Handles the API response and returns the deserialized result or an error.
    ///
    /// # Arguments
    ///
    /// * `response` - A `Response` object containing the API response.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized response if the operation is successful, or an error if the operation fails.
    ///
    /// This function is used internally by the `aliyun_dns` crate and is not part of the public API.
    async fn handle_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: Response,
    ) -> Result<T> {
        // let status = response.status();
        // if !status.is_success() {
        //     return Err(anyhow::anyhow!("Request failed with status: {}", status));
        // }
    
        let response_text = response.text().await?;
        let response_data: ApiResponse<T> = serde_json::from_str(&response_text)
            .context(format!("Failed to parse JSON response: {}", response_text))?;
    
        match response_data {
            ApiResponse::Success(result) => Ok(result),
            ApiResponse::Error {
                request_id,
                error_code,
                error_message,
            } => Err(anyhow::anyhow!(
                "API error: Request ID: {}, Code: {}, Message: {}",
                request_id,
                error_code.unwrap_or_default(),
                error_message.unwrap_or_default()
            )),
        }
    }

}

fn percent_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.as_bytes() {
        if *byte == b'*' {
            encoded.push_str("%2A");
        } else {
            let temp = url::form_urlencoded::byte_serialize(&[*byte]).collect::<String>();
            encoded.push_str(&temp);
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello"), "hello".to_string());
        assert_eq!(percent_encode("a/b"), "a%2Fb".to_string());
        assert_eq!(percent_encode("a+b"), "a%2Bb".to_string());
        assert_eq!(percent_encode("a b"), "a+b".to_string());
        assert_eq!(percent_encode("*"), "%2A".to_string());
        assert_eq!(percent_encode("%"), "%25".to_string());
        assert_eq!(
            percent_encode("你好"),
            "%E4%BD%A0%E5%A5%BD".to_string()
        );
    }
}