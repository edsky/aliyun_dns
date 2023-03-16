use anyhow::{Context, Result};
use chrono::Utc;
use crypto::{hmac::Hmac, sha1::Sha1, mac::Mac};
use reqwest::{Client, Response};
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;
use base64::Engine;

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

#[derive(Debug, Deserialize)]
pub struct DomainRecords {
    #[serde(rename = "Record")]
    pub records: Vec<DomainRecord>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteSubDomainRecordsResponse {
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "TotalCount")]
    pub total_count: String,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RecordResponse {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "RecordId")]
    pub record_id: String,
}

pub struct AliyunDns {
    access_key_id: String,
    access_key_secret: String,
    client: Client,
}

impl AliyunDns {
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        let client = Client::new();
        AliyunDns {
            access_key_id,
            access_key_secret,
            client,
        }
    }

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

    pub async fn delete_domain_record(
        &self,
        record_id: &str,
    ) -> Result<RecordResponse> {
        let action = "DeleteDomainRecord";
        let mut params = HashMap::new();
        params.insert("RecordId", record_id);
        
        self.send_request(action, params).await
    }

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

    pub async fn query_domain_records(&self, domain_name: &str) -> Result<DomainRecordsResponse> {
        let action = "DescribeDomainRecords";
        let mut params = HashMap::new();
        params.insert("DomainName", domain_name);
        self.send_request(action, params).await
    }

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
        let mut mac = Hmac::new(Sha1::new(),signature_key.as_bytes());
        mac.input(string_to_sign.as_bytes());
        let result = mac.result();
        let signature = base64::engine::general_purpose::STANDARD.encode(result.code());
    
        signature
    }

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
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect::<String>()
}