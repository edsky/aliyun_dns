## Aliyun DNS API Client

This library provides a simple and easy-to-use client for interacting with the Aliyun DNS API. With this library, you can manage your domain records programmatically, including adding, updating, deleting, and querying records.

## Usage

To use the library, first create a new `AliyunDns` instance, providing your `access_key_id` and `access_key_secret`:

```rust
use aliyun_dns::AliyunDns;

let access_key_id = "your_access_key_id";
let access_key_secret = "your_access_key_secret";
let aliyun_dns = AliyunDns::new(access_key_id.to_string(), access_key_secret.to_string());
```

### Add a Domain Record

To add a domain record, use the `add_domain_record` method:

```rust
let domain_name = "example.com";
let sub_domain = "www";
let record_type = "A";
let record_value = "1.2.3.4";
let response = aliyun_dns.add_domain_record(domain_name, sub_domain, record_type, record_value).await?;
println!("Record ID: {}", response.record_id);
```

### Update a Domain Record

To update a domain record, use the `update_domain_record` method:

```rust
let record_id = "your_record_id";
let sub_domain = "www";
let record_type = "A";
let new_value = "2.3.4.5";
let response = aliyun_dns.update_domain_record(record_id, sub_domain, record_type, new_value).await?;
println!("Updated Record ID: {}", response.record_id);
```

### Delete a Domain Record

To delete a domain record, use the `delete_domain_record` method:

```rust
let record_id = "your_record_id";
let response = aliyun_dns.delete_domain_record(record_id).await?;
println!("Deleted Record ID: {}", response.record_id);
```

### Delete Subdomain Records

To delete subdomain records, use the `delete_subdomain_records` method:

```rust
let domain_name = "example.com";
let rr = "www";
let response = aliyun_dns.delete_subdomain_records(domain_name, rr).await?;
println!("Deleted RR: {}, Total Count: {}", response.rr, response.total_count);
```

### Query Domain Records

To query domain records, use the `query_domain_records` method:

```rust
let domain_name = "example.com";
let response = aliyun_dns.query_domain_records(domain_name).await?;
println!("Total Records: {}", response.total_count);

for record in response.domain_records.records {
    println!(
        "Record ID: {}, Type: {}, RR: {}, Value: {}",
        record.record_id, record.record_type, record.rr, record.value
    );
}
```

## Example Program

Here is an example program that demonstrates how to use the AliyunDns client:

```rust
use aliyun_dns::AliyunDns;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let access_key_id = "your_access_key_id";
    let access_key_secret = "your_access_key_secret";
    let aliyun_dns = AliyunDns::new(access_key_id.to_string(), access_key_secret.to_string());

    // Add a domain record
    let domain_name = "example.com";
    let sub_domain = "www";
    let record_type = "A";
    let record_value = "1.2.3.4";
    let response = aliyun_dns.add_domain_record(domain_name, sub_domain, record_type, record_value).await?;
    println!("Record ID: {}", response.record_id);
    // Update a domain record
    let record_id = &response.record_id;
    let sub_domain = "www";
    let record_type = "A";
    let new_value = "2.3.4.5";
    let update_response = aliyun_dns.update_domain_record(record_id, sub_domain, record_type, new_value).await?;
    println!("Updated Record ID: {}", update_response.record_id);

    // Query domain records
    let query_response = aliyun_dns.query_domain_records(domain_name).await?;
    println!("Total Records: {}", query_response.total_count);
    for record in query_response.domain_records.records {
        println!(
            "Record ID: {}, Type: {}, RR: {}, Value: {}",
            record.record_id, record.record_type, record.rr, record.value
        );
    }

    // Delete a domain record
    let delete_response = aliyun_dns.delete_domain_record(record_id).await?;
    println!("Deleted Record ID: {}", delete_response.record_id);

    // Delete subdomain records
    let rr = "www";
    let delete_subdomain_response = aliyun_dns.delete_subdomain_records(domain_name, rr).await?;
    println!(
        "Deleted RR: {}, Total Count: {}",
        delete_subdomain_response.rr, delete_subdomain_response.total_count
    );

    Ok(())
}
```