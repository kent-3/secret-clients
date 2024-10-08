/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Configuration {
    pub base_path: String,
    pub user_agent: Option<String>,
    pub client: reqwest::Client,
    pub basic_auth: Option<BasicAuth>,
    pub oauth_access_token: Option<String>,
    pub bearer_access_token: Option<String>,
    pub api_key: Option<ApiKey>,
    // TODO: take an oauth2 token source, similar to the go one
}

pub type BasicAuth = (String, Option<String>);

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub prefix: Option<String>,
    pub key: String,
}

impl Configuration {
    pub fn new() -> Configuration {
        Configuration::default()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            base_path: "https://lcd.mainnet.secretsaturn.net".to_owned(),
            user_agent: Some("OpenAPI-Generator/v1.12.1/rust".to_owned()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            base_path: "https://lcd.mainnet.secretsaturn.net".to_owned(),
            user_agent: Some("OpenAPI-Generator/v1.12.1/rust".to_owned()),
            client: reqwest::Client::builder().build().unwrap(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        }
    }
}
