use std::path::PathBuf;

use anyhow::{Context, Result};
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
    CoreDeviceAuthorizationResponse, CoreGrantType, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreResponseMode,
    CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalProviderMetadata, ClientId, DeviceAuthorizationUrl, IssuerUrl, ProviderMetadata,
    Scope,
};
use openidconnect::{OAuth2TokenResponse, reqwest};

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DeviceEndpointProviderMetadata {
    device_authorization_endpoint: DeviceAuthorizationUrl,
}
impl AdditionalProviderMetadata for DeviceEndpointProviderMetadata {}
type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

#[derive(Clone)]
pub struct OIDCTokenset {
    access_token: String,
    refresh_token: Option<String>,
}

impl OIDCTokenset {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
}

pub struct DeviceCodeData {
    pub verify_url_full: String,
    pub verify_url: String,
    pub device_code: String,
    code_response: CoreDeviceAuthorizationResponse,
    provider_metadata: DeviceProviderMetadata,
    client_id: String,
    device_url: DeviceAuthorizationUrl,
}

pub fn start_device_code_flow(url: String, client_id: String) -> Result<DeviceCodeData> {
    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");
    let provider_metadata = DeviceProviderMetadata::discover(&IssuerUrl::new(url)?, &http_client)?;
    let device_url = provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();
    let client = CoreClient::from_provider_metadata(
        provider_metadata.clone(),
        ClientId::new(client_id.clone()),
        None,
    )
    .set_device_authorization_url(device_url.clone())
    .set_auth_type(openidconnect::AuthType::RequestBody);
    let details: CoreDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(Scope::new("profile".to_string()))
        .request(&http_client)?;
    let verify_url = details
        .verification_uri_complete()
        .map(|u| u.secret().to_owned())
        .expect("couldn't construct the full verification url");
    Ok(DeviceCodeData {
        verify_url_full: verify_url,
        verify_url: details.clone().verification_uri().to_string(),
        device_code: details.device_code().clone().into_secret(),
        code_response: details,
        provider_metadata,
        client_id,
        device_url,
    })
}

pub fn finish_device_code_flow(data: DeviceCodeData) -> Result<OIDCTokenset> {
    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");
    let client = CoreClient::from_provider_metadata(
        data.provider_metadata,
        ClientId::new(data.client_id),
        None,
    )
    .set_device_authorization_url(data.device_url)
    .set_auth_type(openidconnect::AuthType::RequestBody);
    let token = client
        .exchange_device_access_token(&data.code_response)?
        .request(&http_client, std::thread::sleep, None)?;
    let token = OIDCTokenset {
        access_token: token.access_token().secret().to_owned(),
        refresh_token: token.refresh_token().map(|t| t.secret().to_owned()),
    };

    Ok(token)
}

#[derive(Deserialize)]
pub struct Config {
    pub name: String,
    pub client_id: String,
    pub url: String,
    pub rules: Vec<Rule>,
}
impl Config {
    pub fn affected_paths(&self) -> Result<Vec<PathBuf>> {
        self.rules.iter().map(|r| r.resolved_path()).collect()
    }
    pub fn download(url: String) -> Result<Config> {
        let config: Config = if url.starts_with("file://") {
            let url = Url::parse(url.as_str())?;
            let path = url
                .to_file_path()
                .expect("couldn't convert local uri to file path");
            let content = std::fs::read(path)?;
            toml::from_slice(&content)?
        } else {
            let response = reqwest::blocking::get(url)?;
            let content = response.bytes()?;
            toml::from_slice(&content)?
        };
        Ok(config)
    }

    pub fn apply(&self, tokenset: OIDCTokenset) -> Result<(Vec<&str>, Vec<&str>)> {
        let mut skipped = Vec::new();
        let mut applied = Vec::new();
        for rule in self.rules.iter() {
            if rule.render(tokenset.clone())? {
                applied.push(rule.name.as_str());
            } else {
                skipped.push(rule.name.as_str());
            }
        }
        Ok((applied, skipped))
    }
}

#[derive(Deserialize)]
pub struct Rule {
    pub name: String,
    pub path: String,
    pub patterns: Vec<String>,
    pub new_file_template: Option<String>,
}

impl Rule {
    pub fn resolved_path(&self) -> Result<PathBuf> {
        let path = shellexpand::full(&self.path)?;
        Ok(PathBuf::from(&path.to_string()))
    }

    fn regex_patterns(&self) -> Vec<Regex> {
        self.patterns
            .iter()
            .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("couldn't parse pattern {}", p)))
            .collect()
    }

    pub fn render(&self, tokenset: OIDCTokenset) -> Result<bool> {
        let path = self.resolved_path()?;
        let mut matched = false;
        if path.exists() {
            // update file
            matched = self.patch(tokenset)?;
        } else if self.new_file_template.is_some() {
            // create file
            self.new_from_template(tokenset)?;
            matched = true;
        }

        Ok(matched)
    }
    fn patch(&self, tokenset: OIDCTokenset) -> Result<bool> {
        let path = self.resolved_path()?;
        let mut content = std::fs::read_to_string(path.clone())?;
        let mut matched = false;
        for pattern in self.regex_patterns() {
            let mut caps = pattern.captures_iter(content.as_str()).peekable();
            if caps.peek().is_none() {
                continue;
            }
            let mut new = String::with_capacity(content.len());
            let mut last_match = 0;

            for cap in caps {
                if let Some(m) = cap.name("access_token") {
                    new.push_str(&content[last_match..m.start()]);
                    new.push_str(tokenset.access_token());
                    last_match = m.end();
                    matched = true;
                }
                if let Some(m) = cap.name("refresh_token") {
                    new.push_str(&content[last_match..m.start()]);
                    new.push_str(tokenset.refresh_token().expect("refresh token not found"));
                    last_match = m.end();
                    matched = true;
                }
            }
            content = new;
        }
        std::fs::write(path, content)?;

        Ok(matched)
    }

    fn new_from_template(&self, tokenset: OIDCTokenset) -> Result<()> {
        let mut tera = tera::Tera::default();
        tera.add_raw_template(
            self.name.as_str(),
            self.new_file_template
                .clone()
                .context("new_file_template is empty")?
                .as_str(),
        )?;
        let mut context = tera::Context::new();
        context.insert("access_token", tokenset.access_token());
        if let Some(refresh_token) = tokenset.refresh_token() {
            context.insert("refresh_token", refresh_token);
        }
        let rendered = tera.render(self.name.as_str(), &context)?;
        std::fs::write(self.resolved_path()?, rendered)?;
        Ok(())
    }
}
