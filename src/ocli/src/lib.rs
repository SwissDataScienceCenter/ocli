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

#[derive(Debug, Clone)]
pub struct OIDCTokenset {
    access_token: String,
    refresh_token: Option<String>,
}

impl OIDCTokenset {
    pub fn new(access_token: String, refresh_token: Option<String>) -> Self {
        OIDCTokenset {
            access_token,
            refresh_token,
        }
    }
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
}

#[derive(Debug, Clone)]
pub struct DeviceCodeData {
    pub verify_url_full: String,
    pub verify_url: String,
    pub user_code: String,
    code_response: CoreDeviceAuthorizationResponse,
    provider_metadata: DeviceProviderMetadata,
    client_id: String,
    device_url: DeviceAuthorizationUrl,
}

pub fn start_device_code_flow(
    url: String,
    client_id: String,
    scopes: Vec<String>,
) -> Result<DeviceCodeData> {
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
        .add_scopes(scopes.iter().map(|s| Scope::new(s.clone())))
        .request(&http_client)?;
    let verify_url = details
        .verification_uri_complete()
        .map(|u| u.secret().to_owned())
        .expect("couldn't construct the full verification url");
    Ok(DeviceCodeData {
        verify_url_full: verify_url,
        verify_url: details.clone().verification_uri().to_string(),
        user_code: details.user_code().clone().into_secret(),
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

#[derive(Deserialize, Clone)]
pub struct Config {
    pub name: String,
    pub client_id: String,
    pub url: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
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

fn default_scopes() -> Vec<String> {
    vec![
        "email".to_string(),
        "profile".to_string(),
        "openid".to_string(),
    ]
}

#[derive(Deserialize, Clone)]
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
        let mut content = match std::fs::read_to_string(path.clone()) {
            Ok(content) => content,
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => return Ok(false),
                _ => return Result::Err(anyhow::Error::new(e)),
            },
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // Mock OIDCTokenset for testing
    fn mock_tokenset() -> OIDCTokenset {
        OIDCTokenset::new(
            "mock_access_token".to_string(),
            Some("mock_refresh_token".to_string()),
        )
    }

    // Test Config::download function
    #[test]
    fn test_config_download_file() {
        // Test downloading from a file
        let config_content = r#"
name = "test"
client_id = "test-client-id"
url = "https://example.com"
scopes = ["openid", "profile"]
[[rules]]
name = "test-rule"
path = "/tmp/test.txt"
patterns = ["test-pattern"]
"#;

        // Create a temporary directory and file
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("test_config.toml");
        fs::write(&config_file, config_content).unwrap();

        let file_url = format!("file://{}", config_file.to_string_lossy());
        let config = Config::download(file_url).unwrap();
        assert_eq!(config.name, "test");
        assert_eq!(config.client_id, "test-client-id");
        assert_eq!(config.url, "https://example.com");
        assert_eq!(config.scopes, vec!["openid", "profile"]);
    }

    #[test]
    fn test_config_apply_empty_rules() {
        let config = Config {
            name: "test".to_string(),
            client_id: "test-client-id".to_string(),
            url: "https://example.com".to_string(),
            scopes: vec!["openid".to_string()],
            rules: vec![],
        };

        let tokenset = mock_tokenset();
        let (applied, skipped) = config.apply(tokenset).unwrap();
        assert_eq!(applied.len(), 0);
        assert_eq!(skipped.len(), 0);
    }

    #[test]
    fn test_rule_render_no_file_no_template() {
        let temp_dir = TempDir::new().unwrap();
        let rule = Rule {
            name: "test-rule".to_string(),
            path: temp_dir
                .path()
                .join("nonexistent.txt")
                .to_str()
                .unwrap()
                .to_string(),
            patterns: vec![],
            new_file_template: None,
        };

        let tokenset = mock_tokenset();
        let result = rule.render(tokenset);
        assert!(result.is_ok());
    }
    #[test]
    fn test_rule_render_file_template() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("file.txt");
        let rule = Rule {
            name: "test-rule".to_string(),
            path: path.to_str().unwrap().to_string(),
            patterns: vec![],
            new_file_template: Some("test\ntest2\ntest3".to_string()),
        };

        let tokenset = mock_tokenset();
        let result = rule.render(tokenset);
        assert!(result.is_ok());
        let content = fs::read_to_string(path).unwrap();
        assert_eq!("test\ntest2\ntest3", content);
    }

    #[test]
    fn test_rule_patch_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let rule = Rule {
            name: "test-rule".to_string(),
            path: temp_dir
                .path()
                .join("nonexistent.txt")
                .to_str()
                .unwrap()
                .to_string(),
            patterns: vec![],
            new_file_template: None,
        };

        let tokenset = mock_tokenset();
        let result = rule.patch(tokenset);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_new_from_template_no_template() {
        let temp_dir = TempDir::new().unwrap();
        let rule = Rule {
            name: "test-rule".to_string(),
            path: temp_dir
                .path()
                .join("test.txt")
                .to_str()
                .unwrap()
                .to_string(),
            patterns: vec![],
            new_file_template: None,
        };

        let tokenset = mock_tokenset();
        let result = rule.new_from_template(tokenset);
        assert!(result.is_err()); // Should fail because no template
    }
}
