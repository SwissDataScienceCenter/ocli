use anyhow::Result;
use clap::Parser;
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
    CoreDeviceAuthorizationResponse, CoreGrantType, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreResponseMode,
    CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalProviderMetadata, AuthType, ClientId, ClientSecret, DeviceAuthorizationUrl,
    IssuerUrl, ProviderMetadata, Scope,
};
use openidconnect::{OAuth2TokenResponse, reqwest};

use serde::{Deserialize, Serialize};

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

#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    #[arg(short, long)]
    url: String,
    #[arg(short, long)]
    client_id: String,
}
fn main() {
    let args = Args::parse();
    let token = request_token(args.url, args.client_id).expect("couldn't get token");
    println!("Token: {}", token);
}

fn request_token(url: String, client_id: String) -> Result<String> {
    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");
    let provider_metadata = DeviceProviderMetadata::discover(&IssuerUrl::new(url)?, &http_client)?;
    let device_url = provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();
    println!("{}", device_url);
    let client =
        CoreClient::from_provider_metadata(provider_metadata, ClientId::new(client_id), None)
            .set_device_authorization_url(device_url)
            .set_auth_type(openidconnect::AuthType::RequestBody);
    let details: CoreDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(Scope::new("profile".to_string()))
        .request(&http_client)?;
    let details = dbg!(details);
    let verify_url = details
        .verification_uri_complete()
        .map(|u| u.secret().to_owned())
        .expect("couldn't construct the full verification url");
    println!(
        "Please visit {} and authorize this application.",
        verify_url
    );
    open::that(verify_url)?;

    let token = client.exchange_device_access_token(&details)?.request(
        &http_client,
        std::thread::sleep,
        None,
    )?;
    return Ok(token.access_token().secret().to_owned());
}
