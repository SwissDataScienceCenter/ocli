use ocli::*;

#[test]
fn test_start_device_code_flow_mocked() {
    let _ = env_logger::try_init();
    let mut server = mockito::Server::new();
    let url = server.url();
    let mock_well_known_response = serde_json::json!({
    "issuer": format!("{url}/application/o/test/"),
    "authorization_endpoint": format!("{url}/application/o/authorize/"),
    "token_endpoint": format!("{url}/application/o/token/"),
    "userinfo_endpoint": format!("{url}/application/o/userinfo/"),
    "end_session_endpoint": format!("{url}/application/o/test/end-session/"),
    "introspection_endpoint": format!("{url}/application/o/introspect/"),
    "revocation_endpoint": format!("{url}/application/o/revoke/"),
    "device_authorization_endpoint": format!("{url}/application/o/device/"),
    "jwks_uri": format!("{url}/application/o/test/jwks/"),
    "response_types_supported": [
        "code",
        "id_token",
        "id_token token",
        "code token",
        "code id_token",
        "code id_token token"
      ],
    "response_modes_supported": [
        "query",
        "fragment",
        "form_post"
      ],
    "subject_types_supported": [
        "public"
      ],
    "id_token_signing_alg_values_supported": [
        "RS256"
      ],
    });
    server
        .mock(
            "GET",
            "/application/o/test/.well-known/openid-configuration",
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_well_known_response.to_string())
        .create();
    let mock_jwks_response = serde_json::json!(
        {"keys": [{"alg": "RS256", "kid": "72415d072e0293d892aa89b193426117", "kty": "RSA", "use": "sig", "n": "uL06RnKGhoozBH19_Ing_BaTjrULajzaQBASKMqU5VpZROTnSPSmHncarCBoBPB-l_HbUExQUsJNgEFAnUv-ywuURnVZ3Y6XtOZWffZKUgXSTcpsLaY1CBSCeBEF34mlPK0orqsernZuvuNw__rZ9t6SXM7tZfNuAkKiD_ATDl1bzZCO1uiXj_KL-ScQL8mTDIhSxTHGp8_ejhZ0JVORMPzJ44V-lkqwTj3uePBqsa5fMViC1vP2CFXwGHnHj2NcVRnrXgPBxIiqd8ymsEupbekw8vVoBeHsQDA_DLssr8_LuxMVT--rnKbfkzPsS0xbgNYu_rno8U2sNLfkkNMtsDSZlHxURYEt5Ank_sUKaJAfVpdTNGlzLnRu8XAYKrHaThoLpZZB1r3yIXFBP-rhqyURRrUF_ERYRLD0O1ulNidu-hlyMFKTnIXLfJr0UQgUDSKpaJck7axl7mubtx-kX76oOKXPlGokr8MBx4e30itFRC4145mIcPH7RdrWTAkwN67yzJceg_nnY7LusVN4lc5goRIYV3JW_7ZoMtDlhEp5lkYS32wqv1Z8tsWfxHkPM8zl7MkOyfBvouvzybYw8Okqm8MDkuSNEpEn8qjECVoFkHx_MpZv_P_R_mv12UWjUeFVsxAbJuUVnpSCdrrWF2Ea23WaKr-KnQAdvUgFYXk", "e": "AQAB", "x5c": ["MIIE5jCCAs6gAwIBAgIQMNz4vpMVTGi+4a7rZapwpzANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJhdXRoZW50aWsgMjAyNS42LjQwHhcNMjUwOTA3MDkyNTM5WhcNMjgwNjA0MDkyNTM5WjBBMRUwEwYDVQQDDAx2bGxtLWtleXBhaXIxEjAQBgNVBAoMCWF1dGhlbnRpazEUMBIGA1UECwwLU2VsZi1zaWduZWQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4vTpGcoaGijMEfX38ieD8FpOOtQtqPNpAEBIoypTlWllE5OdI9KYedxqsIGgE8H6X8dtQTFBSwk2AQUCdS/7LC5RGdVndjpe05lZ99kpSBdJNymwtpjUIFIJ4EQXfiaU8rSiuqx6udm6+43D/+tn23pJczu1l824CQqIP8BMOXVvNkI7W6JeP8ov5JxAvyZMMiFLFMcanz96OFnQlU5Ew/MnjhX6WSrBOPe548Gqxrl8xWILW8/YIVfAYecePY1xVGeteA8HEiKp3zKawS6lt6TDy9WgF4exAMD8Muyyvz8u7ExVP76ucpt+TM+xLTFuA1i7+uejxTaw0t+SQ0y2wNJmUfFRFgS3kCeT+xQpokB9Wl1M0aXMudG7xcBgqsdpOGgullkHWvfIhcUE/6uGrJRFGtQX8RFhEsPQ7W6U2J276GXIwUpOchct8mvRRCBQNIqlolyTtrGXua5u3H6Rfvqg4pc+UaiSvwwHHh7fSK0VELjXjmYhw8ftF2tZMCTA3rvLMlx6D+edjsu6xU3iVzmChEhhXclb/tmgy0OWESnmWRhLfbCq/Vny2xZ/EeQ8zzOXsyQ7J8G+i6/PJtjDw6SqbwwOS5I0SkSfyqMQJWgWQfH8ylm/8/9H+a/XZRaNR4VWzEBsm5RWelIJ2utYXYRrbdZoqv4qdAB29SAVheQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQBgZImR0PlBIc/76OtXO2NYDZFnnZ9Jy7KO3Z4Wax3TFqRkvvV6fGL1URsKwjVHsd438f36OOXn0oAUJ3tXg2wgS2dwHtHqaPD/ttBcHXldDLn5aWI1qSEAPuLStZQxgDqNsElA1G5jTBEBcItOXdn6Wyt3XrX7v0Ndiab8DL2zQdfqKliiWqpeI1P8g6U0b7Wt8sKpAuXFEAyp/fwmIgKwyWlYpSmj0We17drbQgyejlK+2MkwdHE8Umfw018yzB/Do2yviy7/VQmclUiGzTCbtcyjwolVDGXqggO9QmKpmTdx+oQBmjfwPa7XT5DncxBfHsDwPn7st6AzVIHx2HBM/JVBOSkX9XX8quYbh61YDY3XYojZx2gdlMX7L2ZyJI+fnkjW/pX1skqJhbbTwGTFi1108DFPiQ/fvhiXJcK11+iuMMBfwzS7u0X1qXx3L4bcPobwFjbgD1pxy+tPtMtaZWaG72Ir2/Qef8xdtevg/OnrB0XzLCshTJu0SFqgo6XDPuK9utZLpqKp9M2JBOHO3hHSTtr2kxcdnT7iWsuay7KPvw+To8nj2M/OEPy2kLAFHIFrdRS8Y6GTqTiCSjXcwZfebvOOJ3tayBGJvYNijsQAYesn/gNzksYEek53GnrH6RflZL+eWERNVO57jXv0oH+Ak3L9cLL/jdC5d6SRPg=="], "x5t": "KaR-8H4Kpr85oVCAo9XFgG26AHk", "x5t#S256": "bLuuBF-dvBKNm4NnySWVIh4P--2ZtGH8YUXfwgLgv_8"}]}
    );
    server
        .mock("GET", "/application/o/test/jwks/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_jwks_response.to_string())
        .create();
    let mock_device_response = serde_json::json!({
        "device_authorization_endpoint": format!("{url}/device/"),
        "verification_uri": format!("{url}/verify"),
        "user_code": "ABC123",
        "device_code": "abcdefg123456",
        "verification_uri_complete": format!("{url}/verify?user_code=ABC123"),
        "expires_in": 600,
        "interval": 5
    });
    server
        .mock("POST", "/application/o/device/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_device_response.to_string())
        .create();
    let response = start_device_code_flow(
        format!("{url}/application/o/test/"),
        "client123".to_string(),
        vec!["openid".to_string(), "profile".to_string()],
    );
    assert!(response.is_ok());
    let data = response.unwrap();

    let mock_code_response = serde_json::json!({
        "access_token": "abcdefgabcdefg",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "123456789abc"
    });
    server
        .mock("POST", "/application/o/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_code_response.to_string())
        .create();
    let response = finish_device_code_flow(data);
    assert!(response.is_ok());
    let tokens = response.unwrap();
    assert_eq!(tokens.access_token(), "abcdefgabcdefg");
    assert_eq!(tokens.refresh_token(), Some("123456789abc"));
}
