use std::{collections::HashMap, time::SystemTime};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const IAP_ISSUER: &str = "https://cloud.google.com/iap";

/// The claims in a JWT issued by Google IAP.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Claims {
    pub exp: u64,
    pub iat: u64,
    pub aud: String,
    pub iss: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hd: Option<String>,
    pub sub: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google: Option<Value>,
}

/// The error returned by the `decode_and_validate` method.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid kid: {0}")]
    InvalidKid(String),
    #[error("Invalid alg: {0}, must be ES256")]
    InvalidAlgorithm(String),
    #[error("Invalid aud: {actual}, expected {expected}")]
    InvalidAudience { actual: String, expected: String },
    #[error("Invalid issuer: {0}, expected {}", IAP_ISSUER)]
    InvalidIssuer(String),
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error(transparent)]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
    #[error("Request failed: {0}")]
    RequestFailed(Box<dyn std::error::Error + Send + 'static>),
    #[error("Kid not available in header")]
    KidNotAvailable,
    #[error("Invalid iat: {actual} > {expected}")]
    FutureIat { actual: u64, expected: u64 },
    #[error("Invalid hosted domain: {actual}, expected {expected:?}")]
    InvalidHostedDomain {
        actual: String,
        expected: Vec<String>,
    },
    #[error("hd claim is missing, expected {expected:?}")]
    HdClaimMissing { expected: Vec<String> },
    #[error("Insufficient access level, expected {0}")]
    InsufficientAccessLevel(String),
    #[error("Access levels claim is missing")]
    AccessLevelsMissing,
    #[error("Invalid google claims")]
    InvalidGoogleClaims,
}

/// Configures validation options for JWT issued by Google IAP.
///
/// # Validation Options
///
/// - By default, validates the audience claim against the provided list.
/// - `with_google_hosted_domain`: Additionally validates the `hd` (hosted domain) claim.
/// - `with_access_levels`: Additionally validates the access levels claim in the Google-specific payload.
pub struct ValidationConfig {
    audience: Vec<String>,
    /// "If an account belongs to a hosted domain, the hd claim is provided to differentiate the domain the account is associated with." - https://cloud.google.com/iap/docs/signed-headers-howto
    google_hosted_domain: Option<Vec<String>>,
    access_levels: Option<Vec<String>>,
}

impl ValidationConfig {
    /// Creates a new validation config with the given audience.
    ///
    /// By default, validates the audience claim against the provided list.
    pub fn new<A, I>(audience: I) -> Self
    where
        A: Into<String>,
        I: IntoIterator<Item = A>,
    {
        Self {
            audience: audience.into_iter().map(Into::into).collect(),
            google_hosted_domain: None,
            access_levels: None,
        }
    }

    /// Validates that the hd claim is in the list of google hosted domains.
    ///
    /// "If an account belongs to a hosted domain, the hd claim is provided to differentiate the domain the account is associated with." - https://cloud.google.com/iap/docs/signed-headers-howto
    pub fn with_google_hosted_domain<H, I>(mut self, google_hosted_domain: I) -> Self
    where
        H: Into<String>,
        I: IntoIterator<Item = H>,
    {
        self.google_hosted_domain =
            Some(google_hosted_domain.into_iter().map(Into::into).collect());
        self
    }

    /// Validates that the access levels claim contains all the access levels in the config.
    pub fn with_access_levels<T: Into<String>>(
        mut self,
        access_levels: impl IntoIterator<Item = T>,
    ) -> Self {
        self.access_levels = Some(access_levels.into_iter().map(Into::into).collect());
        self
    }

    /// Decode and validate a jwt with respect to the IAP documentation: https://cloud.google.com/iap/docs/signed-headers-howto
    pub async fn decode_and_validate<E: std::error::Error + Send + 'static>(
        &self,
        token: &str,
        client: &impl PublicKeySource<Error = E>,
    ) -> Result<Claims, Error> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or(Error::KidNotAvailable)?;
        let public_key = client
            .get_public_key(&kid)
            .await
            .map_err(|e| Error::RequestFailed(Box::new(e)))?
            .ok_or_else(|| Error::InvalidKid(kid))?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&self.audience);
        validation.set_issuer(&[IAP_ISSUER]);

        let token = decode::<Claims>(
            token,
            &DecodingKey::from_ec_pem(public_key.as_bytes())
                .map_err(|_| Error::InvalidKeyFormat)?,
            &validation,
        )?;

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if token.claims.iat > now {
            return Err(Error::FutureIat {
                actual: token.claims.iat,
                expected: now,
            });
        }

        if let Some(expected_hd) = &self.google_hosted_domain {
            let Some(hd) = &token.claims.hd else {
                return Err(Error::HdClaimMissing {
                    expected: expected_hd.clone(),
                });
            };
            if !expected_hd.contains(hd) {
                return Err(Error::InvalidHostedDomain {
                    actual: hd.clone(),
                    expected: expected_hd.clone(),
                });
            }
        }

        if let Some(expected_access_levels) = &self.access_levels {
            #[derive(Deserialize)]
            struct GoogleClaims {
                access_levels: Vec<String>,
            }
            let google: GoogleClaims = serde_json::from_value(
                token
                    .claims
                    .google
                    .as_ref()
                    .ok_or(Error::AccessLevelsMissing)?
                    .clone(),
            )
            .map_err(|_| Error::InvalidGoogleClaims)?;
            for access_level in expected_access_levels {
                if !google.access_levels.contains(access_level) {
                    return Err(Error::InsufficientAccessLevel(access_level.clone()));
                }
            }
        }

        Ok(token.claims)
    }
}

pub trait PublicKeySource {
    type Error: std::error::Error + Send + 'static;

    fn get_public_key(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>, Self::Error>> + Send;
}

#[cfg(feature = "reqwest")]
impl PublicKeySource for reqwest::Client {
    type Error = reqwest::Error;

    async fn get_public_key(&self, key: &str) -> Result<Option<String>, Self::Error> {
        Ok(self
            .get("https://www.gstatic.com/iap/verify/public_key")
            .send()
            .await?
            .error_for_status()?
            .json::<HashMap<String, String>>()
            .await?
            .remove(key))
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    use super::*;

    const VALID_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrpu756TO0uDuesyS
1S1jL/6u/X5TUTfnSscBq6sVLTihRANCAATnZzElTUxsOkFb6AhJ2vRUy3uSuRy/
JX8+CfoH13EhLv+gIqtL8ooDGQKktq9fd/yo89wv3Ut8CVDxET2h34jE
-----END PRIVATE KEY-----
";
    const VALID_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52cxJU1MbDpBW+gISdr0VMt7krkc
vyV/Pgn6B9dxIS7/oCKrS/KKAxkCpLavX3f8qPPcL91LfAlQ8RE9od+IxA==
-----END PUBLIC KEY-----
";

    const TEST_AUD: &str = "/projects/1234567890/global/backendServices/test-service-id";
    const TEST_KID: &str = "test-kid";

    fn test_header() -> Header {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        header
    }

    fn test_claims() -> Claims {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 30;
        Claims {
            exp: now + 3600,
            iat: now,
            aud: TEST_AUD.to_string(),
            iss: "https://cloud.google.com/iap".into(),
            hd: Some("example.com".to_string()),
            google: Some(json!({
                "access_levels": ["OWNER", "EDITOR"],
            })),
            sub: "1234567890".into(),
            email: "test@example.com".into(),
        }
    }

    #[derive(Debug, Error)]
    #[error("Mock error: {0}")]
    struct MockError(String);

    fn mock_client(
        f: impl Fn(&str) -> Result<Option<String>, MockError> + Send + Sync + 'static,
    ) -> impl PublicKeySource {
        type MockFn = Box<dyn Fn(&str) -> Result<Option<String>, MockError> + Send + Sync>;
        struct MockClient(MockFn);
        impl PublicKeySource for MockClient {
            type Error = MockError;

            async fn get_public_key(&self, key: &str) -> Result<Option<String>, Self::Error> {
                self.0(key)
            }
        }
        MockClient(Box::new(f))
    }

    #[tokio::test]
    async fn test_decode_with_public_key() {
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let decoded = ValidationConfig::new([TEST_AUD])
            .with_google_hosted_domain(["example.com"])
            .with_access_levels(["OWNER", "EDITOR"])
            .decode_and_validate(&token, &client)
            .await
            .unwrap();
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.iat, claims.iat);
        assert_eq!(decoded.aud, claims.aud);
        assert_eq!(decoded.iss, claims.iss);
        assert_eq!(decoded.hd, claims.hd);
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.email, claims.email);
    }

    #[tokio::test]
    async fn test_decode_with_public_key_not_found() {
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(None)
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Invalid kid: test-kid");
    }

    #[tokio::test]
    async fn test_decode_with_private_key_is_invalid() {
        const TEST_INVALID_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgx1I+Ljp/UOxUumfg
kp1T9PFpY8RklbMF1SHmFaB1OXihRANCAAQnLQRg6fL2pgJYUPKdl6DFVsKtda3i
sDlX34kd5D0tFCdaZ5LH7MRtf5ptFCWouh7JDyOcAucHHwz0Z20PKFmu
-----END PRIVATE KEY-----
";
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(TEST_INVALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "InvalidSignature");
    }

    #[tokio::test]
    async fn test_decode_invalid_audience() {
        let mut claims = test_claims();
        claims.aud = "invalid-aud".to_string();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "InvalidAudience");
    }

    #[tokio::test]
    async fn test_decode_aud_not_found() {
        let claims = test_claims();
        let mut json = serde_json::to_value(&claims).unwrap();
        json.as_object_mut().unwrap().remove("aud");
        let token = jsonwebtoken::encode(
            &test_header(),
            &json,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("missing field `aud`"),
            "{} does not contain `aud`",
            error
        );
    }

    #[tokio::test]
    async fn test_decode_invalid_algorithm() {
        const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDbWZjcOnBP8XB1
OJIitW3Nc7/YpI+rNni1JBCSngMN/PVnOWrmkEj3ObsvYPwVpZ+FF+tKYNdcCU3S
Z6ntUkd6404tB/QeutCtRFF1m9jtLa1bayP3dnsnhrrD/qsV/BWxw1BynJ8a1HLe
303E0jBKNa+kVxf0OMccHyyoAAnaOtCvJmY+xFV/Z9ai584Rs8aKWoiL+vg28tEt
LGu/YgWIbEibVbQCpy8w8kuYFraU92uuXlCDJ6SMIfWmaj4yob/YiGDqwYTT+jyF
EZIXsHJzuUXCsgshfG4cAOKjYpqR+bbRwPVznINxQLWgs4SCisX8xMXuAumyVLta
K330dWXbAgMBAAECgf994+gVzockCXpcI/Yrqor2frBkeorbChDfdTEUB6imaxFa
hHpyMPMA2BTt15yX7yVgKuOObvNplETXao6ZKWeq+mZgnZoghcZ2pNgbuoIjeEWv
H2rJu1vHnp5/hvs/+k7QmByaDtlz3b87iFfuRvKC3RTes8AFfXF39w684B0SZlpp
rayQY2eXNQnVZXxORLls2NEkqFByZmIuNd0yIuvnYaYICtvzL8Er7xPkgLREvmzH
rivbjhL2IpFrlH7Hye9kKSrQ0nwmuKAZutOYP1PPq1YrK/dEkJhy6NdqAcMlBhib
PH4WQ2wCFtADb74mI3vfEKDHFMdaEf0XxBc0BEECgYEA8CkZbejMFcuIrWuXJ61V
EtFEKZQVr8LKvGhlE41vEqfqBt7Gj6VHz9fJEVo/nrqz9lZz6lKFZMF0TLkEHRFc
jtXaLoJQ9OVcqiA4cwUFoHE99rjql8oDZ2/ccOaHnmxlXfByGUTDuI+CxbuEh8AR
GfFk7HR8h6rR2jlMDQrox4cCgYEA6dEhN5LNIHY0lpLx9rhDEb/ecsn64bo4vOTk
KiSwcw/VDiYQeua6JnVpY1c4Ir9us5+NNCs/As00LJeNdWkFDLO5dnxud0mqquKd
SSG1tS4L7CIi7IqQYeOSDB3idFxj8u/8M6FgMVXuDui+inxkd+0Yb1ZVmtC9vTCD
oEPLnA0CgYBLpXZ4E0Ltfo3PqjsTaVqJsdbZjeaC1UWMsQldbkhVRQTHIzbCGlqT
UjHoQFgXxFFZP4QFg/a2dOUQIZr1GPnhl+TAj5W2feSBReLh/+v0zJaq9zYVl7EY
zLhP650+PoBzZYBbCzjnEnUrmVQ2ej4owMt8W3i6Nwkgxrl4xj3qUwKBgQCipt5q
oG6dxFz02igEL05IzKZcR/GEkVzi2n92aattf3gAra4NMPARzN+RQZ1FXtINllJO
Fj9xHXrMAmlfYb0nhubfa9QUm2RkF9y+gPq8nNmiXGTbE9E4p2xzjV54/8RvvU4+
RGZ8K4C9Ul8qSzpAyuiSmwZV+hvjvhnypPbBCQKBgFNo/R0p0O9GLAPe6aF5dJVx
mXTqfrk1BmXxkSS16EgoZC8D8N6EnAQC8tI6FFYWYsgD7kaUnKG1lNIXQjw63PDx
NksAFp0qJeVLilaFwTXrR1RNIoWzWrZkWzsZ3IHpE1WHgrH3hzVZ0O3X94ns4vT6
W8BYg+xGjeeybwjKuiVc
-----END PRIVATE KEY-----
";
        const TEST_RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA21mY3DpwT/FwdTiSIrVt
zXO/2KSPqzZ4tSQQkp4DDfz1Zzlq5pBI9zm7L2D8FaWfhRfrSmDXXAlN0mep7VJH
euNOLQf0HrrQrURRdZvY7S2tW2sj93Z7J4a6w/6rFfwVscNQcpyfGtRy3t9NxNIw
SjWvpFcX9DjHHB8sqAAJ2jrQryZmPsRVf2fWoufOEbPGilqIi/r4NvLRLSxrv2IF
iGxIm1W0AqcvMPJLmBa2lPdrrl5QgyekjCH1pmo+MqG/2Ihg6sGE0/o8hRGSF7By
c7lFwrILIXxuHADio2Kakfm20cD1c5yDcUC1oLOEgorF/MTF7gLpslS7Wit99HVl
2wIDAQAB
-----END PUBLIC KEY-----
";
        let mut header = test_header();
        header.alg = Algorithm::RS256;
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(TEST_RSA_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Invalid key format"));
    }

    #[tokio::test]
    async fn test_decode_request_failure_handling() {
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Err(MockError("test-error".to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Request failed: Mock error: test-error");
    }

    #[tokio::test]
    async fn test_docode_kid_not_available() {
        let mut header = test_header();
        header.kid = None;
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Err(MockError("test-error".to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Kid not available in header");
    }

    #[tokio::test]
    async fn test_decode_future_iat() {
        let mut claims = test_claims();
        claims.iat += 60;
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Invalid iat"));
    }

    #[tokio::test]
    async fn test_decode_without_iat() {
        let claims = test_claims();
        let mut json = serde_json::to_value(&claims).unwrap();
        json.as_object_mut().unwrap().remove("iat");
        let token = jsonwebtoken::encode(
            &test_header(),
            &json,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("missing field `iat`"));
    }

    #[tokio::test]
    async fn test_decode_expired() {
        let mut claims = test_claims();
        claims.exp -= 4000;
        claims.iat -= 4000;
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Expired"));
    }

    #[tokio::test]
    async fn test_decode_without_exp() {
        let claims = test_claims();
        let mut json = serde_json::to_value(&claims).unwrap();
        json.as_object_mut().unwrap().remove("exp");
        let token = jsonwebtoken::encode(
            &test_header(),
            &json,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("missing field `exp`"));
    }

    #[tokio::test]
    async fn test_decode_without_iss() {
        let claims = test_claims();
        let mut json = serde_json::to_value(&claims).unwrap();
        json.as_object_mut().unwrap().remove("iss");
        let token = jsonwebtoken::encode(
            &test_header(),
            &json,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("missing field `iss`"));
    }

    #[tokio::test]
    async fn test_decode_invalid_iss() {
        let mut claims = test_claims();
        claims.iss = "invalid-iss".to_string();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "InvalidIssuer");
    }

    #[tokio::test]
    async fn test_decode_validate_hd() {
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .with_google_hosted_domain(["another.example.com"])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid hosted domain: example.com, expected [\"another.example.com\"]"
        );
    }

    #[tokio::test]
    async fn test_decode_hd_not_found() {
        let mut claims = test_claims();
        claims.hd = None;
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .with_google_hosted_domain(["example.com"])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "hd claim is missing, expected [\"example.com\"]"
        );
    }

    #[tokio::test]
    async fn test_decode_validate_access_levels() {
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .with_access_levels(["EDITOR", "ADMIN"])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Insufficient access level, expected ADMIN"
        );
    }

    #[tokio::test]
    async fn test_decode_validate_access_levels_missing() {
        let claims = test_claims();
        let mut json = serde_json::to_value(&claims).unwrap();
        json.as_object_mut().unwrap().remove("google");
        let token = jsonwebtoken::encode(
            &test_header(),
            &json,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let error = ValidationConfig::new([TEST_AUD])
            .with_access_levels(["EDITOR"])
            .decode_and_validate(&token, &client)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Access levels claim is missing");
    }

    #[tokio::test]
    async fn test_decode_super_set_access_levels() {
        let claims = test_claims();
        let token = jsonwebtoken::encode(
            &test_header(),
            &claims,
            &EncodingKey::from_ec_pem(VALID_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let client = mock_client(|key| {
            assert_eq!(key, TEST_KID);
            Ok(Some(VALID_PUBLIC_KEY.to_string()))
        });
        let decoded = ValidationConfig::new([TEST_AUD])
            .with_google_hosted_domain(["example.com"])
            .with_access_levels(["EDITOR"])
            .decode_and_validate(&token, &client)
            .await
            .unwrap();
        assert_eq!(decoded.sub, claims.sub);
    }
}
