use anyhow::{Context, Result, ensure};
use jwt_simple::prelude::*;
use serde_json::Value;
use sqlx::types::Uuid;
use std::time::Duration as StdDuration;

const MAX_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 900;

pub(crate) struct AccessTokenIssuer {
	key_pair: Ed25519KeyPair,
	issuer: String,
	audience: String,
	lifetime: Duration,
}

impl AccessTokenIssuer {
	pub(crate) fn new(
		t_private_key_pem: &str,
		t_key_id: &str,
		t_issuer: &str,
		t_audience: &str,
		t_lifetime: StdDuration,
	) -> Result<Self> {
		ensure!(
			!t_key_id.trim().is_empty(),
			"Access token key ID is required"
		);
		ensure!(
			!t_issuer.trim().is_empty(),
			"Access token issuer is required"
		);
		ensure!(
			!t_audience.trim().is_empty(),
			"Access token audience is required"
		);

		let temp_seconds = t_lifetime.as_secs();

		ensure!(
			(1..=MAX_ACCESS_TOKEN_LIFETIME_SECONDS).contains(&temp_seconds)
				&& t_lifetime.subsec_nanos() == 0,
			"Access token lifetime must be between 1 and 900 whole seconds"
		);

		let temp_key_pair = Ed25519KeyPair::from_pem(t_private_key_pem)
			.context("Invalid Ed25519 access token signing key")?
			.with_key_id(t_key_id);

		Ok(Self {
			key_pair: temp_key_pair,
			issuer: t_issuer.to_owned(),
			audience: t_audience.to_owned(),
			lifetime: Duration::from_secs(temp_seconds),
		})
	}

	pub(crate) fn verify(&self, t_token: &str) -> Option<Uuid> {
		if t_token.len() > 4096 {
			return None;
		}
		let mut temp_options = VerificationOptions::default();
		temp_options.allowed_issuers = Some([self.issuer.clone()].into_iter().collect());
		temp_options.allowed_audiences = Some([self.audience.clone()].into_iter().collect());
		temp_options.time_tolerance = Some(Duration::from_secs(0));

		let temp_claims = self
			.key_pair
			.public_key()
			.verify_token::<NoCustomClaims>(t_token, Some(temp_options))
			.ok()?;
		let temp_account_id = temp_claims.subject?.parse::<Uuid>().ok()?;

		(!temp_account_id.is_nil()).then_some(temp_account_id)
	}

	pub(crate) fn get_jwks(&self) -> Value {
		// Publish only public JWK material
		serde_json::json!({"keys": [self.key_pair.public_key().to_jwk()]})
	}

	pub(crate) fn expires_in_seconds(&self) -> u64 {
		self.lifetime.as_secs()
	}

	pub(crate) fn issue(&self, t_account_id: Uuid) -> Result<String> {
		ensure!(
			!t_account_id.is_nil(),
			"Cannot issue a token for a nil AccountId"
		);
		let temp_claims = Claims::create(self.lifetime)
			.with_subject(t_account_id.to_string())
			.with_issuer(&self.issuer)
			.with_audience(&self.audience);
		self.key_pair
			.sign(temp_claims)
			.context("Failed to sign access token")
	}
}
