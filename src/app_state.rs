use crate::{
	config::Config,
	steam::{openid::SteamOpenId, ticket_verifier::SteamTicketVerifier},
	token::access_issuer::AccessTokenIssuer,
};
use anyhow::{Context, Result};
use reqwest::{Client, redirect::Policy};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub(crate) struct AppState {
	pub(crate) pool: PgPool,
	pub(crate) openid: Arc<SteamOpenId>,
	pub(crate) steam_client: Client,
	pub(crate) ticket_verifier: Option<Arc<SteamTicketVerifier>>,
	pub(crate) access_issuer: Arc<AccessTokenIssuer>,
	pub(crate) steam_login_lifetime: Duration,
	pub(crate) exchange_lifetime: Duration,
	pub(crate) refresh_token_lifetime: Duration,
	pub(crate) secure_cookie: bool,
	pub(crate) public_origin: String,
}

impl AppState {
	pub(crate) fn new(
		t_config: &Config,
		t_pool: PgPool,
		t_access_issuer: AccessTokenIssuer,
	) -> Result<Self> {
		let temp_openid = SteamOpenId::new(t_config.public_origin.as_str())?;
		let temp_steam_client = Client::builder()
			.timeout(t_config.steam_verify_timeout)
			.https_only(true)
			.redirect(Policy::none())
			.referer(false)
			.build()
			.context("Failed to initialize Steam HTTP client")?;

		let temp_ticket_verifier = t_config.steamworks.as_ref().map(|t_credentials| {
			Arc::new(SteamTicketVerifier::new(
				t_credentials.app_id,
				&t_credentials.publisher_key,
				&t_credentials.ticket_identity,
			))
		});

		Ok(Self {
			pool: t_pool,
			openid: Arc::new(temp_openid),
			steam_client: temp_steam_client,
			ticket_verifier: temp_ticket_verifier,
			access_issuer: Arc::new(t_access_issuer),
			steam_login_lifetime: t_config.steam_login_lifetime,
			exchange_lifetime: t_config.exchange_lifetime,
			refresh_token_lifetime: t_config.refresh_token_lifetime,
			secure_cookie: t_config.public_origin.scheme() == "https",
			public_origin: t_config
				.public_origin
				.as_str()
				.trim_end_matches('/')
				.to_owned(),
		})
	}
}
