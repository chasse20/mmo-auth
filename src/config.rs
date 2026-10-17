use anyhow::{Context, Result, ensure};
use std::{
	env, error::Error, io::ErrorKind, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration,
};
use url::Url;

pub(crate) struct SteamworksCredentials {
	pub(crate) app_id: u32,
	pub(crate) publisher_key: String,
	pub(crate) ticket_identity: String,
}

pub(crate) struct Config {
	pub(crate) log_filter: String,
	pub(crate) database_url: String,
	pub(crate) listen_address: SocketAddr,
	pub(crate) public_origin: Url,
	pub(crate) shutdown_grace_duration: Duration,
	pub(crate) steam_login_lifetime: Duration,
	pub(crate) steam_verify_timeout: Duration,
	pub(crate) exchange_lifetime: Duration,
	pub(crate) refresh_token_lifetime: Duration,
	pub(crate) access_token_lifetime: Duration,
	pub(crate) access_token_key_path: PathBuf,
	pub(crate) access_token_key_id: String,
	pub(crate) access_token_issuer: String,
	pub(crate) access_token_audience: String,
	pub(crate) database_max_connections: u32,
	pub(crate) database_acquire_timeout: Duration,
	pub(crate) maintenance_interval: Duration,
	pub(crate) steamworks: Option<SteamworksCredentials>,
}

impl Config {
	pub(crate) fn load() -> Result<Self> {
		// Load an optional local .env before validating required settings
		match dotenvy::from_path(".env") {
			Ok(_) => {}
			Err(dotenvy::Error::Io(temp_error)) if temp_error.kind() == ErrorKind::NotFound => {}
			Err(temp_error) => return Err(temp_error).context("Unable to load .env"),
		}

		let temp_log_filter = get_env_variable("RUST_LOG")?;
		let temp_database_url = get_env_variable("DATABASE_URL")?;
		let temp_listen_address = get_env_variable("LISTEN_ADDRESS")?;
		let temp_public_origin: Url = get_env_variable("PUBLIC_ORIGIN")?;
		let temp_shutdown: u64 = get_env_variable("SHUTDOWN_GRACE_SECONDS")?;
		let temp_steam_lifetime: u64 = get_env_variable("STEAM_LOGIN_TTL_SECONDS")?;
		let temp_steam_timeout: u64 = get_env_variable("STEAM_VERIFY_TIMEOUT_SECONDS")?;
		let temp_exchange_lifetime: u64 = get_env_variable("EXCHANGE_TTL_SECONDS")?;
		let temp_refresh_lifetime: u64 = get_env_variable("REFRESH_TOKEN_TTL_SECONDS")?;
		let temp_access_lifetime: u64 = get_env_variable("ACCESS_TOKEN_TTL_SECONDS")?;
		let temp_key_path = get_env_variable("ACCESS_TOKEN_PRIVATE_KEY_PATH")?;
		let temp_key_id: String = get_env_variable("ACCESS_TOKEN_KEY_ID")?;
		let temp_issuer: String = get_env_variable("ACCESS_TOKEN_ISSUER")?;
		let temp_audience: String = get_env_variable("ACCESS_TOKEN_AUDIENCE")?;
		let temp_max_connections: u32 = get_env_variable("DATABASE_MAX_CONNECTIONS")?;
		let temp_acquire_timeout: u64 = get_env_variable("DATABASE_ACQUIRE_TIMEOUT_SECONDS")?;
		let temp_maintenance_interval: u64 = get_env_variable("MAINTENANCE_INTERVAL_SECONDS")?;

		// Native Steamworks login is optional but needs complete credentials when enabled
		let temp_steamworks = if get_env_variable::<bool>("STEAMWORKS_ENABLED")? {
			let temp_app_id = get_env_variable("STEAMWORKS_APP_ID")?;
			let temp_publisher_key = get_env_variable("STEAMWORKS_PUBLISHER_KEY")?;
			let temp_ticket_identity: String = get_env_variable("STEAMWORKS_TICKET_IDENTITY")?;

			ensure!(
				temp_app_id != 0,
				"STEAMWORKS_APP_ID must be greater than zero"
			);
			ensure!(
				temp_ticket_identity.len() <= 128
					&& temp_ticket_identity.trim() == temp_ticket_identity,
				"STEAMWORKS_TICKET_IDENTITY must be at most 128 characters with no surrounding whitespace"
			);

			Some(SteamworksCredentials {
				app_id: temp_app_id,
				publisher_key: temp_publisher_key,
				ticket_identity: temp_ticket_identity,
			})
		} else {
			None
		};

		ensure!(
			(1..=300).contains(&temp_shutdown),
			"Invalid SHUTDOWN_GRACE_SECONDS"
		);
		ensure!(
			(1..=600).contains(&temp_steam_lifetime),
			"Invalid STEAM_LOGIN_TTL_SECONDS"
		);
		ensure!(
			(1..=30).contains(&temp_steam_timeout),
			"Invalid STEAM_VERIFY_TIMEOUT_SECONDS"
		);
		ensure!(
			(1..=300).contains(&temp_exchange_lifetime),
			"Invalid EXCHANGE_TTL_SECONDS"
		);
		ensure!(
			(3_600..=7_776_000).contains(&temp_refresh_lifetime),
			"Invalid REFRESH_TOKEN_TTL_SECONDS"
		);
		ensure!(
			(1..=900).contains(&temp_access_lifetime),
			"Invalid ACCESS_TOKEN_TTL_SECONDS"
		);
		ensure!(
			(1..=100).contains(&temp_max_connections),
			"Invalid DATABASE_MAX_CONNECTIONS"
		);
		ensure!(
			(1..=60).contains(&temp_acquire_timeout),
			"Invalid DATABASE_ACQUIRE_TIMEOUT_SECONDS"
		);
		ensure!(
			(300..=86_400).contains(&temp_maintenance_interval),
			"Invalid MAINTENANCE_INTERVAL_SECONDS"
		);
		ensure!(
			temp_public_origin.as_str().ends_with('/'),
			"PUBLIC_ORIGIN must end with /"
		);

		Ok(Self {
			log_filter: temp_log_filter,
			database_url: temp_database_url,
			listen_address: temp_listen_address,
			public_origin: temp_public_origin,
			shutdown_grace_duration: Duration::from_secs(temp_shutdown),
			steam_login_lifetime: Duration::from_secs(temp_steam_lifetime),
			steam_verify_timeout: Duration::from_secs(temp_steam_timeout),
			exchange_lifetime: Duration::from_secs(temp_exchange_lifetime),
			refresh_token_lifetime: Duration::from_secs(temp_refresh_lifetime),
			access_token_lifetime: Duration::from_secs(temp_access_lifetime),
			access_token_key_path: temp_key_path,
			access_token_key_id: temp_key_id,
			access_token_issuer: temp_issuer,
			access_token_audience: temp_audience,
			database_max_connections: temp_max_connections,
			database_acquire_timeout: Duration::from_secs(temp_acquire_timeout),
			maintenance_interval: Duration::from_secs(temp_maintenance_interval),
			steamworks: temp_steamworks,
		})
	}
}

fn get_env_variable<T>(t_key: &str) -> Result<T>
where
	T: FromStr,
	T::Err: Error + Send + Sync + 'static,
{
	let temp_value = env::var(t_key).with_context(|| format!("Unable to read {t_key}"))?;

	ensure!(!temp_value.trim().is_empty(), "{t_key} cannot be empty");

	temp_value
		.parse::<T>()
		.with_context(|| format!("Invalid {t_key} value"))
}
