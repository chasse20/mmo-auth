mod app_state;
mod config;
mod http;
mod maintenance;
mod proto;
mod steam;
mod token;

use anyhow::Context;
use app_state::AppState;
use config::Config;
use sqlx::postgres::PgPoolOptions;
use token::access_issuer::AccessTokenIssuer;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let temp_config = Config::load()?;
	let temp_filter = EnvFilter::try_new(&temp_config.log_filter)?;

	tracing_subscriber::fmt()
		.with_env_filter(temp_filter)
		.init();

	// Validate the signing key and wipe its PEM contents before serving requests
	let mut temp_signing_pem = tokio::fs::read_to_string(&temp_config.access_token_key_path)
		.await
		.context("Unable to read access token signing key file")?;
	let temp_issuer_result = AccessTokenIssuer::new(
		&temp_signing_pem,
		&temp_config.access_token_key_id,
		&temp_config.access_token_issuer,
		&temp_config.access_token_audience,
		temp_config.access_token_lifetime,
	);
	temp_signing_pem.zeroize();
	let temp_issuer = temp_issuer_result?;

	// Apply the embedded SQLx migrations before accepting requests
	let temp_database_pool = PgPoolOptions::new()
		.max_connections(temp_config.database_max_connections)
		.acquire_timeout(temp_config.database_acquire_timeout)
		.connect(&temp_config.database_url)
		.await
		.context("Failed to connect to YugabyteDB")?;

	sqlx::migrate!("./migrations")
		.run(&temp_database_pool)
		.await
		.context("Failed to apply SQLx database migrations")?;
	tracing::info!("Database migrations validated and applied");

	let temp_state = AppState::new(&temp_config, temp_database_pool.clone(), temp_issuer)?;
	tracing::info!("Auth service initialized");

	let temp_cancellation_token = CancellationToken::new();
	let temp_maintenance_task = tokio::spawn(maintenance::run(
		temp_database_pool.clone(),
		temp_cancellation_token.child_token(),
		temp_config.maintenance_interval,
	));

	let temp_http_result = http::serve(
		temp_config.listen_address,
		temp_config.shutdown_grace_duration,
		temp_state,
	)
	.await;

	temp_cancellation_token.cancel();

	let _ = tokio::time::timeout(temp_config.shutdown_grace_duration, temp_maintenance_task).await;

	temp_database_pool.close().await;
	temp_http_result
}
