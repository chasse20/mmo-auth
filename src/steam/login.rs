use crate::token::secret;
use anyhow::{Context, Result};
use sqlx::PgPool;
use std::time::Duration;

pub(crate) struct SteamLogin {
	state: String,
}

impl SteamLogin {
	pub(crate) async fn create(t_pool: &PgPool, t_lifetime: Duration) -> Result<Self> {
		let temp_state = secret::generate().context("Failed to generate Steam login state")?;
		let temp_state_hash = secret::hash(&temp_state).expect("generated state is canonical");
		let temp_microseconds = i64::try_from(t_lifetime.as_micros())?;

		sqlx::query(
			r#"
			INSERT INTO public."SteamLogin" ("StateHash", "ExpiresAt")
			VALUES ($1, NOW() + $2::BIGINT * INTERVAL '1 microsecond')
			"#,
		)
		.bind(&temp_state_hash[..])
		.bind(temp_microseconds)
		.execute(t_pool)
		.await
		.context("Failed to create Steam login attempt")?;

		Ok(Self { state: temp_state })
	}

	pub(crate) async fn consume(t_pool: &PgPool, t_state: &str) -> sqlx::Result<bool> {
		// Consume login state only after the callback and browser cookie agree
		let Some(temp_hash) = secret::hash(t_state) else {
			return Ok(false);
		};

		let temp_result = sqlx::query(
			r#"
			UPDATE public."SteamLogin"
			SET "ConsumedAt" = NOW()
			WHERE "StateHash" = $1
				AND "ConsumedAt" IS NULL
				AND "ExpiresAt" > NOW()
			"#,
		)
		.bind(&temp_hash[..])
		.execute(t_pool)
		.await?;

		Ok(temp_result.rows_affected() == 1)
	}

	pub(crate) fn state(&self) -> &str {
		&self.state
	}
}
