use super::secret;
use anyhow::Result;
use sqlx::{PgConnection, PgPool, types::Uuid};
use std::time::Duration;

pub(crate) struct LoginExchange {
	code: String,
}

impl LoginExchange {
	pub(crate) async fn create(
		t_pool: &PgPool,
		t_account_id: Uuid,
		t_lifetime: Duration,
	) -> Result<Self> {
		let temp_code = secret::generate()?;
		let temp_hash = secret::hash(&temp_code).expect("generated secret is canonical");
		let temp_seconds = i64::try_from(t_lifetime.as_secs())?;

		sqlx::query(
			r#"
			INSERT INTO public."LoginExchange" ("AccountId", "CodeHash", "ExpiresAt")
			VALUES ($1, $2, NOW() + $3::BIGINT * INTERVAL '1 second')
			"#,
		)
		.bind(t_account_id)
		.bind(&temp_hash[..])
		.bind(temp_seconds)
		.execute(t_pool)
		.await?;

		Ok(Self { code: temp_code })
	}

	pub(crate) async fn consume(
		t_connection: &mut PgConnection,
		t_code: &str,
	) -> sqlx::Result<Option<Uuid>> {
		// Share a transaction with refresh issuance so failures restore the exchange code
		let Some(temp_hash) = secret::hash(t_code) else {
			return Ok(None);
		};

		sqlx::query_scalar::<_, Uuid>(
			r#"
			UPDATE public."LoginExchange"
			SET "ConsumedAt" = NOW()
			WHERE "CodeHash" = $1
				AND "ConsumedAt" IS NULL
				AND "ExpiresAt" > NOW()
			RETURNING "AccountId"
			"#,
		)
		.bind(&temp_hash[..])
		.fetch_optional(t_connection)
		.await
	}

	pub(crate) fn code(&self) -> &str {
		&self.code
	}
}
