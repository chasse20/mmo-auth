use super::secret;
use anyhow::Result;
use sqlx::{PgConnection, PgPool, Row, types::Uuid};
use std::time::Duration;

pub(crate) struct RefreshToken {
	value: String,
}

impl RefreshToken {
	pub(crate) async fn issue(
		t_connection: &mut PgConnection,
		t_account_id: Uuid,
		t_family_id: Option<Uuid>,
		t_lifetime: Duration,
	) -> Result<Self> {
		let temp_value = secret::generate()?;
		let temp_hash = secret::hash(&temp_value).expect("generated refresh token is canonical");
		let temp_seconds = i64::try_from(t_lifetime.as_secs())?;

		sqlx::query(
			r#"
			INSERT INTO public."RefreshToken" ("AccountId", "FamilyId", "TokenHash", "ExpiresAt")
			VALUES ($1, COALESCE($2::UUID, gen_random_uuid()), $3,
				NOW() + $4::BIGINT * INTERVAL '1 second')
			"#,
		)
		.bind(t_account_id)
		.bind(t_family_id)
		.bind(&temp_hash[..])
		.bind(temp_seconds)
		.execute(t_connection)
		.await?;

		Ok(Self { value: temp_value })
	}

	pub(crate) async fn rotate(
		t_pool: &PgPool,
		t_value: &str,
		t_lifetime: Duration,
	) -> Result<Option<(Uuid, Self)>> {
		// Rotate refresh tokens under a lock and revoke on concurrent use to prevent replay attacks
		let Some(temp_hash) = secret::hash(t_value) else {
			return Ok(None);
		};
		let mut temp_transaction = t_pool.begin().await?;
		let temp_row = sqlx::query(
			r#"
			SELECT "AccountId", "FamilyId",
				("ExpiresAt" <= NOW()) AS "Expired",
				("ConsumedAt" IS NOT NULL) AS "Consumed",
				("RevokedAt" IS NOT NULL) AS "Revoked"
			FROM public."RefreshToken"
			WHERE "TokenHash" = $1
			FOR UPDATE
			"#,
		)
		.bind(&temp_hash[..])
		.fetch_optional(&mut *temp_transaction)
		.await?;

		let Some(temp_row) = temp_row else {
			return Ok(None);
		};
		let temp_account_id: Uuid = temp_row.try_get("AccountId")?;
		let temp_family_id: Uuid = temp_row.try_get("FamilyId")?;
		let temp_expired: bool = temp_row.try_get("Expired")?;
		let temp_consumed: bool = temp_row.try_get("Consumed")?;
		let temp_revoked: bool = temp_row.try_get("Revoked")?;

		if temp_revoked {
			return Ok(None);
		} else if temp_consumed {
			sqlx::query(
				r#"
				UPDATE public."RefreshToken"
				SET "RevokedAt" = NOW()
				WHERE "FamilyId" = $1 AND "RevokedAt" IS NULL
				"#,
			)
			.bind(temp_family_id)
			.execute(&mut *temp_transaction)
			.await?;
			temp_transaction.commit().await?;
			return Ok(None);
		} else if temp_expired {
			return Ok(None);
		}

		let temp_next = Self::issue(
			&mut *temp_transaction,
			temp_account_id,
			Some(temp_family_id),
			t_lifetime,
		)
		.await?;

		sqlx::query(
			r#"
			UPDATE public."RefreshToken" SET "ConsumedAt" = NOW()
			WHERE "TokenHash" = $1 AND "ConsumedAt" IS NULL
			"#,
		)
		.bind(&temp_hash[..])
		.execute(&mut *temp_transaction)
		.await?;

		temp_transaction.commit().await?;

		Ok(Some((temp_account_id, temp_next)))
	}

	pub(crate) async fn revoke_family(t_pool: &PgPool, t_value: &str) -> Result<()> {
		// Logout never reveals whether a refresh token exists
		let Some(temp_hash) = secret::hash(t_value) else {
			return Ok(());
		};

		sqlx::query(
			r#"
			UPDATE public."RefreshToken"
			SET "RevokedAt" = NOW()
			WHERE "FamilyId" = (
				SELECT "FamilyId" FROM public."RefreshToken" WHERE "TokenHash" = $1
			) AND "RevokedAt" IS NULL
			"#,
		)
		.bind(&temp_hash[..])
		.execute(t_pool)
		.await?;

		Ok(())
	}

	pub(crate) fn value(&self) -> &str {
		&self.value
	}
}
