use sqlx::{Error, PgPool, Result, types::Uuid};
use std::time::Duration;
use tokio::time;

const MAX_CREATE_ATTEMPTS: usize = 5;

pub(crate) async fn get_or_create(t_pool: &PgPool, t_steam_account_id: i64) -> Result<Uuid> {
	// Resolve or create accounts while retrying concurrent Steam identity inserts
	for temp_attempt in 0..MAX_CREATE_ATTEMPTS {
		match try_get_or_create(t_pool, t_steam_account_id).await {
			Ok(Some(temp_account_id)) => return Ok(temp_account_id),
			Ok(None) => {}
			Err(temp_error)
				if is_retryable(&temp_error) && temp_attempt + 1 < MAX_CREATE_ATTEMPTS => {}
			Err(temp_error) => return Err(temp_error),
		}
		if temp_attempt + 1 < MAX_CREATE_ATTEMPTS {
			time::sleep(Duration::from_millis(25u64 << temp_attempt)).await;
		}
	}
	Err(Error::RowNotFound)
}

async fn try_get_or_create(t_pool: &PgPool, t_steam_account_id: i64) -> Result<Option<Uuid>> {
	let temp_existing = sqlx::query_scalar::<_, Uuid>(
		r#"SELECT "AccountId" FROM public."SteamAccount" WHERE "SteamAccountId" = $1"#,
	)
	.bind(t_steam_account_id)
	.fetch_optional(t_pool)
	.await?;

	if temp_existing.is_some() {
		return Ok(temp_existing);
	}

	// Roll back the placeholder Account if another request wins the Steam ID race
	let mut temp_transaction = t_pool.begin().await?;
	let temp_created = sqlx::query_scalar::<_, Uuid>(
		r#"
		WITH new_account AS (
			INSERT INTO public."Account" DEFAULT VALUES
			RETURNING "AccountId"
		)
		INSERT INTO public."SteamAccount" ("SteamAccountId", "AccountId")
		SELECT $1, "AccountId" FROM new_account
		WHERE TRUE
		ON CONFLICT ("SteamAccountId") DO NOTHING
		RETURNING "AccountId"
		"#,
	)
	.bind(t_steam_account_id)
	.fetch_optional(&mut *temp_transaction)
	.await?;

	if temp_created.is_some() {
		temp_transaction.commit().await?;
	} else {
		temp_transaction.rollback().await?;
	}

	Ok(temp_created)
}

fn is_retryable(t_error: &Error) -> bool {
	matches!(
		t_error,
		Error::Database(temp_error)
			if matches!(temp_error.code().as_deref(), Some("40001" | "40P01"))
	)
}
