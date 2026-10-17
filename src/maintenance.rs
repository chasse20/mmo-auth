use sqlx::PgPool;
use std::time::Duration;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

pub(crate) async fn run(t_pool: PgPool, t_cancellation: CancellationToken, t_frequency: Duration) {
	let mut temp_interval = interval(t_frequency);
	temp_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

	loop {
		tokio::select! {
			_ = t_cancellation.cancelled() => break,
			_ = temp_interval.tick() => {
				// Preserve a short audit and replay window after expiration
				for temp_statement in [
					r#"DELETE FROM public."SteamLogin" WHERE "ExpiresAt" < NOW() - INTERVAL '1 day'"#,
					r#"DELETE FROM public."LoginExchange" WHERE "ExpiresAt" < NOW() - INTERVAL '1 day'"#,
					r#"DELETE FROM public."RefreshToken" WHERE "ExpiresAt" < NOW() - INTERVAL '7 days'"#,
				] {
					if let Err(temp_error) = sqlx::query(temp_statement).execute(&t_pool).await {
						tracing::warn!(error = %temp_error, "Expired authentication record cleanup failed");
					}
				}
			}
		}
	}
}
