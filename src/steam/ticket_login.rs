use crate::{
	app_state::AppState,
	proto::AuthenticateSteamTicketRequest,
	steam::{account, ticket_verifier::MAX_TICKET_BYTES},
	token::{handlers, refresh::RefreshToken},
};
use axum::{
	body::Bytes,
	extract::State,
	http::{HeaderMap, StatusCode},
	response::Response,
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Result, types::Uuid};

pub(crate) async fn handle(
	State(t_state): State<AppState>,
	t_headers: HeaderMap,
	t_body: Bytes,
) -> Result<Response, StatusCode> {
	// Native authentication verifies Steam identity and records single-use ticket redemption
	let temp_verifier = t_state
		.ticket_verifier
		.as_ref()
		.ok_or(StatusCode::NOT_FOUND)?;
	let temp_request: AuthenticateSteamTicketRequest = handlers::decode(&t_headers, &t_body)?;

	if temp_request.ticket.is_empty() || temp_request.ticket.len() > MAX_TICKET_BYTES {
		return Err(StatusCode::BAD_REQUEST);
	}

	let temp_steam_id = temp_verifier
		.verify_ticket(&t_state.steam_client, &temp_request.ticket)
		.await
		.map_err(|t_error| {
			tracing::error!("Steamworks ticket verification failed: {t_error:#}");
			StatusCode::BAD_GATEWAY
		})?
		.ok_or(StatusCode::UNAUTHORIZED)?;
	let temp_account_id = account::get_or_create(&t_state.pool, temp_steam_id)
		.await
		.map_err(handlers::database_error)?;

	// Sign first so no database record is committed when signing fails
	let temp_access_token = t_state
		.access_issuer
		.issue(temp_account_id)
		.map_err(|t_error| {
			tracing::error!("Failed to sign access token: {t_error:#}");
			StatusCode::INTERNAL_SERVER_ERROR
		})?;
	let mut temp_transaction = t_state
		.pool
		.begin()
		.await
		.map_err(handlers::database_error)?;

	if !record_ticket(
		&mut *temp_transaction,
		&temp_request.ticket,
		temp_account_id,
	)
	.await
	.map_err(handlers::database_error)?
	{
		return Err(StatusCode::UNAUTHORIZED);
	}

	let temp_refresh_token = RefreshToken::issue(
		&mut *temp_transaction,
		temp_account_id,
		None,
		t_state.refresh_token_lifetime,
	)
	.await
	.map_err(handlers::database_error)?;

	temp_transaction
		.commit()
		.await
		.map_err(handlers::database_error)?;

	Ok(handlers::token_response(
		&t_state,
		temp_account_id,
		temp_access_token,
		&temp_refresh_token,
	))
}

async fn record_ticket(
	t_connection: &mut PgConnection,
	t_ticket: &[u8],
	t_account_id: Uuid,
) -> Result<bool> {
	// SHA-256 digest is the unique ticket key and prevents concurrent replays
	let temp_digest = Sha256::digest(t_ticket);
	let temp_result = sqlx::query(
		r#"
		INSERT INTO public."SteamTicket" ("SteamTicketId", "AccountId")
		VALUES ($1, $2)
		ON CONFLICT ("SteamTicketId") DO NOTHING
		"#,
	)
	.bind(&temp_digest[..])
	.bind(t_account_id)
	.execute(t_connection)
	.await?;
	Ok(temp_result.rows_affected() == 1)
}
