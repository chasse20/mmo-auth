use super::{exchange::LoginExchange, refresh::RefreshToken};
use crate::{
	app_state::AppState,
	proto::{
		ExchangeRequest, RefreshRequest, RevokeRequest, RevokeResponse, TokenResponse,
		ValidateRequest, ValidateResponse,
	},
};
use axum::{
	Json,
	body::Bytes,
	extract::State,
	http::{
		HeaderMap, HeaderValue, StatusCode,
		header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE},
	},
	response::{IntoResponse, Response},
};
use prost::Message;
use sqlx::types::Uuid;
use std::fmt::Display;

const PROTOBUF: &str = "application/x-protobuf";
const COOKIE_NAME: &str = "auth_exchange";

pub(crate) async fn exchange(
	State(t_state): State<AppState>,
	t_headers: HeaderMap,
	t_body: Bytes,
) -> Result<Response, StatusCode> {
	// Redeem the browser-bound cookie with refresh token issuance in one transaction
	if !same_origin(&t_headers, &t_state.public_origin) {
		return Err(StatusCode::FORBIDDEN);
	}

	let _: ExchangeRequest = decode(&t_headers, &t_body)?;
	let temp_code = read_cookie(&t_headers, COOKIE_NAME).ok_or(StatusCode::UNAUTHORIZED)?;
	let mut temp_transaction = t_state.pool.begin().await.map_err(database_error)?;
	let temp_account_id = LoginExchange::consume(&mut *temp_transaction, temp_code)
		.await
		.map_err(database_error)?
		.ok_or(StatusCode::UNAUTHORIZED)?;
	let temp_access_token = t_state
		.access_issuer
		.issue(temp_account_id)
		.map_err(internal_error)?;
	let temp_refresh_token = RefreshToken::issue(
		&mut *temp_transaction,
		temp_account_id,
		None,
		t_state.refresh_token_lifetime,
	)
	.await
	.map_err(database_error)?;

	temp_transaction.commit().await.map_err(database_error)?;

	let mut temp_response = token_response(
		&t_state,
		temp_account_id,
		temp_access_token,
		&temp_refresh_token,
	);

	temp_response
		.headers_mut()
		.append(SET_COOKIE, exchange_cookie("", 0, t_state.secure_cookie));

	Ok(temp_response)
}

pub(crate) async fn refresh(
	State(t_state): State<AppState>,
	t_headers: HeaderMap,
	t_body: Bytes,
) -> Result<Response, StatusCode> {
	let temp_request: RefreshRequest = decode(&t_headers, &t_body)?;

	if temp_request.refresh_token.is_empty() || temp_request.refresh_token.len() > 256 {
		return Err(StatusCode::UNAUTHORIZED);
	}

	let (temp_account_id, temp_refresh_token) = RefreshToken::rotate(
		&t_state.pool,
		&temp_request.refresh_token,
		t_state.refresh_token_lifetime,
	)
	.await
	.map_err(database_error)?
	.ok_or(StatusCode::UNAUTHORIZED)?;

	let temp_access_token = t_state
		.access_issuer
		.issue(temp_account_id)
		.map_err(internal_error)?;

	Ok(token_response(
		&t_state,
		temp_account_id,
		temp_access_token,
		&temp_refresh_token,
	))
}

pub(crate) async fn revoke(
	State(t_state): State<AppState>,
	t_headers: HeaderMap,
	t_body: Bytes,
) -> Result<Response, StatusCode> {
	let temp_request: RevokeRequest = decode(&t_headers, &t_body)?;

	if temp_request.refresh_token.len() > 256 {
		return Err(StatusCode::BAD_REQUEST);
	}

	RefreshToken::revoke_family(&t_state.pool, &temp_request.refresh_token)
		.await
		.map_err(database_error)?;

	Ok(encode(&RevokeResponse { revoked: true }))
}

pub(crate) async fn validate(
	State(t_state): State<AppState>,
	t_headers: HeaderMap,
	t_body: Bytes,
) -> Result<Response, StatusCode> {
	let temp_request: ValidateRequest = decode(&t_headers, &t_body)?;
	let temp_account_id = t_state.access_issuer.verify(&temp_request.access_token);

	Ok(encode(&ValidateResponse {
		valid: temp_account_id.is_some(),
		account_id: temp_account_id.map_or(String::new(), |t_id| t_id.to_string()),
	}))
}

pub(crate) async fn jwks(State(t_state): State<AppState>) -> Response {
	let mut temp_response = Json(t_state.access_issuer.get_jwks()).into_response();

	temp_response.headers_mut().insert(
		CACHE_CONTROL,
		HeaderValue::from_static("public, max-age=300"),
	);

	temp_response
}

// Build a single token response shared by both Steam login flows and refresh
pub(crate) fn token_response(
	t_state: &AppState,
	t_account_id: Uuid,
	t_access_token: String,
	t_refresh_token: &RefreshToken,
) -> Response {
	encode(&TokenResponse {
		access_token: t_access_token,
		refresh_token: t_refresh_token.value().to_owned(),
		expires_in_seconds: t_state.access_issuer.expires_in_seconds(),
		account_id: t_account_id.to_string(),
	})
}

pub(crate) fn exchange_cookie(t_code: &str, t_seconds: u64, t_secure: bool) -> HeaderValue {
	let temp_secure = if t_secure { "; Secure" } else { "" };

	HeaderValue::from_str(&format!(
		"{COOKIE_NAME}={t_code}; Path=/auth/exchange; Max-Age={t_seconds}; HttpOnly; SameSite=Lax{temp_secure}"
	)).expect("generated cookie contains only safe ASCII")
}

fn same_origin(t_headers: &HeaderMap, t_expected: &str) -> bool {
	let mut temp_values = t_headers.get_all(ORIGIN).iter();

	matches!(
		(temp_values.next(), temp_values.next()),
		(Some(temp_value), None) if temp_value.to_str().ok() == Some(t_expected)
	)
}

pub(crate) fn read_cookie<'a>(t_headers: &'a HeaderMap, t_name: &str) -> Option<&'a str> {
	// Reject duplicate cookie names rather than choosing an attacker-controlled value
	let mut temp_value = None;

	for temp_header in t_headers.get_all(COOKIE).iter() {
		let temp_cookies = temp_header.to_str().ok()?;

		for temp_cookie in temp_cookies.split(';') {
			let Some(temp_found) = temp_cookie
				.trim()
				.strip_prefix(t_name)
				.and_then(|t_rest| t_rest.strip_prefix('='))
			else {
				continue;
			};
			if temp_value.replace(temp_found).is_some() {
				return None;
			}
		}
	}

	temp_value
}

pub(crate) fn decode<M: Message + Default>(
	t_headers: &HeaderMap,
	t_body: &Bytes,
) -> Result<M, StatusCode> {
	if t_headers
		.get(CONTENT_TYPE)
		.and_then(|t_header| t_header.to_str().ok())
		!= Some(PROTOBUF)
	{
		return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
	}

	M::decode(t_body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)
}

pub(crate) fn encode<M: Message>(t_message: &M) -> Response {
	let mut temp_response = t_message.encode_to_vec().into_response();

	temp_response
		.headers_mut()
		.insert(CONTENT_TYPE, HeaderValue::from_static(PROTOBUF));
	temp_response
		.headers_mut()
		.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
	temp_response.headers_mut().insert(
		"x-content-type-options",
		HeaderValue::from_static("nosniff"),
	);

	temp_response
}

pub(crate) fn database_error(t_error: impl Display) -> StatusCode {
	tracing::error!("Authentication database operation failed: {t_error}");
	StatusCode::SERVICE_UNAVAILABLE
}

fn internal_error(t_error: impl Display) -> StatusCode {
	tracing::error!("Authentication token issuance failed: {t_error}");
	StatusCode::INTERNAL_SERVER_ERROR
}
