use crate::{
	app_state::AppState,
	steam::{account, login::SteamLogin},
	token::{
		exchange::LoginExchange,
		handlers::{exchange_cookie, read_cookie},
		secret,
	},
};
use axum::{
	extract::{RawQuery, State},
	http::{
		HeaderMap, HeaderValue, StatusCode,
		header::{CACHE_CONTROL, REFERRER_POLICY, SET_COOKIE},
	},
	response::{IntoResponse, Redirect, Response},
};
use sqlx::types::Uuid;

pub(crate) async fn handle(
	State(t_state): State<AppState>,
	t_headers: HeaderMap,
	RawQuery(t_query): RawQuery,
) -> Response {
	let temp_outcome = finish_login(&t_state, t_query.as_deref(), &t_headers).await;
	let mut temp_response = match temp_outcome {
		Ok(temp_account_id) => {
			match LoginExchange::create(&t_state.pool, temp_account_id, t_state.exchange_lifetime)
				.await
			{
				Ok(temp_exchange) => {
					let mut temp_response = Redirect::to("/auth/steam/complete").into_response();
					temp_response.headers_mut().append(
						SET_COOKIE,
						exchange_cookie(
							temp_exchange.code(),
							t_state.exchange_lifetime.as_secs(),
							t_state.secure_cookie,
						),
					);
					temp_response
				}
				Err(temp_error) => {
					tracing::error!("Failed to create one-time login exchange: {temp_error:#}");
					(
						StatusCode::SERVICE_UNAVAILABLE,
						"Unable to finish authentication; please retry.",
					)
						.into_response()
				}
			}
		}
		Err(temp_status) => (
			temp_status,
			"Steam login failed. Start a new login attempt.",
		)
			.into_response(),
	};

	let temp_clear_state = if t_state.secure_cookie {
		HeaderValue::from_static(
			"steam_login_state=; Path=/auth/steam; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
		)
	} else {
		HeaderValue::from_static(
			"steam_login_state=; Path=/auth/steam; Max-Age=0; HttpOnly; SameSite=Lax",
		)
	};

	temp_response
		.headers_mut()
		.append(SET_COOKIE, temp_clear_state);
	temp_response
		.headers_mut()
		.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
	temp_response
		.headers_mut()
		.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
	temp_response
}

async fn finish_login(
	t_state: &AppState,
	t_query: Option<&str>,
	t_headers: &HeaderMap,
) -> Result<Uuid, StatusCode> {
	// Verify Steam OpenID and consume the browser state before resolving the account
	let temp_query = t_query.ok_or(StatusCode::BAD_REQUEST)?;
	let temp_browser_state = read_cookie(t_headers, "steam_login_state")
		.filter(|t_value| secret::hash(t_value).is_some())
		.ok_or(StatusCode::UNAUTHORIZED)?;
	let temp_steam_id = t_state
		.openid
		.verify_callback(&t_state.steam_client, temp_query, temp_browser_state)
		.await
		.map_err(|t_error| {
			tracing::error!("Steam OpenID verification failed: {t_error:#}");
			StatusCode::BAD_GATEWAY
		})?
		.ok_or(StatusCode::UNAUTHORIZED)?;

	if !SteamLogin::consume(&t_state.pool, temp_browser_state)
		.await
		.map_err(|t_error| {
			tracing::error!("Failed to consume Steam login state: {t_error}");
			StatusCode::SERVICE_UNAVAILABLE
		})? {
		return Err(StatusCode::UNAUTHORIZED);
	}

	account::get_or_create(&t_state.pool, temp_steam_id)
		.await
		.map_err(|t_error| {
			tracing::error!("Failed to resolve Steam account: {t_error}");
			StatusCode::SERVICE_UNAVAILABLE
		})
}
