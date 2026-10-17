use crate::{app_state::AppState, steam::login::SteamLogin};
use axum::{
	extract::State,
	http::{
		HeaderValue, StatusCode,
		header::{CACHE_CONTROL, SET_COOKIE},
	},
	response::{IntoResponse, Redirect, Response},
};

pub(crate) async fn handle(State(t_state): State<AppState>) -> Result<Response, StatusCode> {
	let temp_login = SteamLogin::create(&t_state.pool, t_state.steam_login_lifetime)
		.await
		.map_err(|t_error| {
			tracing::error!("Failed to create Steam login attempt: {t_error:#}");
			StatusCode::SERVICE_UNAVAILABLE
		})?;
	let temp_authorization_url = t_state
		.openid
		.get_authorization_url(temp_login.state())
		.map_err(|t_error| {
			tracing::error!("Failed to construct Steam authorization URL: {t_error:#}");
			StatusCode::INTERNAL_SERVER_ERROR
		})?;
	let temp_secure = if t_state.secure_cookie {
		"; Secure"
	} else {
		""
	};
	let temp_cookie = format!(
		"steam_login_state={}; Path=/auth/steam; Max-Age={}; HttpOnly; SameSite=Lax{}",
		temp_login.state(),
		t_state.steam_login_lifetime.as_secs(),
		temp_secure
	);

	let mut temp_response = Redirect::to(temp_authorization_url.as_str()).into_response();

	temp_response.headers_mut().append(
		SET_COOKIE,
		HeaderValue::from_str(&temp_cookie).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
	);
	temp_response
		.headers_mut()
		.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
	temp_response
		.headers_mut()
		.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

	Ok(temp_response)
}
