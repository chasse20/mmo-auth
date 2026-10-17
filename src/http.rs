use crate::{app_state::AppState, steam, token};
use anyhow::{Context, Result, bail};
use axum::{
	Router,
	extract::{DefaultBodyLimit, State},
	http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
	response::{Html, IntoResponse, Response},
	routing::{get, post},
};
use std::{
	future::IntoFuture,
	io::{self, Error, ErrorKind},
	net::SocketAddr,
	time::Duration,
};
use steam::{callback, start, ticket_login};
use token::handlers;
use tokio::{net::TcpListener, signal, sync::oneshot, time::timeout};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal as unix_signal};

pub(crate) async fn serve(
	t_address: SocketAddr,
	t_grace: Duration,
	t_state: AppState,
) -> Result<()> {
	let temp_listener = TcpListener::bind(t_address)
		.await
		.with_context(|| format!("Failed to bind HTTP listener at {t_address}"))?;
	let temp_bound_address = temp_listener.local_addr()?;

	// Register the native ticket route only when Steamworks credentials are configured
	let mut temp_router = Router::new()
		.route("/health/live", get(liveness))
		.route("/health/ready", get(readiness))
		.route("/auth/steam/start", get(start::handle))
		.route("/auth/steam/callback", get(callback::handle))
		.route("/auth/steam/complete", get(browser_complete))
		.route("/auth/exchange", post(handlers::exchange))
		.route("/auth/refresh", post(handlers::refresh))
		.route("/auth/revoke", post(handlers::revoke))
		.route("/auth/validate", post(handlers::validate))
		.route("/.well-known/jwks.json", get(handlers::jwks))
		.layer(DefaultBodyLimit::max(4096));

	if t_state.ticket_verifier.is_some() {
		temp_router = temp_router.route("/auth/steam/ticket", post(ticket_login::handle));
	}

	let (temp_shutdown_sender, temp_shutdown_receiver) = oneshot::channel::<()>();
	let temp_server = axum::serve(temp_listener, temp_router.with_state(t_state))
		.with_graceful_shutdown(async move {
			let _ = temp_shutdown_receiver.await;
		})
		.into_future();

	tokio::pin!(temp_server);

	// Drain pending requests within the configured shutdown deadline
	tracing::info!(address = %temp_bound_address, "HTTP service listening");
	tokio::select! {
		temp_result = &mut temp_server => {
			temp_result.context("HTTP server failed")?;
			bail!("HTTP server exited without a shutdown request")
		}
		temp_signal_result = get_shutdown_signal() => {
			temp_signal_result.context("Failed while waiting for a shutdown signal")?;
			tracing::info!("Shutting down HTTP service");
			let _ = temp_shutdown_sender.send(());
			timeout(t_grace, &mut temp_server)
				.await
				.context("HTTP graceful shutdown exceeded its deadline")?
				.context("HTTP server failed while shutting down")
		}
	}
}

async fn liveness() -> StatusCode {
	StatusCode::OK
}

async fn readiness(State(t_state): State<AppState>) -> StatusCode {
	match sqlx::query_scalar::<_, i32>("SELECT 1")
		.fetch_one(&t_state.pool)
		.await
	{
		Ok(1) => StatusCode::OK,
		_ => StatusCode::SERVICE_UNAVAILABLE,
	}
}

async fn browser_complete() -> Response {
	// Complete the browser redirect without exposing login credentials to the page
	let temp_html = r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer"><title>Steam Login</title></head>
<body><h1>Steam authentication completed</h1>
<p>Your login has been verified. The client can now redeem its one-time exchange credential.</p>
</body></html>"#;
	let mut temp_response = Html(temp_html).into_response();

	temp_response
		.headers_mut()
		.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
	temp_response
		.headers_mut()
		.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
	temp_response.headers_mut().insert(
		"x-content-type-options",
		HeaderValue::from_static("nosniff"),
	);
	temp_response.headers_mut().insert(
		"content-security-policy",
		HeaderValue::from_static("default-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
	);

	temp_response
}

async fn get_shutdown_signal() -> io::Result<()> {
	#[cfg(unix)]
	{
		let mut temp_terminate = unix_signal(SignalKind::terminate())?;
		tokio::select! {
			temp_result = signal::ctrl_c() => temp_result,
			temp_result = temp_terminate.recv() => {
				temp_result.ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "SIGTERM stream closed"))?;
				Ok(())
			}
		}
	}
	#[cfg(not(unix))]
	{
		signal::ctrl_c().await
	}
}
