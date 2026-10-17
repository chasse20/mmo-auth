use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, StatusCode};
use serde_json::Value;

const VERIFY_URL: &str = "https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/";
pub(crate) const MAX_TICKET_BYTES: usize = 2_560;

pub(crate) struct SteamTicketVerifier {
	app_id: u32,
	publisher_key: String,
	ticket_identity: String,
}

impl SteamTicketVerifier {
	pub(crate) fn new(t_app_id: u32, t_publisher_key: &str, t_ticket_identity: &str) -> Self {
		Self {
			app_id: t_app_id,
			publisher_key: t_publisher_key.to_owned(),
			ticket_identity: t_ticket_identity.to_owned(),
		}
	}

	pub(crate) async fn verify_ticket(
		&self,
		t_client: &Client,
		t_ticket: &[u8],
	) -> Result<Option<i64>> {
		// Only accept Steam-verified identities instead of Steam IDs asserted by clients
		let mut temp_url = url::Url::parse(VERIFY_URL)?;
		temp_url
			.query_pairs_mut()
			.append_pair("key", &self.publisher_key)
			.append_pair("appid", &self.app_id.to_string())
			.append_pair("ticket", &hex::encode(t_ticket))
			.append_pair("identity", &self.ticket_identity);
		let temp_response = t_client
			.get(temp_url)
			.send()
			.await
			.map_err(reqwest::Error::without_url)
			.context("Steam ticket verification request failed")?;

		let temp_status = temp_response.status();
		if temp_status != StatusCode::OK && temp_status != StatusCode::BAD_REQUEST {
			bail!("Steam ticket verification returned HTTP {temp_status}");
		}
		let temp_bytes = temp_response
			.bytes()
			.await
			.map_err(reqwest::Error::without_url)
			.context("Unable to read Steam ticket verification response")?;
		ensure!(
			temp_bytes.len() <= 16_384,
			"Unexpected Steam ticket verification response size"
		);
		let temp_payload: Value = serde_json::from_slice(&temp_bytes)
			.context("Steam returned a malformed ticket verification response")?;
		if temp_status == StatusCode::BAD_REQUEST {
			if steam_error_code(&temp_payload) == Some(101) {
				return Ok(None);
			}
			bail!("Steam rejected the ticket verification request with HTTP 400");
		}
		parse_response(&temp_payload)
	}
}

fn steam_error_code(t_payload: &Value) -> Option<i64> {
	let temp_value = t_payload.pointer("/response/error/errorcode")?;
	temp_value
		.as_i64()
		.or_else(|| temp_value.as_str()?.parse().ok())
}

fn parse_response(t_payload: &Value) -> Result<Option<i64>> {
	if let Some(temp_error_code) = steam_error_code(t_payload) {
		if temp_error_code == 101 {
			return Ok(None);
		}
		bail!("Steam ticket verification returned provider error {temp_error_code}");
	}

	let temp_params = t_payload
		.pointer("/response/params")
		.context("Steam ticket verification response is missing params")?;
	ensure!(
		temp_params.get("result").and_then(Value::as_str) == Some("OK"),
		"Steam ticket verification response did not confirm success"
	);

	let temp_steam_id: u64 = temp_params
		.get("steamid")
		.and_then(Value::as_str)
		.context("Steam ticket verification response is missing steamid")?
		.parse()
		.context("Steam returned a malformed SteamID64")?;
	let temp_steam_id =
		i64::try_from(temp_steam_id).context("SteamID64 exceeds the YugabyteDB BIGINT range")?;
	ensure!(temp_steam_id > 0, "Steam returned a non-positive Steam ID");

	Ok(Some(temp_steam_id))
}
