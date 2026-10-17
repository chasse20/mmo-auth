use anyhow::{Context, Result, bail, ensure};
use reqwest::Client;
use std::{collections::HashMap, str};
use url::{Url, form_urlencoded};

const STEAM_OPENID_ENDPOINT: &str = "https://steamcommunity.com/openid/login";
const OPENID_NAMESPACE: &str = "http://specs.openid.net/auth/2.0";
const OPENID_IDENTIFIER_SELECT: &str = "http://specs.openid.net/auth/2.0/identifier_select";
const MAX_CALLBACK_QUERY_LENGTH: usize = 16_384;

pub(crate) struct SteamOpenId {
	realm: Url,
	callback_url: Url,
}

impl SteamOpenId {
	pub(crate) fn new(t_public_origin: &str) -> Result<Self> {
		let temp_realm =
			Url::parse(t_public_origin).context("PUBLIC_ORIGIN must be an absolute URL")?;
		let temp_is_local_http = temp_realm.scheme() == "http"
			&& matches!(
				temp_realm.host_str(),
				Some("localhost" | "127.0.0.1" | "[::1]")
			);

		ensure!(
			temp_realm.scheme() == "https" || temp_is_local_http,
			"PUBLIC_ORIGIN must use HTTPS (HTTP is permitted only on localhost)"
		);

		ensure!(
			temp_realm.username().is_empty() && temp_realm.password().is_none(),
			"PUBLIC_ORIGIN must not contain credentials"
		);

		ensure!(
			temp_realm.path() == "/"
				&& temp_realm.query().is_none()
				&& temp_realm.fragment().is_none(),
			"PUBLIC_ORIGIN must be an origin without a path, query or fragment"
		);

		let temp_callback_url = temp_realm
			.join("/auth/steam/callback")
			.context("Unable to construct the Steam callback URL")?;

		Ok(Self {
			realm: temp_realm,
			callback_url: temp_callback_url,
		})
	}

	pub(crate) fn get_authorization_url(&self, t_state: &str) -> Result<Url> {
		ensure!(
			is_valid_state(t_state),
			"Steam login state must be a URL-safe token of 32 to 128 characters"
		);

		let mut temp_return_to = self.callback_url.clone();
		temp_return_to
			.query_pairs_mut()
			.append_pair("state", t_state);

		let mut temp_authorization_url = Url::parse(STEAM_OPENID_ENDPOINT)?;
		temp_authorization_url
			.query_pairs_mut()
			.append_pair("openid.ns", OPENID_NAMESPACE)
			.append_pair("openid.mode", "checkid_setup")
			.append_pair("openid.return_to", temp_return_to.as_str())
			.append_pair("openid.realm", self.realm.as_str())
			.append_pair("openid.identity", OPENID_IDENTIFIER_SELECT)
			.append_pair("openid.claimed_id", OPENID_IDENTIFIER_SELECT);

		Ok(temp_authorization_url)
	}

	pub(crate) async fn verify_callback(
		&self,
		t_client: &Client,
		t_query: &str,
		t_browser_state: &str,
	) -> Result<Option<i64>> {
		// Require browser-bound state before checking the Steam assertion
		let Some((temp_form, temp_steam_id)) = self.prepare_assertion(t_query, t_browser_state)
		else {
			return Ok(None);
		};

		let mut temp_response = t_client
			.post(STEAM_OPENID_ENDPOINT)
			.form(&temp_form)
			.send()
			.await
			.context("Steam OpenID verification request failed")?
			.error_for_status()
			.context("Steam OpenID verification returned an HTTP error")?;
		let mut temp_response_body = Vec::new();

		while let Some(temp_chunk) = temp_response
			.chunk()
			.await
			.context("Unable to read Steam response")?
		{
			ensure!(
				temp_response_body.len() + temp_chunk.len() <= 4096,
				"Steam verification response too large"
			);
			temp_response_body.extend_from_slice(&temp_chunk);
		}

		let temp_body =
			str::from_utf8(&temp_response_body).context("Steam response is not UTF-8")?;

		// Parse and confirm Steam's direct OpenID verification response
		let mut temp_namespace = None;
		let mut temp_validity = None;

		for temp_line in temp_body.lines() {
			let (temp_key, temp_value) = temp_line
				.trim_end_matches('\r')
				.split_once(':')
				.context("Malformed Steam verification response")?;

			match temp_key {
				"ns" => {
					ensure!(
						temp_namespace.replace(temp_value).is_none(),
						"Duplicate Steam verification namespace"
					);
				}
				"is_valid" => {
					ensure!(
						temp_validity.replace(temp_value).is_none(),
						"Duplicate Steam verification result"
					);
				}
				_ => {}
			}
		}

		ensure!(
			temp_namespace == Some(OPENID_NAMESPACE),
			"Invalid Steam verification namespace"
		);

		match temp_validity {
			Some("true") => Ok(Some(temp_steam_id)),
			Some("false") => Ok(None),
			_ => bail!("Malformed Steam verification result"),
		}
	}

	fn prepare_assertion(
		&self,
		t_query: &str,
		t_browser_state: &str,
	) -> Option<(HashMap<String, String>, i64)> {
		if t_query.len() > MAX_CALLBACK_QUERY_LENGTH || !is_valid_state(t_browser_state) {
			return None;
		}

		let mut temp_fields = HashMap::new();

		for (temp_key, temp_value) in form_urlencoded::parse(t_query.as_bytes()) {
			if temp_fields
				.insert(temp_key.into_owned(), temp_value.into_owned())
				.is_some()
			{
				return None;
			}
		}

		let temp_field = |t_key: &str| temp_fields.get(t_key).map(String::as_str);

		let mut temp_return_to = self.callback_url.clone();
		temp_return_to
			.query_pairs_mut()
			.append_pair("state", t_browser_state);

		if temp_field("state") != Some(t_browser_state)
			|| temp_field("openid.ns") != Some(OPENID_NAMESPACE)
			|| temp_field("openid.mode") != Some("id_res")
			|| temp_field("openid.op_endpoint") != Some(STEAM_OPENID_ENDPOINT)
			|| temp_field("openid.return_to") != Some(temp_return_to.as_str())
		{
			return None;
		}

		let temp_claimed_id = temp_field("openid.claimed_id")?;

		if temp_field("openid.identity") != Some(temp_claimed_id) {
			return None;
		}

		let temp_digits = temp_claimed_id
			.strip_prefix("https://steamcommunity.com/openid/id/")
			.or_else(|| temp_claimed_id.strip_prefix("http://steamcommunity.com/openid/id/"))?;

		if temp_digits.is_empty() || !temp_digits.bytes().all(|t_digit| t_digit.is_ascii_digit()) {
			return None;
		}

		let temp_steam_id = temp_digits.parse::<i64>().ok().filter(|t_id| *t_id > 0)?;
		let temp_signed = temp_field("openid.signed")?;

		if ![
			"op_endpoint",
			"return_to",
			"response_nonce",
			"assoc_handle",
			"claimed_id",
			"identity",
		]
		.into_iter()
		.all(|t_required| temp_signed.split(',').any(|t_field| t_field == t_required))
		{
			return None;
		}

		// Forward only OpenID fields to Steam for direct verification
		temp_fields.retain(|t_key, _| t_key.starts_with("openid."));
		temp_fields.insert("openid.mode".to_owned(), "check_authentication".to_owned());

		Some((temp_fields, temp_steam_id))
	}
}

fn is_valid_state(t_state: &str) -> bool {
	(32..=128).contains(&t_state.len())
		&& t_state
			.bytes()
			.all(|t_byte| t_byte.is_ascii_alphanumeric() || t_byte == b'-' || t_byte == b'_')
}
