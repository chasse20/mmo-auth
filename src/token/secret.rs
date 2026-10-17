use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const SECRET_BYTES: usize = 32;
const SECRET_LENGTH: usize = 43;

pub(crate) fn generate() -> Result<String> {
	let mut temp_random = [0u8; SECRET_BYTES];
	getrandom::fill(&mut temp_random).context("Secure random number generator failed")?;
	Ok(URL_SAFE_NO_PAD.encode(temp_random))
}

pub(crate) fn hash(t_value: &str) -> Option<[u8; SECRET_BYTES]> {
	if t_value.len() != SECRET_LENGTH {
		return None;
	}

	let temp_bytes = URL_SAFE_NO_PAD.decode(t_value).ok()?;

	if temp_bytes.len() != SECRET_BYTES || URL_SAFE_NO_PAD.encode(temp_bytes) != t_value {
		return None;
	}

	let temp_digest = Sha256::digest(t_value.as_bytes());
	let mut temp_hash = [0u8; SECRET_BYTES];
	temp_hash.copy_from_slice(&temp_digest);

	Some(temp_hash)
}
