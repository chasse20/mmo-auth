use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
	println!("cargo:rerun-if-changed=proto/auth.proto");
	println!("cargo:rerun-if-changed=migrations");

	let temp_protoc = protoc_bin_vendored::protoc_bin_path()?;
	prost_build::Config::new()
		.protoc_executable(temp_protoc)
		.compile_protos(&["proto/auth.proto"], &["proto"])?;
	Ok(())
}
