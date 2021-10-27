#[cfg(feature = "use-protobuf")]
extern crate protobuf_codegen_pure;

fn main() {
	#[cfg(feature = "use-protobuf")]
	{
		println!("cargo:rerun-if-changed=src/router/protos/rules.proto");
		protobuf_codegen_pure::Codegen::new()
			.out_dir("src/router/protos")
			.inputs(&["src/router/protos/rules.proto"])
			.include("src/router/protos")
			.run()
			.expect("Codegen failed.");
	}
}
