mod common;

#[cfg(all(feature = "use-protobuf", feature = "use-router-regex"))]
mod router;

use common::{setup_logger, Tester};

#[test]
fn test_integration_tcp() {
	println!(
		"Current work directory: {}",
		std::env::current_dir().unwrap().display()
	);

	setup_logger();

	let tester = Tester::new();
	// #[cfg(all(feature = "socks5-inbound", feature = "socks5-outbound"))]
	tester.test_socks5();
	#[cfg(all(feature = "http-inbound", feature = "http-outbound"))]
	tester.test_http();
	#[cfg(any(
		all(
			feature = "shadowsocks-inbound-openssl",
			feature = "shadowsocks-outbound-openssl"
		),
		all(
			feature = "shadowsocks-inbound-ring",
			feature = "shadowsocks-outbound-ring"
		)
	))]
	tester.test_shadowsocks();
	#[cfg(any(
		all(feature = "vmess-inbound-openssl", feature = "vmess-outbound-openssl"),
		all(feature = "vmess-inbound-ring", feature = "vmess-outbound-ring")
	))]
	tester.test_vmess();
	#[cfg(feature = "chain-outbound")]
	tester.test_chain();
	#[cfg(all(
		any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"),
		any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"),
		any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"),
	))]
	tester.test_transport();
}

#[cfg(feature = "use-udp")]
#[test]
fn test_integration_udp() {
	println!(
		"Current work directory: {}",
		std::env::current_dir().unwrap().display()
	);

	setup_logger();

	let tester = Tester::new();
	tester.test_udp_tunnel();
	#[cfg(any(
		all(feature = "vmess-inbound-openssl", feature = "vmess-outbound-openssl"),
		all(feature = "vmess-inbound-ring", feature = "vmess-outbound-ring")
	))]
	tester.test_udp_vmess();
	#[cfg(feature = "socks5-inbound")]
	tester.test_udp_socks();
}

#[cfg(all(feature = "use-protobuf", feature = "use-router-regex"))]
#[test]
fn test_integration_destination_container_geosite() {
	use ladder_lib::router::{Destination, DestinationContainer};
	use std::collections::HashSet;

	let file = "tests/geosites.dat";
	let tag = "amazon";
	let container = DestinationContainer::new(vec![Destination::GeoSite {
		file_path: file.to_owned().into(),
		tag: tag.to_owned().into(),
	}])
	.unwrap();
	{
		let expected_domains = router::AMAZON_DOMAINS
			.iter()
			.copied()
			.collect::<HashSet<&'static str>>();
		assert_eq!(expected_domains.len(), container.domains.len());
		for d in &container.domains {
			assert!(
				expected_domains.contains(d.as_str()),
				"domain '{}' not expected",
				d
			);
		}
	}
	{
		let expected_regexes = router::AMAZON_REGEX
			.iter()
			.copied()
			.collect::<HashSet<&'static str>>();
		assert_eq!(expected_regexes.len(), container.regex_domains.len());

		for d in &container.regex_domains {
			assert!(
				expected_regexes.contains(d.as_str()),
				"regex '{}' not expected",
				d
			);
		}
	}
	{
		let expected_full = router::AMAZON_FULL
			.iter()
			.copied()
			.collect::<HashSet<&'static str>>();
		assert_eq!(expected_full.len(), container.full_domains.len());

		for d in &container.full_domains {
			assert!(
				expected_full.contains(d.as_str()),
				"full domain '{}' not expected",
				d
			);
		}
	}
}
