/**********************************************************************

Copyright (C) 2021 by reddal

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

**********************************************************************/

const TAG_BLOCKED: &str = "$blocked";

const DOMAIN_PREFIX: &str = "domain";
#[allow(dead_code)]
const DOMAIN_REGEXP_PREFIX: &str = "regexp";
const DOMAIN_FULL_PREFIX: &str = "full";
const DOMAIN_SUBSTR_PREFIX: &str = "substr";

#[allow(dead_code)]
const GEOSITE_PREFIX: &str = "geosite";
#[allow(dead_code)]
const GEOIP_PREFIX: &str = "geoip";

use crate::protocol::SocksDestination;
use super::Cidr;
use smol_str::SmolStr;
use std::{borrow::Cow, collections::HashSet, net::IpAddr, str::FromStr};

#[cfg(feature = "use-protobuf")]
use super::protos::rules as proto;

#[allow(unused_imports)]
use crate::prelude::BoxStdErr;

#[cfg(feature = "use-router-regex")]
use regex::Regex;

type Domain = SmolStr;
type Tag = SmolStr;

/// All fields are considered allow all if empty
#[derive(Default, Debug)]
pub struct Rule {
	pub inbound_inds: Vec<usize>,
	// src
	pub src_hosts: SourceContainer,
	pub src_ports: Vec<u16>,
	// dst
	pub dst_hosts: DestinationContainer,
	pub dst_ports: Vec<u16>,
	/// None means blocked
	pub outbound_ind: Option<usize>,
}

impl Rule {
	#[inline]
	#[must_use]
	pub fn contains_inbound(&self, inbound_ind: usize) -> bool {
		if self.inbound_inds.is_empty() {
			return true;
		}
		self.inbound_inds.contains(&inbound_ind)
	}

	/// Returns true if a source port is allowed
	#[inline]
	#[must_use]
	pub fn contains_src_port(&self, port: u16) -> bool {
		if self.src_ports.is_empty() {
			return true;
		}
		self.src_ports.is_empty() || self.src_ports.contains(&port)
	}

	/// Returns true if a destination port is allowed
	#[must_use]
	pub fn contains_dst_port(&self, port: u16) -> bool {
		if self.dst_ports.is_empty() {
			return true;
		}
		self.dst_ports.contains(&port)
	}
}

#[inline]
fn check_cidrs(ip: &IpAddr, cidrs: &[(Cidr, CidrMode)]) -> bool {
	cidrs.iter().any(|(cidr, mode)| {
		let matched = cidr.match_ip(ip);
		if matches!(mode, CidrMode::Reverse) {
			!matched
		} else {
			matched
		}
	})
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("unknown inbound tag '{0}'")]
	UnknownInboundTag(Tag),
	#[error("empty inbound tag")]
	EmptyInboundTag,
	#[error("unknown outbound tag '{0}'")]
	UnknownOutboundTag(Tag),
	#[error("empty outbound tag")]
	EmptyOutboundTag,
	#[error("invalid source ({0})")]
	InvalidSource(Cow<'static, str>),
	#[error("invalid destination ({0})")]
	InvalidDestination(Cow<'static, str>),
	#[cfg(feature = "use-router-regex")]
	#[error("regex error ({0})")]
	Regex(regex::Error),
	#[error("cannot open file '{file_path}' ({err})")]
	FileIo {
		file_path: String,
		err: std::io::Error,
	},
	#[cfg(feature = "use-protobuf")]
	#[error("protobuf error ({0})")]
	Protobuf(protobuf::error::ProtobufError),
}

#[derive(Default, Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "use_serde", serde(deny_unknown_fields))]
pub struct Plain {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub inbound_tags: Vec<Tag>,
	pub outbound_tag: Option<Tag>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub srcs: Vec<Source>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub src_ports: Vec<u16>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub dst: Vec<Destination>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub dst_ports: Vec<u16>,
}

impl Plain {
	/// Create a new [`Plain`].
	///
	/// `find_inbound` and `find_outbound` accepts a `&str` and
	/// return `Some(inbound/outbound index)` if tag is found.
	///
	/// # Errors
	///
	/// Returns:
	///
	/// [`Error::EmptyInboundTag`] or [`Error::EmptyOutboundTag`] if
	/// inbound tag or outbound tag is empty;
	///
	/// [`Error::UnknownInboundTag`] or [`Error::UnknownOutboundTag`] if
	/// inbound or outbound index cannot be found by
	/// `find_inbound` and `find_outbound`
	///
	/// And if feature `use-router-regex` or `use-protobuf` is enabled, an error
	/// will be returned if reading and parsing geosite/geoip failed.
	pub fn build(
		self,
		find_inbound: impl Fn(&str) -> Option<usize>,
		find_outbound: impl Fn(&str) -> Option<usize>,
	) -> Result<Rule, Error> {
		let mut inbound_inds = Vec::with_capacity(self.inbound_tags.len());
		for tag in self.inbound_tags {
			if tag.is_empty() {
				return Err(Error::EmptyInboundTag);
			}

			let ind = find_inbound(tag.as_str()).ok_or(Error::UnknownInboundTag(tag))?;
			inbound_inds.push(ind);
		}

		let outbound_ind = match self.outbound_tag {
			Some(tag) => {
				if tag == TAG_BLOCKED {
					None
				} else {
					if tag.is_empty() {
						return Err(Error::EmptyOutboundTag);
					}
					let ind = find_outbound(tag.as_str()).ok_or(Error::UnknownOutboundTag(tag))?;
					Some(ind)
				}
			}
			None => None,
		};

		let src_ports = self.src_ports;
		let src_hosts = {
			let mut src_hosts = SourceContainer::default();

			for src in self.srcs {
				match src {
					Source::Ip(ip) => {
						src_hosts.push_ip(ip);
					}
					Source::Cidr(cidr) => {
						src_hosts.push_cidr(cidr);
					}
				};
			}

			src_hosts
		};

		let dst_hosts = DestinationContainer::new(self.dst)?;

		let dst_ports = self.dst_ports;
		let rule = Rule {
			inbound_inds,
			src_hosts,
			src_ports,
			dst_hosts,
			dst_ports,
			outbound_ind,
		};

		Ok(rule)
	}
}

#[cfg(feature = "use-protobuf")]
fn get_protobuf_dat<'a, T>(data: &'a mut Option<T>, file_path: &str) -> Result<&'a T, Error>
where
	T: protobuf::Message,
{
	if let Some(geosites) = data {
		return Ok(geosites);
	}
	let mut file = std::fs::File::open(file_path).map_err(|err| Error::FileIo {
		file_path: file_path.into(),
		err,
	})?;
	// Always insert because `geosites` is None
	Ok(data.get_or_insert(T::parse_from_reader(&mut file).map_err(Error::Protobuf)?))
}

#[derive(Clone, Copy, Debug)]
pub enum CidrMode {
	Normal,
	Reverse,
}

#[derive(Default, Debug)]
pub struct DestinationContainer {
	pub ips: HashSet<IpAddr>,
	pub cidrs: Vec<(Cidr, CidrMode)>,
	pub domains: HashSet<Domain>,
	pub substrings: Vec<SmolStr>,
	pub full_domains: HashSet<Domain>,
	#[cfg(feature = "use-router-regex")]
	pub regex_domains: Vec<Regex>,
}

impl DestinationContainer {
	/// Create a new [`DestinationContainer`] from an iterator of [`Destination`].
	///
	/// # Errors
	///
	/// An [`Error`] will be returned when errors occurred during reading geosite/geoip file.
	///
	/// This will only happened when feature `use-router-regex` or `use-protobuf` is enabled.
	pub fn new(data: impl IntoIterator<Item = Destination>) -> Result<Self, Error> {
		let mut result = Self::default();
		#[cfg(feature = "use-protobuf")]
		let mut site_list = Option::<proto::GeoSiteList>::None;
		#[cfg(feature = "use-protobuf")]
		let mut ip_list = Option::<proto::GeoIPList>::None;
		for dst in data {
			match dst {
				Destination::Ip(ip) => {
					result.push_ip(ip);
				}
				Destination::Cidr(cidr) => {
					result.push_cidr(cidr, CidrMode::Normal);
				}
				Destination::Domain(name) => {
					result.push_domain(name);
				}
				Destination::FullDomain(name) => result.push_domain_full(name),
				Destination::DomainSubstring(substr) => result.push_domain_substr(substr),
				#[cfg(feature = "use-router-regex")]
				Destination::Regex(value) => result.push_domain_regex(value),
				#[cfg(feature = "use-protobuf")]
				Destination::GeoSite { file_path, tag } => {
					let geo_sites = get_protobuf_dat(&mut site_list, &file_path)?;
					for geo_site in geo_sites
						.entry
						.iter()
						.filter(|geosite| geosite.country_code.eq_ignore_ascii_case(&tag))
					{
						// Iterate every domain
						for domain in &geo_site.domain {
							result.push_proto_domain(domain)?;
						}
					}
				}
				#[cfg(feature = "use-protobuf")]
				Destination::GeoIp { file_path, tag } => {
					let geo_ips = get_protobuf_dat(&mut ip_list, &file_path)?;
					for geo_ip in geo_ips
						.entry
						.iter()
						.filter(|geoip| geoip.country_code == tag)
					{
						// Only take domains with specific tag
						let mode = if geo_ip.reverse_match {
							CidrMode::Reverse
						} else {
							CidrMode::Normal
						};
						// Iterate every CIDR
						for cidr in &geo_ip.cidr {
							result
								.push_proto_cidr(cidr, mode)
								.map_err(Error::InvalidDestination)?;
						}
					}
				}
			}
		}
		Ok(result)
	}

	// --------- IP rule ---------

	pub fn push_ip(&mut self, ip: IpAddr) {
		self.ips.insert(ip);
	}

	pub fn push_cidr(&mut self, cidr: Cidr, mode: CidrMode) {
		self.cidrs.push((cidr, mode));
	}

	// --------- Domain rule -----------

	/// Returns `true` if container did not have this value in present.
	///
	/// Returns `false` if container already had this value in present.
	#[allow(clippy::map_unwrap_or)]
	pub fn push_domain(&mut self, domain: impl Into<SmolStr> + std::borrow::Borrow<str>) -> bool {
		// Remove tailing '.'
		let name = domain
			.borrow()
			.strip_suffix('.')
			.map(SmolStr::from)
			.unwrap_or_else(|| domain.into());
		// Generate hash
		self.domains.insert(name)
	}

	pub fn push_domain_substr(&mut self, substr: impl Into<SmolStr>) {
		self.substrings.push(substr.into());
	}

	pub fn push_domain_full(&mut self, domain: impl Into<SmolStr>) {
		self.full_domains.insert(domain.into());
	}

	#[cfg(feature = "use-router-regex")]
	pub fn push_domain_regex(&mut self, value: Regex) {
		self.regex_domains.push(value);
	}

	#[cfg(feature = "use-router-regex")]
	#[inline]
	fn is_regex_domains_empty(&self) -> bool {
		self.regex_domains.is_empty()
	}

	#[cfg(feature = "use-router-regex")]
	fn contains_domain_regex(&self, name: &str) -> bool {
		for reg in &self.regex_domains {
			if reg.is_match(name) {
				return true;
			}
		}
		false
	}

	fn contains_domain_substring(&self, name: &str) -> bool {
		for substr in &self.substrings {
			if name.contains(substr.as_str()) {
				return true;
			}
		}
		false
	}

	fn is_empty(&self) -> bool {
		if !(self.ips.is_empty()
			&& self.cidrs.is_empty()
			&& self.domains.is_empty()
			&& self.full_domains.is_empty())
		{
			return false;
		}
		#[cfg(feature = "use-router-regex")]
		if !self.is_regex_domains_empty() {
			return false;
		}
		true
	}

	fn contains_ip(&self, ip: &IpAddr) -> bool {
		self.ips.contains(ip) || check_cidrs(ip, &self.cidrs)
	}

	/// Hopefully even faster version
	///
	/// Returns true if one of the domain name in `dsts` is the subdomain of `name`.
	fn contains_domain_normal(&self, mut name: &str) -> bool {
		loop {
			if self.domains.contains(name) {
				return true;
			}
			if let Some((_, subdomain)) = name.split_once('.') {
				name = subdomain;
			} else {
				break;
			}
		}
		false
	}

	fn contains_domain(&self, name: &str) -> bool {
		// Ignore tailing '.'
		let name = name.strip_suffix('.').unwrap_or(name);
		if self.contains_domain_normal(name)
			|| self.full_domains.contains(name)
			|| self.contains_domain_substring(name)
		{
			return true;
		}
		#[cfg(feature = "use-router-regex")]
		if self.contains_domain_regex(name) {
			return true;
		}
		false
	}

	/// Returns true if a destination address is allowed
	#[must_use]
	pub fn contains(&self, dest: &SocksDestination) -> bool {
		if self.is_empty() {
			return true;
		}
		match dest {
			SocksDestination::Ip(ip) => self.contains_ip(ip),
			SocksDestination::Name(name) => self.contains_domain(name),
		}
	}

	#[cfg(feature = "use-protobuf")]
	fn push_proto_domain(&mut self, domain: &proto::Domain) -> Result<(), Error> {
		match domain.field_type {
			proto::Domain_Type::Plain => {
				self.substrings.push(domain.value.as_str().into());
			}
			proto::Domain_Type::Regex => {
				#[cfg(feature = "use-router-regex")]
				{
					let re = Regex::new(&domain.value).map_err(Error::Regex)?;
					self.push_domain_regex(re);
				}
				#[cfg(not(feature = "use-router-regex"))]
				{
					return Err(Error::InvalidDestination(
						"regex support not enabled".into(),
					));
				}
			}
			proto::Domain_Type::Domain => {
				let val = idna::domain_to_ascii_strict(&domain.value)
					.map_err(|e| Error::InvalidDestination(e.to_string().into()))?;
				self.push_domain(val);
			}
			proto::Domain_Type::Full => {
				let val = idna::domain_to_ascii_strict(&domain.value)
					.map_err(|e| Error::InvalidDestination(e.to_string().into()))?;
				self.push_domain_full(val);
			}
		}
		Ok(())
	}

	#[cfg(feature = "use-protobuf")]
	fn push_proto_cidr(
		&mut self,
		proto_cidr: &proto::CIDR,
		mode: CidrMode,
	) -> Result<(), Cow<'static, str>> {
		use std::{cmp::Ordering, convert::TryFrom};

		let ip_slice = proto_cidr.ip.as_slice();

		// Prefix should be less than 128 in all situations.
		let prefix = u8::try_from(proto_cidr.prefix).unwrap();

		if let Ok(ip) = <[u8; 4]>::try_from(ip_slice) {
			// IPv4
			let max_bits = ip.len() * 8;

			match (prefix as usize).cmp(&max_bits) {
				Ordering::Less => {
					self.push_cidr(Cidr::from_ipv4(ip.into(), prefix), mode);
				}
				Ordering::Equal => {
					// Full match, use IP match for performance
					self.push_ip(ip.into());
				}
				Ordering::Greater => {
					// Prefix too large
					let msg = format!(
						"IP prefix for IPv4 can must within [0, {}], not {}",
						max_bits, prefix
					);
					return Err(msg.into());
				}
			}
		} else if let Ok(ip) = <[u8; 16]>::try_from(ip_slice) {
			// IPv6
			let max_bits = ip.len() * 8;

			match (prefix as usize).cmp(&max_bits) {
				Ordering::Less => {
					self.push_cidr(Cidr::from_ipv6(ip.into(), prefix), mode);
				}
				Ordering::Equal => {
					// Full match, use IP match for performance
					self.push_ip(ip.into());
				}
				Ordering::Greater => {
					// Prefix too large
					let msg = format!(
						"IP prefix for IPv6 must be within [0, {}], not {}",
						max_bits, prefix
					);
					return Err(msg.into());
				}
			}
		} else {
			return Err(format!(
				"IP can only be either 4 or 16 bytes, not {} bytes",
				ip_slice.len()
			)
			.into());
		};
		Ok(())
	}
}

#[derive(Debug, Default)]
pub struct SourceContainer {
	pub ips: HashSet<IpAddr>,
	pub cidrs: Vec<(Cidr, CidrMode)>,
}

impl SourceContainer {
	fn push_ip(&mut self, ip: IpAddr) {
		self.ips.insert(ip);
	}

	fn push_cidr(&mut self, cidr: Cidr) {
		self.cidrs.push((cidr, CidrMode::Normal));
	}

	/// Returns true if a source ip is allowed
	#[inline]
	pub fn contains(&self, src_ip: &IpAddr) -> bool {
		if self.ips.is_empty() && self.cidrs.is_empty() {
			return true;
		}
		self.ips.contains(src_ip) || check_cidrs(src_ip, self.cidrs.as_slice())
	}
}

#[derive(Debug)]
pub enum Source {
	Ip(IpAddr),
	Cidr(Cidr),
}

impl FromStr for Source {
	type Err = Error;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		if let Ok(ip) = IpAddr::from_str(value) {
			return Ok(Self::Ip(ip));
		} else if let Ok(cidr) = Cidr::from_str(value) {
			return Ok(Self::Cidr(cidr));
		}
		let msg = format!("'{}' is neither an IP nor a CIDR", value);
		Err(Error::InvalidSource(msg.into()))
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrefixType {
	Domain,
	DomainSubstring,
	FullDomain,
	#[cfg(feature = "use-router-regex")]
	Regex,
	#[cfg(feature = "use-protobuf")]
	GeoSite,
	#[cfg(feature = "use-protobuf")]
	GeoIp,
}

impl PrefixType {
	fn from_str(val: &str) -> Option<Self> {
		Some(match val {
			DOMAIN_PREFIX => Self::Domain,
			DOMAIN_FULL_PREFIX => Self::FullDomain,
			DOMAIN_SUBSTR_PREFIX => Self::DomainSubstring,
			#[cfg(feature = "use-router-regex")]
			DOMAIN_REGEXP_PREFIX => Self::Regex,
			#[cfg(feature = "use-protobuf")]
			GEOSITE_PREFIX => Self::GeoSite,
			#[cfg(feature = "use-protobuf")]
			GEOIP_PREFIX => Self::GeoIp,
			_ => return None,
		})
	}
}

#[derive(Debug)]
pub enum Destination {
	Ip(IpAddr),
	Cidr(Cidr),
	Domain(Domain),
	DomainSubstring(SmolStr),
	FullDomain(Domain),
	#[cfg(feature = "use-router-regex")]
	Regex(Regex),
	#[cfg(feature = "use-protobuf")]
	GeoSite {
		file_path: Cow<'static, str>,
		tag: Cow<'static, str>,
	},
	#[cfg(feature = "use-protobuf")]
	GeoIp {
		file_path: Cow<'static, str>,
		tag: Cow<'static, str>,
	},
}

impl FromStr for Destination {
	type Err = Error;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		// Check for IP
		if let Ok(ip) = IpAddr::from_str(value) {
			return Ok(Self::Ip(ip));
		}
		// Check for CIDR
		if let Ok(cidr) = Cidr::from_str(value) {
			return Ok(Self::Cidr(cidr));
		}

		// Checking format [prefix]:[name]
		if let Some((prefix, name)) = value.split_once(':') {
			let prefix_type = PrefixType::from_str(prefix).ok_or_else(|| {
				let msg = format!("unknown prefix '{}' in '{}'", prefix, value);
				Error::InvalidDestination(msg.into())
			})?;
			// Check for geosite or geoip or regex or substring
			#[allow(clippy::match_wildcard_for_single_variants)]
			match prefix_type {
				#[cfg(feature = "use-protobuf")]
				PrefixType::GeoSite => {
					let (file, tag) = name.split_once(':').ok_or_else(|| {
						Error::InvalidDestination(
							format!("invalid destination geosite '{}' in '{}'", name, value).into(),
						)
					})?;
					return Ok(Self::GeoSite {
						file_path: file.to_owned().into(),
						tag: tag.to_owned().into(),
					});
				}
				#[cfg(feature = "use-protobuf")]
				PrefixType::GeoIp => {
					let (file, tag) = name.split_once(':').ok_or_else(|| {
						Error::InvalidDestination(
							format!("invalid destination geoip '{}' in '{}'", name, value).into(),
						)
					})?;
					return Ok(Self::GeoIp {
						file_path: file.to_owned().into(),
						tag: tag.to_owned().into(),
					});
				}
				#[cfg(feature = "use-router-regex")]
				PrefixType::Regex => {
					return Ok(Self::Regex(Regex::new(name).map_err(Error::Regex)?));
				}
				PrefixType::DomainSubstring => return Ok(Self::DomainSubstring(name.into())),
				PrefixType::FullDomain => return Ok(Self::FullDomain(name.into())),
				_ => {}
			}
			// Check for domain
			let domain = idna::domain_to_ascii_strict(name).map_err(|e| {
				let msg = format!("invalid domain '{}' in '{}' ({})", name, value, e);
				Error::InvalidDestination(msg.into())
			})?;

			let res = if PrefixType::Domain == prefix_type {
				Self::Domain(domain.into())
			} else {
				let msg = format!("invalid domain '{}' in '{}'", domain, value);
				return Err(Error::InvalidDestination(msg.into()));
			};
			Ok(res)
		} else {
			let domain = idna::domain_to_ascii_strict(value).map_err(|e| {
				let msg = format!(
					"'{}' is not a valid IP address, CIDR, or domain name ({})",
					value, e
				);
				Error::InvalidDestination(msg.into())
			})?;
			Ok(Self::Domain(domain.into()))
		}
	}
}

#[cfg(feature = "use_serde")]
mod serde_internals {
	use super::{Destination, Source};
	use serde::Deserialize;
	use std::{
		fmt::{self, Formatter},
		str::FromStr,
	};

	impl<'de> Deserialize<'de> for Destination {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: serde::Deserializer<'de>,
		{
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Destination;

				fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
					formatter.write_str("an IP address or CIDR or domain name")
				}

				fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					Destination::from_str(value).map_err(serde::de::Error::custom)
				}
			}

			deserializer.deserialize_str(Visitor)
		}
	}

	impl<'de> Deserialize<'de> for Source {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: serde::Deserializer<'de>,
		{
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Source;

				fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
					formatter.write_str("an IP address or CIDR")
				}

				fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					Source::from_str(value).map_err(serde::de::Error::custom)
				}
			}

			deserializer.deserialize_str(Visitor)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_destination_from_str_domain() {
		let domain = "this.is-a.domain";
		let result = Destination::from_str(domain).unwrap();
		if let Destination::Domain(name) = &result {
			assert_eq!(name, domain)
		} else {
			panic!("Destination {:?} is not a domain", result);
		}
	}

	#[cfg(feature = "use-protobuf")]
	#[test]
	fn test_destination_from_str_geosite() {
		let expected_file = "/dir/file";
		let expected_tag = "tag";
		let val = format!("geosite:{}:{}", expected_file, expected_tag);
		let result = Destination::from_str(&val).unwrap();
		if let Destination::GeoSite {
			file_path: file,
			tag,
		} = &result
		{
			assert_eq!(expected_file, file);
			assert_eq!(expected_tag, tag);
		} else {
			panic!("Destination {:?} is not a geosite", result);
		}
	}

	#[cfg(feature = "use-protobuf")]
	#[test]
	fn test_destination_from_str_geoip() {
		let expected_file = "/dir/file";
		let expected_tag = "tag";
		let val = format!("geoip:{}:{}", expected_file, expected_tag);
		let result = Destination::from_str(&val).unwrap();
		if let Destination::GeoIp {
			file_path: file,
			tag,
		} = &result
		{
			assert_eq!(expected_file, file);
			assert_eq!(expected_tag, tag);
		} else {
			panic!("Destination {:?} is not a geosite", result);
		}
	}

	#[test]
	fn test_destination_from_str_ip() {
		let ip = "127.0.0.3";
		let result = Destination::from_str(ip).unwrap();
		if let Destination::Ip(res_ip) = &result {
			assert_eq!(res_ip, &IpAddr::from_str(ip).unwrap())
		} else {
			panic!("Destination {:?} is not an IP", result);
		}
	}

	#[test]
	fn test_destination_from_str_cidr() {
		let cidr = "127.0.0.3/24";
		let result = Destination::from_str(cidr).unwrap();
		if let Destination::Cidr(res_cidr) = &result {
			assert_eq!(res_cidr, &Cidr::from_str(cidr).unwrap())
		} else {
			panic!("Destination {:?} is not a CIDR", result);
		}
	}

	#[test]
	fn test_destination_from_str_full_domain() {
		let domain = "this.is-a.full.domain";
		let value = &format!("full:{}", domain);
		let result = Destination::from_str(value).unwrap();
		if let Destination::FullDomain(res_domain) = &result {
			assert_eq!(res_domain, domain)
		} else {
			panic!("Destination {:?} is not a FullDomain", result);
		}
	}

	#[test]
	fn test_destination_from_str_domain_substr() {
		let substr = "substr.domain";
		let value = &format!("substr:{}", substr);
		let result = Destination::from_str(value).unwrap();
		if let Destination::DomainSubstring(res_domain) = &result {
			assert_eq!(res_domain, substr)
		} else {
			panic!("Destination {:?} is not a domain substring", result);
		}
	}

	#[cfg(feature = "use-router-regex")]
	#[test]
	fn test_destination_from_str_regex() {
		let reg = "^this.is-a.regex$";
		let value = &format!("regexp:{}", reg);
		let result = Destination::from_str(value).unwrap();
		if let Destination::Regex(res_reg) = &result {
			assert_eq!(res_reg.as_str(), reg)
		} else {
			panic!("Destination {:?} is not a Regex", result);
		}
	}

	#[test]
	fn test_destination_container_contains_domain_normal() {
		let data = ["a.com", "b.a.com", "c.b.a.com", "bad.website"];
		let mut dc = DestinationContainer::default();
		for name in data {
			dc.push_domain(name);
		}
		for name in data {
			println!("try to find name: {} in {:?}", name, data);
			assert_eq!(dc.contains_domain_normal(name), true);
		}

		assert_eq!(dc.contains_domain_normal("a.com"), true);
		assert_eq!(dc.contains_domain_normal("b.a.com"), true);
		assert_eq!(dc.contains_domain_normal("c.b.a.com"), true);
		assert_eq!(dc.contains_domain_normal("d.c.b.a.com"), true);
		assert_eq!(dc.contains_domain_normal("e.d.c.b.a.com"), true);
	}

	#[test]
	fn test_destination_container_contains_domain_normal_failed() {
		let data = ["a.com", "b.a.com", "c.b.a.com", "bad.website"];
		let mut dc = DestinationContainer::default();
		for name in data {
			dc.push_domain(name);
		}
		for name in data {
			println!("try to find name: {} in {:?}", name, data);
			assert_eq!(dc.contains_domain_normal(name), true);
		}

		assert_eq!(dc.contains_domain_normal("com"), false);
		assert_eq!(dc.contains_domain_normal("a"), false);
		assert_eq!(dc.contains_domain_normal("b"), false);
	}

	#[test]
	fn test_destination_container_contain_domain() {
		let mut c = DestinationContainer::default();
		c.push_domain("normal.domain");

		// True
		assert!(c.contains_domain("this-is.normal.domain"));
		assert!(c.contains_domain("this-is-another.normal.domain"));
		// False
		assert!(!c.contains_domain("not-normal.domain"));
		assert!(!c.contains_domain("not-normal.domain"));
		assert!(!c.contains_domain("substr"));
		assert!(!c.contains_domain("full.domain"));
		assert!(!c.contains_domain("normal.domain.com"));
	}

	#[test]
	fn test_destination_container_contain_domain_full() {
		let mut c = DestinationContainer::default();
		c.push_domain_full("full.domain");

		// True
		assert!(c.contains_domain("full.domain"));
		// False
		assert!(!c.contains_domain("full.domain.com"));
		assert!(!c.contains_domain("not-full.domain"));
		assert!(!c.contains_domain("normal.domain"));
	}

	#[cfg(feature = "use-router-regex")]
	#[test]
	fn test_destination_container_contain_domain_regex() {
		let mut c = DestinationContainer::default();
		c.push_domain_regex(Regex::new(r"re.*-.*\.domain$").unwrap());

		// True
		assert!(c.contains_domain("re-.domain"));
		assert!(c.contains_domain("re-asdf.domain"));
		assert!(c.contains_domain("re-asdf-asdf.domain"));
		assert!(c.contains_domain("re.this-is-regex.domain"));
		// False
		assert!(!c.contains_domain("full.domain"));
		assert!(!c.contains_domain("normal.domain"));
		assert!(!c.contains_domain("e.this-is-regex.domain"));
	}

	#[test]
	fn test_destination_container_contain_domain_substr() {
		let mut c = DestinationContainer::default();
		c.push_domain_substr("substr");

		// True
		assert!(c.contains_domain("simple.substr"));
		assert!(c.contains_domain("substr.simple"));
		assert!(c.contains_domain("foosubstrbar"));
		// False
		assert!(!c.contains_domain("full.domain"));
		assert!(!c.contains_domain("normal.domain"));
		assert!(!c.contains_domain("foosub-strbar"));
	}

	#[cfg(feature = "use-router-regex")]
	#[test]
	fn test_destination_container_contain_domain_mixed() {
		let mut c = DestinationContainer::default();
		c.push_domain("normal.domain");
		c.push_domain_full("full.domain");
		c.push_domain_regex(Regex::new(r"re.*-.*\.domain$").unwrap());
		c.push_domain_substr("substr");

		// True
		assert!(c.contains_domain("this.is.normal.domain"));
		assert!(c.contains_domain("full.domain"));
		assert!(c.contains_domain("re.this-is-regex.domain"));
		assert!(c.contains_domain("asdfsubstr.asdf"));

		// False
		assert!(!c.contains_domain("not.full.domain"));
		assert!(!c.contains_domain("not.normal.domain.com"));
		assert!(!c.contains_domain("e.this-is-regex.domain"));
	}
}
