use std::str::FromStr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ladder_lib::{
	protocol::{socks_addr::DomainName, SocksDestination},
	router::{Destination, DestinationContainer},
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

fn generate_data(size: usize, seed: u64) -> DestinationContainer {
	let mut dc = DestinationContainer::default();

	let rng = &mut StdRng::seed_from_u64(seed);
	let mut part = *b"abcdef";
	let part = &mut part;
	let mut domain = String::new();
	// 100 domains in the container
	for _ in 0..size {
		loop {
			// Each domain name has 3 levels
			domain.clear();
			for pn in 0..3 {
				part.shuffle(rng);
				if pn > 0 {
					domain.push('.');
				}
				domain.push_str(std::str::from_utf8(part).unwrap());
			}

			// Try until domain is unique
			if dc.push_domain(DomainName::from_str(&domain).unwrap()) {
				break;
			}
		}
	}
	// Make sure the data is correct
	assert_eq!(dc.domains.len(), size);
	assert!(!dc.contains(&SocksDestination::new_domain("this.is.invalid.domain").unwrap()));
	dc
}

pub fn criterion_benchmark(c: &mut Criterion) {
	let host = &SocksDestination::new_domain("this.is.invalid.domain").unwrap();
	{
		let dc = generate_data(10, 0);
		c.bench_function("destination_container_10", |b| {
			b.iter(|| {
				let _res = dc.contains(black_box(host));
			})
		});
	}
	{
		let dc = generate_data(10_000, 0);
		c.bench_function("destination_container_10k", |b| {
			b.iter(|| {
				let _res = dc.contains(black_box(host));
			})
		});
	}
	{
		let dc = generate_data(1_000_000, 0);
		c.bench_function("destination_container_1m", |b| {
			b.iter(|| {
				let _res = dc.contains(black_box(host));
			})
		});
	}
	{
		c.bench_function("destination_from_str", |b| {
			b.iter(|| {
				let _res = Destination::from_str("hello.world");
			})
		});
	}
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
