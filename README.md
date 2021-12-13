# **Rusty-ladder**
This is a proxy client/server that helps you bypass the Great Fire Wall.

Currently supports: 
- HTTP in/outbound with basic username/password authentication
- SOCKS5 in/outbound with CONNECT command and username/password authentication (TCP only)
- Shadowsocks in/outbound (TCP only)
- VMess in/outbound
- Trojan outbound
- TLS/WS/WSS transport layer for in/outbounds

# **Requirements**
- OpenSSL (required for crytography/TLS)

# **How to use**
Create a configuration file in TOML v0.5 format.
Detailed explanation can be found in `rusty_ladder/examples/example.toml`.

For example, a simple SOCKS5 proxy server:

```toml
[log]
level = "info"

[[inbounds]]
addr = "0.0.0.0:40080"
protocol = "socks5"

[[outbounds]]
protocol = "freedom"

```

More configuration examples can be found in `rusty_ladder/examples/`.

Start proxy with

```bash
./rusty_ladder -c config.toml
```

If built with feature `use-tui` enabled, run with `--tui` to enable the TUI.

```bash
./rusty_ladder -c config.toml --tui
```


# **How to build**
## **Use cargo to build**
Build with cargo by running:
```bash
RUSTFLAGS='-C link-arg=-s' cargo build --release
```
`RUSTFLAGS='-C link-arg=-s'` is used to minimize the size of binary.

The executable `rusty_ladder` can be found in `./target/release/`.

## **Use cargo cross to build**
To build with [cross](https://github.com/rust-embedded/cross) and package the result, run:
```bash
bash ./build/build.sh
```
All results will be in `./build/output/`.

For linux target, OpenSSL is used by default as crypto/TLS library, so custom docker images `./build/Dockerfile.*` are needed.
For windows target, ring/rustls is used as crypto/TLS library.

To remove all docker images and output, run:
```bash
bash ./build/clean_up.sh
```

## **OpenSSL**
OpenSSL is needed for cryptography/TLS for some proxies/transport by default.
You will need both libraries and headers to build this crate. 

For example on debian/ubuntu, you will need 
```bash
apt install libssl-dev
```

If you want to cross compile to other platform with cargo,
you may need to download the source code of OpenSSL and cross compile it manually first,
then specify the location of OpenSSL by setting environment
variables `OPENSSL_INCLUDE_DIR`, `OPENSSL_LIB_DIR` and `OPENSSL_DIR` and build like this: 
```bash
export OPENSSL_DIR="..."
export OPENSSL_LIB_DIR=$OPENSSL_DIR
export OPENSSL_INCLUDE_DIR=$OPENSSL_DIR/include 

cargo build --target aarch64-unknown-linux-gnu 
```

See more at https://docs.rs/openssl/0.10.36/openssl/#manual

## **Feature Flags**
DNS:
- `local-dns`

    Enable local DNS proxy.

- `local-dns-over-openssl`

    Enable local DNS proxy and remote DNS over TLS using OpenSSL.

- `local-dns-over-rustls`

    Enable local DNS proxy and remote DNS over TLS using rustls.
    You can only use either `-openssl` or `-rustls`.

API:
- `use-tui` (*Enabled by default*)

    Enable TUI. 

- `use-webapi`

    Enable web API


Router: 
- `use-protobuf`

    Enable support for v2ray geosite/geoip data file.

- `use-router-regex` (*Enabled by default*)

    Enable regex support for router.

Transport: 
- `all-transports-openssl` (*Enabled by default*)

    Enable all transport with OpenSSL as TLS library.
    You can only use either `-openssl` or `-rustls`/`-ring`.

- `all-transports-rustls`

    Enable all transports with rustls as TLS library.

- `ws-transport-rustls` | `ws-transport-openssl`

    Enable websocket transport layer.

- `tls-transport-rustls` | `tls-transport-openssl`

    Enable TLS transport layer.

- `h2-transport-rustls` | `h2-transport-openssl`

    Enable h2 transport layer.

Proxy: 
- `all-proxies-openssl` (*Enabled by default*)

    Enable all proxies with OpenSSL as crypto library.
    You can only use either `-openssl` or `-rustls`/`-ring`.

- `all-proxies-ring`

    Enable all proxies with ring/RustCrypto as crypto library.
    This enabled for windows target in `build/build.sh` instead of OpenSSL.

- `use-udp` (*Enabled by default*)

    Enable UDP support for some proxies. 
    Currently only Shadowsocks outbound, VMess in/outbound support UDP.

- `chain-outbound`

    Enable chain proxy outbound.

- `trojan-outbound`

    Enable Trojan proxy outbound.

- `socks5-inbound`

    Enable SOCKS5 proxy inbound.

- `socks5-outbound`

    Enable SOCKS5 proxy outbound.

- `socks5`

    Enable both `socks5-inbound` and `socks5-outbound`.

- `http-inbound`

    Enable HTTP proxy inbound.

- `http-outbound`

    Enable HTTP proxy outbound.

- `http-proxy`

    Enable both `http-inbound` and `http-outbound`.

- `shadowsocks-inbound-ring` | `shadowsocks-inbound-openssl`

    Enable Shadowsocks proxy inbound.

- `shadowsocks-outbound-ring` | `shadowsocks-outbound-openssl`

    Enable Shadowsocks proxy outbound.

- `shadowsocks-ring` | `shadowsocks-openssl`

    Enable both Shadowsocks inbound and outbound.

- `vmess-inbound-ring` | `vmess-inbound-openssl`

    Enable VMess proxy inbound.

- `vmess-outbound-ring` | `vmess-outbound-openssl`

    Enable VMess proxy outbound.

- `vmess-ring` | `vmess-openssl`

    Enable both VMess inbound and outbound.


OpenSSL is needed if any feature with `-openssl` is enabled.

# **Tests**
Run unit tests and integration tests with
```bash
export RUST_BACKTRACE=1
# Specify log level.
export RUST_LOG=trace
# V2RAY_PATH must be specified to run integration tests.
export V2RAY_PATH=../v2ray/v2ray
cargo test --workspace
```

# **Benchmark**
See more in speed_tester/README.md

# **Credits**
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [OpenSSL](https://www.openssl.org/)
- [sfackler/rust-openssl](https://github.com/sfackler/rust-openssl)

# **License**
```
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
```