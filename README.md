# **Rusty-ladder**
A proxy client/server for bypassing GFW censorship.

This is a hobby project and not for production.

Currently supports: 
- HTTP in/outbound with basic username/password authentication
- SOCKS5 in/outbound with CONNECT command and username/password authentication (TCP only)
- Shadowsocks in/outbound (TCP only)
- VMess in/outbound
- Trojan outbound
- TLS/WS/WSS transport layer for in/outbounds

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
cargo build --release
```
Binary will be in `./target/release/`.

## **Use cargo cross to build**
[cross](https://github.com/rust-embedded/cross) is used to build for different platforms.
```bash
cross build --release --no-default-features --features "$FEATURES" --target $target
```

## **Feature Flags**
Commandline:
- `parse-url` (*Enabled by default*)

    Enable commandline option that parse URL:
    `--inbound`, `--outbound`, `--log`, `--block`

- `parse-config` (*Enabled by default*)

    Enable commandline option that parse JSON or TOML: `--config`

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
- `all-transports-rustls` (*Enabled by default*)

    Enable all transports with rustls as TLS library.

- `all-transports-openssl`

    Enable all transport with OpenSSL as TLS library.
    You can only use either `-openssl` or `-rustls`/`-ring`.
    
    Requires OpenSSL.

- `ws-transport-rustls` | `ws-transport-openssl`

    Enable websocket transport layer.

- `tls-transport-rustls` | `tls-transport-openssl`

    Enable TLS transport layer.

- `h2-transport-rustls` | `h2-transport-openssl`

    Enable h2 transport layer.

Proxy: 
- `all-proxies-ring` (*Enabled by default*)

    Enable all proxies with ring/RustCrypto as crypto library.

- `all-proxies-openssl` 

    Enable all proxies with OpenSSL as crypto library.

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

# **Credits**
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [OpenSSL](https://www.openssl.org/)
- [sfackler/rust-openssl](https://github.com/sfackler/rust-openssl)
- [rustls](https://github.com/rustls/rustls)

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
