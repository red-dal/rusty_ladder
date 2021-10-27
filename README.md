# **Rusty-ladder**
This is a proxy client/server that helps you bypass the Great Fire Wall.

Currently supports: 
- HTTP in/outbound with basic username/password authentication
- SOCKS5 in/outbound with CONNECT command and username/password authentication
- Shadowsocks in/outbound
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

## **Setup**
Benchmark is run on raspberrypi 4.

```
ubuntu@ubuntu:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.3 LTS
Release:	20.04
Codename:	focal

ubuntu@ubuntu:~$ uname -r
5.4.0-1044-raspi
```

Layout:
 ```
 +--------------+                +----------------+
 |              |    tunnel      |                |
 |              +--------------->| Proxy Outbound |
 |              |                |                |
 |              |                +-------+--------+
 | SpeedTester  |                        |
 |              |                        | direct/Shadowsocks/VMess
 |              |                        v
 |              |               +-----------------+
 |              |    freedom    |                 |
 |              |<--------------+  Proxy Inbound  |
 +--------------+               |                 |
                                +-----------------+
 ```

First, upload: 

- rusty_ladder binary `target/aarch64-unknown-linux-gnu/release/rusty_ladder`
- rusty_ladder config files `speed_tester/configs/test_outbound.toml` and `speed_tester/configs/test_inbound.toml`
- v2ray config files `speed_tester/configs/v2ray_outbound.json` and `speed_tester/configs/v2ray_inbound.json` if you want to benchmark v2ray

to raspberry pi 4.

Second, run one inbound and one outbound for rusty_ladder/v2ray, for example:
```bash
tmux \
    new-session -d './rusty_ladder -c speed_tester/configs/test_inbound.toml' \; \
    split-window './rusty_ladder -c speed_tester/configs/test_outbound.toml' \; \
    attach
```

Then run speed_tester with config file `speed_tester/configs/conf.toml`:
```bash
cargo run -p speed_tester --release -- speed_tester/configs/conf.toml
```

## **Result**
|             name | elapsed_ms |  aver_speed |
| ---------------: | ---------: | ----------: |
|         tunnel-1 |       2541 | 100.74 MB/s |
|         tunnel-4 |       2522 | 101.47 MB/s |
|        tunnel-32 |       2964 |  86.34 MB/s |
|       tunnel-128 |       3539 |  72.33 MB/s |
|        ss-none-1 |       2655 |  96.41 MB/s |
|        ss-none-4 |       2815 |  90.92 MB/s |
|       ss-none-32 |       3395 |  75.40 MB/s |
|      ss-none-128 |       4246 |  60.29 MB/s |
|      ss-aes128-1 |       2674 |  95.73 MB/s |
|      ss-aes128-4 |       2561 |  99.96 MB/s |
|     ss-aes128-32 |       3361 |  76.16 MB/s |
|    ss-aes128-128 |       4378 |  58.46 MB/s |
|      ss-aes256-1 |       2671 |  95.82 MB/s |
|      ss-aes256-4 |       2822 |  90.69 MB/s |
|     ss-aes256-32 |       3375 |  75.84 MB/s |
|    ss-aes256-128 |       4341 |  58.97 MB/s |
|      ss-chacha-1 |       2548 | 100.45 MB/s |
|      ss-chacha-4 |       2528 | 101.23 MB/s |
|     ss-chacha-32 |       3660 |  69.94 MB/s |
|    ss-chacha-128 |       4490 |  57.01 MB/s |
|     vmess-none-1 |      11987 |  21.35 MB/s |
|     vmess-none-4 |       6391 |  40.05 MB/s |
|    vmess-none-32 |       6284 |  40.74 MB/s |
|   vmess-none-128 |       9167 |  27.92 MB/s |
|   vmess-aes128-1 |       2787 |  91.85 MB/s |
|   vmess-aes128-4 |       2889 |  88.59 MB/s |
|  vmess-aes128-32 |       4061 |  63.03 MB/s |
| vmess-aes128-128 |       4671 |  54.80 MB/s |
|   vmess-chacha-1 |       2681 |  95.47 MB/s |
|   vmess-chacha-4 |       2793 |  91.65 MB/s |
|  vmess-chacha-32 |       3467 |  73.84 MB/s |
| vmess-chacha-128 |       4516 |  56.68 MB/s |
|     vmess-zero-1 |       2501 | 102.33 MB/s |
|     vmess-zero-4 |       2768 |  92.47 MB/s |
|    vmess-zero-32 |       3385 |  75.61 MB/s |
|   vmess-zero-128 |       4526 |  56.55 MB/s |

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