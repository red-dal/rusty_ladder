
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