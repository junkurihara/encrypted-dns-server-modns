# A forked version of encrypted-dns-server for &mu;ODNS

This repo is a forked version of [`encrypted-dns-server`](https://github.com/jedisct1/encrypted-dns-server). From the original version, this has been modified to employ a PoC implementation of **&mu;ODNS** that is a **multiple-relay-based anonymization protocol for DNS queries**.

&mu;ODNS has been designed to protect user privacy in DNS even if a relay(s) collude with a resolver(s), which cannot be solved in existing DNS anonymization protocols. For the detailed information of &mu;ODNS, please refer to our concept paper below:

> Jun Kurihara and Takeshi Kubo, ''Mutualized oblivious DNS (&mu;ODNS): Hiding a tree in the wild forest,'' Apr. 2021. [https://arxiv.org/abs/2104.13785](https://arxiv.org/abs/2104.13785)

The client proxy translating Do53 (traditional DNS) to PoC &mu;ODNS is available at [https://github.com/junkurihara/dnscrypt-proxy-modns](https://github.com/junkurihara/dnscrypt-proxy-modns). Publicly available relays for PoC &mu;ODNS are listed at [https://github.com/junkurihara/experimental-resolvers](https://github.com/junkurihara/experimental-resolvers), where these relays has been deployed with the code in this repo.

> **NOTE**: **At this time this solution should be considered suitable for research and experimentation.**

---

## How to configure for PoC &mu;ODNS

The PoC implementation of &mu;ODNS has been implemented by extending the Anonymized DNSCrypt protocol of DNSCrypt v2. Original `encrypted-dns-server` provides two functions: translating DNSCrypt v2 messages to Do53 messages to upstream resolvers, and relaying Anonymized DNSCrypt query messages to upstream `encrypted-dns-server` instances. In addition to these functions, `encrypted-dns-server-modns` provides a function to relay PoC &mu;ODNS query messages to relays or upstream resolvers. Thus in the configuration file, our `encrypted-dns-server-modns` only adds the option of `[anonymized_dns]` section in `encrypted-dns.toml` for PoC &mu;ODNS.

```:toml
#####################################################
### For privacy enhanced anonymized DNS (mu-ODNS) ###
#####################################################

# Maximum allowed relays after this server (default = 2).
# If it is n, then n subsequent hops except for the final destination (DNS server) are allowed.
# If it is 0, the next node after this server must be the target DNSCrypt v2 resolver.

max_subsequent_relays = 2
```

Please refer to the example file `example-encrypted-dns.toml`.

The option `max_subsequent_relays` is given to simply avoid the overload for incredibly large number of relays. Our implementation also has the loop avoidance for relaying.

If you want to see debug messages, please run with an environment variable `RUST_LOG=debug` as:

```:bash
$ cargo build
$ RUST_LOG=debug target/debug/encrypted-dns-modns --config=encrypted-dns.toml
```

**We are also planning to publish a docker image and Dockerfile of `encrypted-dns-server-modns`**.

---

## Modified parts from the original version

We only modified the following parts from the original repo of `encrypted-dns-server`:

- modified several `.rs` files in `src/`

- modified the example configuration file `example-encrypted-dns.toml'

> **NOTE**: This repo continuously tracks and reflects changes in the original repo of `encrypted-dns-server`. At this point, Github Actions (under `.github/`) do not work in this forked repo since their setting is not modified for the forked version yet. (We are planning to do that.)

---

Below is the original README.md.

---

# ![Encrypted DNS Server](logo.png)

![Github CI status](https://img.shields.io/github/workflow/status/jedisct1/encrypted-dns-server/Rust)
[![Gitter chat](https://badges.gitter.im/gitter.svg)](https://gitter.im/dnscrypt-operators/Lobby)

An easy to install, high-performance, zero maintenance proxy to run an encrypted DNS server.

![Dashboard](dashboard.png)

## Protocols

The proxy supports the following protocols:

- [DNSCrypt v2](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt)
- [Anonymized DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt)
- DNS-over-HTTP (DoH) forwarding

All of these can be served simultaneously, on the same port (usually port 443). The proxy automatically detects what protocol is being used by each client.

## Installation

### Option 1: precompiled binary for Linux

Precompiled tarballs and Debian packages for Linux/x86_64 [can be downloaded here](https://github.com/jedisct1/encrypted-dns-server/releases/latest).

Nothing else has to be installed. The server doesn't require any external dependencies.

In the Debian package, the example configuration file can be found in `/usr/share/doc/encrypted-dns/`.

### Option 2: compilation from source code

The proxy requires rust >= 1.0.39 or rust-nightly.

Rust can installed with:

```sh
curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain nightly
source $HOME/.cargo/env
```

Once rust is installed, the proxy can be compiled and installed as follows:

```sh
cargo install encrypted-dns
strip ~/.cargo/bin/encrypted-dns
```

The executable file will be copied to `~/.cargo/bin/encrypted-dns` by default.

### Options 3: Docker

[dnscrypt-server-docker](https://github.com/dnscrypt/dnscrypt-server-docker) is the most popular way to deploy an encrypted DNS server.

This Docker image that includes a caching DNS resolver, the encrypted DNS proxy, and scripts to automatically configure everything.

## Setup

The proxy requires a recursive DNS resolver, such as Knot, PowerDNS or Unbound.

That resolver can run locally and only respond to `127.0.0.1`. External resolvers such as Quad9 or Cloudflare DNS can also be used, but this may be less reliable due to rate limits.

In order to support DoH in addition to DNSCrypt, a DoH proxy must be running as well. [rust-doh](https://github.com/jedisct1/rust-doh) is the recommended DoH proxy server. DoH support is optional, as it is currently way more complicated to setup than DNSCrypt due to certificate management.

Make a copy of the `example-encrypted-dns.toml` configuration file named `encrypted-dns.toml`.

Then, review the [`encrypted-dns.toml`](https://raw.githubusercontent.com/jedisct1/encrypted-dns-server/master/example-encrypted-dns.toml) file. This is where all the parameters can be configured, including the IP addresses to listen to.

You should probably at least change the `listen_addresses` and `provider_name` settings.

Start the proxy. It will automatically create a new provider key pair if there isn't any.

The DNS stamps are printed. They can be used directly with [`dnscrypt-proxy`](https://github.com/dnscrypt/dnscrypt-proxy/).

There is nothing else to do. Certificates are automatically generated and rotated.

## Migrating from dnscrypt-wrapper

If you are currently running an encrypted DNS server using [`dnscrypt-wrapper`](https://github.com/cofyc/dnscrypt-wrapper), moving to the new proxy is simple:

- Double check that the provider name in `encrypted-dns.toml` matches the one you previously configured. If you forgot it, it can be recovered [from its DNS stamp](https://dnscrypt.info/stamps/).
- Run `encrypted-dns --import-from-dnscrypt-wrapper secret.key`, with `secret.key` being the file with the `dnscrypt-wrapper` provider secret key.

Done. Your server is now running the new proxy.

## Built-in DNS cache

The proxy includes a key cache, as well as a DNS cache to significantly reduce the load on upstream servers.

In addition, if a server is slow or unresponsive, expired cached queries will be returned, ensuring that popular domain names always keep being served.

## State file

The proxy creates and updates a file named `encrypted-dns.state` by default. That file contains the provider secret key, as well as certificates and encryption keys.

Do not delete the file, unless you want to change parameters (such as the provider name), and keep it secret, or the keys will be lost.

Putting it in a directory that is only readable by the super-user is not a bad idea.

## Filtering

Domains can be filtered directly by the proxy, see the `[filtering]` section of the configuration file.

## Access control

Access control can be enabled in the `[access_control]` section and configured with the `query_meta` configuration value of `dnscrypt-proxy`.

## Prometheus metrics

Prometheus metrics can optionally be enabled in order to monitor performance, cache efficiency, and more.

## Anonymized DNSCrypt

Enabling Anonymized DNSCrypt allows the server to be used as an encrypted DNS relay.
