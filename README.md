# DNS updater for DANE

Purpose of this program is to maintain a set of
[DANE](https://datatracker.ietf.org/doc/html/rfc6698) (TLSA) resource records
in DNS via [RFC2136](https://datatracker.ietf.org/doc/html/rfc2136) dynamic DNS
updates, on basis of supplied TLS certificate private keys.

Currently, only DANE EE (3 1 1) is supported.

`dane-updater` expects zero one or many .pem files that contain the public key
besides the private key part, the latter of which is not used by dane-updater.
If more than one key is supplied, a rollover scheme is achieved.

## Building

Assuming an installed [Rust toolchain](https://rustup.rs/), you can
build like this:

```sh
cargo build --release
```

You'll find the executable in `target/release/dane-updater`; just copy
it to an appropriate place. If you are targeting Linux, you can
instead build a statically-linked executable if desired:

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

In this case, you'll find the executable at
`./target/x86_64-unknown-linux-musl/release/dane-updater`.

## TSIG key file format

The file contains 3 parts, seperated by colons.
* Name
* Algorithm
* Key (base64)

Example:
```
sec1_key:hmac-md5:6KM6qiKfwfEpamEq72HQdA==
```

## Example usage

### Without config file

```sh
dane-updater \
    --key-file privkey.pem \
    --key-file privkey.roll.pem \
    --zone example.org \
    --rfc2136-nameserver 192.0.2.1:53 \
    --ports 25 \
    --tsig-key tsig.key \
    foo.example.org
```

### With config file

See also [`example-config.toml`](./example-config.toml).

```sh
dane-updater --config example-config.toml \
    --key-file privkey.pem \
    --key-file privkey.roll.pem \
    foo.example.org
```

## Missing features

Not yet clear if we want to support these.

- [ ] RSA key support
- [ ] Support for DANE types differing from "3 1 1"

