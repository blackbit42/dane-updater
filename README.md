# DNS updater for DANE

Purpose of this program is to maintain a set of
[DANE](https://datatracker.ietf.org/doc/html/rfc6698) (TLSA) resource records
in DNS via [RFC2136](https://datatracker.ietf.org/doc/html/rfc2136) dynamic DNS
updates, on basis of supplied TLS certificate private keys.

Currently, only DANE EE (3 1 1) is supported.

`dane-updater` expects zero one or many .pem files that contain the public key
besides the private key part, the latter of which is not used by dane-updater.
If more than one key is supplied, a rollover scheme is achieved.

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

```
dane-updater \
    --key-file privkey.pem \
    --key-file privkey.roll.pem \
    --domain-name foo.example.org \
    --zone example.org \
    --rfc2136-nameserver 192.0.2.1:53 \
    --ports 25 \
    --tsig-key tsig.key
```

## Missing features

Not yet clear if we want to support these.

- [ ] RSA key support
- [ ] Support for DANE types differing from "3 1 1"

