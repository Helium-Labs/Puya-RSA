# Puya RSA

Algorand Puya RSA RFC8017 RSASSA-PKCS1-V1.5-VERIFY function implementation. Intended to allow on-chain verification of RSA signatures seen in practice (e.g. JWT signatures), compliant with the Public Key Cryptography Standard v1.5. See [RFC Section 8.2.2](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2).

## Features

- Supports up to `1024 bytes` (8192 bits) long modulus
- RSASSA-PKCS1-V1.5-VERIFY function implementation

## Install

Puya RSA is available on PyPI:

```sh
pip install puya-rsa
```

## Usage

All inputs to math functions are assumed to be big-endian encoded numbers unless explicitly stated otherwise.

```python
from puya_rsa import (
    pkcs1_v15_verify
)
# ... pkcs1_v15_verify(msg_digest_info, signature, public_modulus, exponent, barrett_reduction_factor)
```

The `pkcs1_v15_verify` function arguments are as follows:
- `msg_digest_info` is a message digest with an identifier of the hashing function prepended 
- `signature` is the signature used to sign the message
- `public_modulus` is the public RSA key (modulus)
- `exponent` is the exponent used to generate the RSA key (typically `2**16`)
- `barrett_reduction_factor` is a precomputed factor according to the Barrett Reduction algorithm, which depends on the public key modulus. This must be calculated on-chain and proven (e.g. in contract state) to be trustless, otherwise it would act as a magic number. See `Puya BigNumber`.

## Develop

This module uses `poetry` as the package manager and Python environment manager. Please see [How to Build and Publish Python Packages With Poetry](https://www.freecodecamp.org/news/how-to-build-and-publish-python-packages-with-poetry/).

### Test

```
poetry run pytest -v
```

## License & Contribution

Contributions and additions are welcomed. Please respect the terms of the [GNU GPL v3 license](./LICENSE). Attribution for the author _Winton Nathan-Roberts_ is required. No warranties or liabilities per the license. It is not yet officially production ready, although it is thoroughly tested.
