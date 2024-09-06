from algopy import arc4, Bytes, subroutine, BigUInt, UInt64
from algopy.op import bzero

from puya_bignumber import less_than, modexp_barrett_reduce, equal

__all__ = [
    "pkcs1_v15_verify",
]


@subroutine
def _RSAVP1(s: Bytes, n: Bytes, e: Bytes, barrett_reduction_factor: Bytes) -> Bytes:
    assert less_than(s, n), "signature representative out of range"
    return modexp_barrett_reduce(s, e, n, barrett_reduction_factor)


@subroutine
def _I2OSP(m: Bytes, k: UInt64) -> Bytes:
    assert m.length == k, "m too large"
    return m


@subroutine
def _EMSA_PKCS1_v15(msg_digest_info: Bytes, k: UInt64) -> Bytes:
    # msg_digest_info = Hash Function Identifier || digest
    assert k >= msg_digest_info.length + 11, "intended encoded message length too short"
    PS = ~bzero(k - msg_digest_info.length - 3)
    return b"\x00\x01" + PS + b"\x00" + msg_digest_info


# RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S) implementation. See https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2.
@subroutine
def pkcs1_v15_verify(
    msg_digest_info: Bytes,
    s: Bytes,
    n: Bytes,
    e: Bytes,
    barrett_reduction_factor: Bytes,
) -> Bytes:
    k: UInt64 = n.length
    assert s.length == k, "signature must have the same length as the modulus"
    m: Bytes = _RSAVP1(s, n, e, barrett_reduction_factor)
    em: Bytes = _I2OSP(m, k)
    em_prime: Bytes = _EMSA_PKCS1_v15(msg_digest_info, k)
    assert equal(em, em_prime), "em must match em_prime for signature to be valid"
