from algopy import (
    arc4,
    Bytes,
)
from puya_rsa import pkcs1_v15_verify


class RSATester(arc4.ARC4Contract):
    @arc4.abimethod()
    def pkcs1_v15_verify(
        self,
        msg_digest_info: Bytes,
        s: Bytes,
        n: Bytes,
        e: Bytes,
        barrett_reduction_factor: Bytes,
    ) -> None:
        pkcs1_v15_verify(msg_digest_info, s, n, e, barrett_reduction_factor)
