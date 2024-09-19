from algopy import Bytes
from puya_rsa import pkcs1_v15_verify, pkcs1_v15_verify_without_barrett_validation
from .util import (
    RSAVerifyTestVector,
    get_rsa_verify_test_vectors,
    SHAAlgorithm,
    get_der_encoded_hash_oid,
)
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Math.Numbers import Integer
from Crypto.Hash import (
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
)
from .build import build

RSA_VERIFY_PKCS_15_FIPS_TESTVECTORS_PATH = (
    "./tests/FIPS 186-4 RSA Test Vectors/SigVer15_186-3.rsp"
)


def assert_rs256_verify(plaintext_sha256hash: bytes, sig: bytes, public_mod: bytes):
    pass


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def hash_of_msg(tv: RSAVerifyTestVector):
    match tv.sha_alg:
        case SHAAlgorithm.SHA1:
            return SHA1.new(tv.msg)
        case SHAAlgorithm.SHA224:
            return SHA224.new(tv.msg)
        case SHAAlgorithm.SHA256:
            return SHA256.new(tv.msg)
        case SHAAlgorithm.SHA384:
            return SHA384.new(tv.msg)
        case SHAAlgorithm.SHA512:
            return SHA512.new(tv.msg)
        case _:
            raise ValueError(f"Unsupported SHA algorithm: {tv.sha_alg}")


def is_valid_sig_with_pycryptodome(tv: RSAVerifyTestVector) -> bool:
    rsa_key = RsaKey(n=Integer(bytes_to_int(tv.mod)), e=Integer(bytes_to_int(tv.exp)))
    verifier = pkcs1_15.new(rsa_key)
    try:
        verifier.verify(hash_of_msg(tv), tv.sig)
        return True
    except Exception:
        return False


def get_barrett_precomputed_factor(mod: bytes) -> bytes:
    mod_int: int = int.from_bytes(mod)
    shift: int = len(mod) * 2 * 8
    factor: int = 2**shift // mod_int
    factor_bytes: bytes = factor.to_bytes((factor.bit_length() + 7) // 8)
    return factor_bytes


def get_msg_digest_info(tv: RSAVerifyTestVector) -> bytes:
    hash = hash_of_msg(tv)
    oid_bytes: bytes = get_der_encoded_hash_oid(tv.sha_alg)
    hash_bytes: bytes = hash.digest()
    return oid_bytes + hash_bytes


def assert_pkcs1_v15_verify_tv(tv: RSAVerifyTestVector):
    msg_digest_info = get_msg_digest_info(tv)
    precomputed_barrett_factor: bytes = get_barrett_precomputed_factor(tv.mod)

    try:
        pkcs1_v15_verify(
            Bytes(msg_digest_info),
            Bytes(tv.sig),
            Bytes(tv.mod),
            Bytes(tv.exp),
            Bytes(precomputed_barrett_factor),
        )
        assert tv.is_valid_sig == True, "TV must be a valid sig"
    except Exception as e:
        assert tv.is_valid_sig == False, f"TV must be an invalid sig:\n{e}"
        return False


def assert_pkcs1_v15_verify_without_barrett_validation_tv(tv: RSAVerifyTestVector):
    msg_digest_info = get_msg_digest_info(tv)
    precomputed_barrett_factor: bytes = get_barrett_precomputed_factor(tv.mod)

    try:
        pkcs1_v15_verify_without_barrett_validation(
            Bytes(msg_digest_info),
            Bytes(tv.sig),
            Bytes(tv.mod),
            Bytes(tv.exp),
            Bytes(precomputed_barrett_factor),
        )
        assert tv.is_valid_sig == True, "TV must be a valid sig"
    except Exception as e:
        assert tv.is_valid_sig == False, f"TV must be an invalid sig:\n{e}"
        return False


def test_all():
    # Test that it compiles
    build("./tests", "tester_contract")
    # Test that operators are accurate
    test_vectors = get_rsa_verify_test_vectors(RSA_VERIFY_PKCS_15_FIPS_TESTVECTORS_PATH)
    for tv in test_vectors:
        assert (
            is_valid_sig_with_pycryptodome(tv) == tv.is_valid_sig
        ), "Pycryptodome Verify should correctly verify"

        assert_pkcs1_v15_verify_tv(tv)
        assert_pkcs1_v15_verify_without_barrett_validation_tv(tv)
