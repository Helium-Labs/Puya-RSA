from typing import List
import re
from enum import Enum


class SHAAlgorithm(Enum):
    SHA1 = "SHA1"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    MD5 = "MD5"
    SHA512_224 = "SHA512_224"
    SHA512_256 = "SHA512_256"


# DER encoding T of the DigestInfo. See: https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
_HASH_DER_OID = {
    SHAAlgorithm.MD5: bytes.fromhex("3020300C06082A864886F70D020505000410"),
    SHAAlgorithm.SHA1: bytes.fromhex("3021300906052B0E03021A05000414"),
    SHAAlgorithm.SHA224: bytes.fromhex("302D300D06096086480165030402040500041C"),
    SHAAlgorithm.SHA256: bytes.fromhex("3031300D060960864801650304020105000420"),
    SHAAlgorithm.SHA384: bytes.fromhex("3041300D060960864801650304020205000430"),
    SHAAlgorithm.SHA512: bytes.fromhex("3051300D060960864801650304020305000440"),
    SHAAlgorithm.SHA512_224: bytes.fromhex("302D300D06096086480165030402050500041C"),
    SHAAlgorithm.SHA512_256: bytes.fromhex("3031300D060960864801650304020605000420"),
}


def get_der_encoded_hash_oid(algorithm: SHAAlgorithm):
    return _HASH_DER_OID[algorithm]


class RSAVerifyTestVector:
    mod_bitlength: int
    mod: bytes
    sha_alg: SHAAlgorithm
    exp: bytes
    msg: bytes
    sig: bytes
    is_valid_sig: bool

    def __str__(self) -> str:
        formatted_attrs = []
        for key, value in vars(self).items():
            if isinstance(value, bytes):
                formatted_value = value.hex()
            else:
                formatted_value = value
            formatted_attrs.append(f"  {key}: {formatted_value}")

        return f"RSAVerifyTestVector(\n" + "\n".join(formatted_attrs) + "\n)"


def pad_hex_string(hex_str: str) -> str:
    """Pad a hexadecimal string with a leading '0' if its length is odd. Should fail if padding is needed (invalid hex)."""
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return hex_str


def from_hex(hex_str: str) -> str:
    return bytes.fromhex(pad_hex_string(hex_str))


def get_rsa_verify_test_vectors(file_path: str) -> List[RSAVerifyTestVector]:
    # Regular expressions to match different parts of the test vector
    mod_bitlength_re = re.compile(r"\[mod = (\d+)]")
    sha_alg_re = re.compile(r"SHAAlg = (\w+)")
    e_re = re.compile(r"e = ([0-9a-fA-F]+)")
    msg_re = re.compile(r"Msg = ([0-9a-fA-F]+)")
    sig_re = re.compile(r"S = ([0-9a-fA-F]+)")
    mod_re = re.compile(r"n = ([0-9a-fA-F]+)")
    result_re = re.compile(r"Result = ([PF])")

    test_vectors: List[RSAVerifyTestVector] = []
    current_vector: RSAVerifyTestVector = RSAVerifyTestVector()
    with open(file_path, "r") as file:
        current_mod_bitlength = None
        current_mod = None
        for line in file:
            # Check for modulus
            mod_match = mod_re.match(line)
            if mod_match:
                current_mod = from_hex(mod_match.group(1))
                continue

            # Check for modulus size
            mod_bitlength_match = mod_bitlength_re.match(line)
            if mod_bitlength_match:
                current_mod_bitlength = int(mod_bitlength_match.group(1))
                continue

            # Check for SHA Algorithm
            sha_alg_match = sha_alg_re.match(line)
            if sha_alg_match:
                current_vector.sha_alg = SHAAlgorithm[sha_alg_match.group(1)]
                continue

            # Check for exponent (e)
            e_match = e_re.match(line)
            if e_match:
                current_vector.exp = from_hex(e_match.group(1))
                continue

            # Check for message (Msg)
            msg_match = msg_re.match(line)
            if msg_match:
                current_vector.msg = from_hex(msg_match.group(1))
                continue

            # Check for signature (S)
            sig_match = sig_re.match(line)
            if sig_match:
                current_vector.sig = from_hex(sig_match.group(1))
                continue

            # Check for result (Result)
            result_match = result_re.match(line)
            if result_match:
                current_vector.is_valid_sig = result_match.group(1) == "P"
                current_vector.mod_bitlength = current_mod_bitlength
                current_vector.mod = current_mod
                assert len(current_mod) == current_mod_bitlength // 8
                test_vectors.append(current_vector)
                current_vector: RSAVerifyTestVector = RSAVerifyTestVector()
    return test_vectors
