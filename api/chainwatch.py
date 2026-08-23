#!/usr/bin/env python3
"""
Receive-address derivation from an extended public key.

This is the piece that lets an operator take Bitcoin with no merchant account,
no custodian, no BTCPay instance and no chain data on disk: they paste the
public half of their own wallet, and the control plane derives a fresh receive
address per invoice. Funds go straight to their wallet. Nobody else ever holds
them, and nothing here can spend them — an extended *public* key cannot sign.

Everything below is pure standard library. No secp256k1 package, no bech32
package, nothing to vendor or audit at install time. That is a deliberate
trade: a hundred lines of well-specified arithmetic against a dependency on
somebody else's C extension in the path that receives money.

The obvious risk with hand-written derivation is that a subtle bug sends
customers to addresses the operator cannot spend — money destroyed, silently,
with the system reporting success. That is why every function here is checked
against the official test vectors from BIP32, BIP84 and BIP173 in the test
suite rather than against addresses this file generated itself. A test that
compares the code to its own output proves nothing.
"""

from __future__ import annotations

import hashlib
import hmac

# --- secp256k1 --------------------------------------------------------------
# y^2 = x^3 + 7 over F_p. Only what public derivation needs: point addition,
# scalar multiplication by the generator, and compressed serialization.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv(a: int, m: int = P) -> int:
    return pow(a, m - 2, m)


def _point_add(a, b):
    """Add two points on secp256k1. None is the point at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _point_mul(k: int, point=G):
    """Double-and-add. Not constant time — it only ever touches public data."""
    result, addend = None, point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _serialize(point) -> bytes:
    x, y = point
    return (b"\x03" if y & 1 else b"\x02") + x.to_bytes(32, "big")


def _deserialize(data: bytes):
    """Decompress a 33-byte SEC point: recover y from x."""
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("not a compressed secp256k1 point")
    x = int.from_bytes(data[1:], "big")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (data[0] & 1):
        y = P - y
    if (y * y - (pow(x, 3, P) + 7)) % P != 0:
        raise ValueError("point is not on the curve")
    return (x, y)


# --- base58check ------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode_check(s: str) -> bytes:
    num = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58 character {ch!r}")
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        raise ValueError("too short for base58check")
    body, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        raise ValueError("base58 checksum mismatch")
    return body


# --- bech32 / bech32m (BIP173, BIP350) --------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid value for base conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise ValueError("invalid padding in base conversion")
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """A segwit address. witver 0 uses bech32; 1+ uses bech32m."""
    data = [witver] + _convertbits(witprog, 8, 5)
    const = 1 if witver == 0 else 0x2BC830A3
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


# --- BIP32 public derivation ------------------------------------------------

class ExtendedPubkey:
    """
    An account-level extended public key (xpub / ypub / zpub / tpub / vpub).

    Only unhardened public derivation is possible from one of these, which is
    exactly what a receive chain needs and exactly what makes it safe to keep
    on an internet-facing box.
    """

    # Version bytes → (network hrp, address style). ypub/zpub are the same key
    # material as xpub with a different prefix advertising the script type.
    VERSIONS = {
        0x0488B21E: ("bc", "p2pkh"),    # xpub
        0x049D7CB2: ("bc", "p2wpkh"),   # ypub  (wrapped segwit)
        0x04B24746: ("bc", "p2wpkh"),   # zpub  (native segwit, BIP84)
        0x043587CF: ("tb", "p2pkh"),    # tpub  (testnet)
        0x045F1CF6: ("tb", "p2wpkh"),   # vpub  (testnet native segwit)
    }

    def __init__(self, serialized: str):
        raw = b58decode_check(serialized.strip())
        if len(raw) != 78:
            raise ValueError("extended key is not 78 bytes")
        version = int.from_bytes(raw[:4], "big")
        if version not in self.VERSIONS:
            raise ValueError(
                "unrecognised extended key prefix — expected xpub/ypub/zpub")
        self.hrp, self.style = self.VERSIONS[version]
        self.depth = raw[4]
        self.chain_code = raw[13:45]
        self.key = raw[45:78]
        if self.key[0] not in (2, 3):
            raise ValueError(
                "this is an extended PRIVATE key — never give one to a server")
        self.point = _deserialize(self.key)

    def child(self, index: int) -> "ExtendedPubkey":
        if index >= 0x80000000:
            raise ValueError("cannot derive a hardened child from a public key")
        data = self.key + index.to_bytes(4, "big")
        digest = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        left, chain = digest[:32], digest[32:]
        scalar = int.from_bytes(left, "big")
        if scalar >= N:
            raise ValueError("derived scalar out of range; skip this index")
        child_point = _point_add(_point_mul(scalar), self.point)
        if child_point is None:
            raise ValueError("derived the point at infinity; skip this index")
        clone = object.__new__(ExtendedPubkey)
        clone.hrp, clone.style = self.hrp, self.style
        clone.depth = self.depth + 1
        clone.chain_code = chain
        clone.point = child_point
        clone.key = _serialize(child_point)
        return clone

    def address(self) -> str:
        """The receive address for this exact key."""
        h160 = hashlib.new("ripemd160", hashlib.sha256(self.key).digest()).digest()
        if self.style == "p2wpkh":
            return bech32_encode(self.hrp, 0, h160)
        # Legacy P2PKH, for an operator who pasted a plain xpub.
        prefix = b"\x00" if self.hrp == "bc" else b"\x6f"
        body = prefix + h160
        checksum = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
        num = int.from_bytes(body + checksum, "big")
        out = ""
        while num:
            num, rem = divmod(num, 58)
            out = _B58[rem] + out
        return "1" * (len(body + checksum) - len((body + checksum).lstrip(b"\x00"))) + out


def receive_address(xpub: str, index: int, chain: int = 0) -> str:
    """
    The address at m/<chain>/<index> below the given account key.

    chain 0 is the receive chain by BIP44 convention; 1 is change, which a
    receiving-only system never needs.
    """
    return ExtendedPubkey(xpub).child(chain).child(index).address()


def looks_like_xpub(value: str) -> bool:
    try:
        ExtendedPubkey(value)
        return True
    except Exception:
        return False
