#!/usr/bin/env python3
"""
Address derivation, against the specs' own test vectors.

The watch-only payment path derives a receive address per invoice from the
operator's extended public key. A subtle bug here does not throw, does not
fail a health check and does not look wrong: it quietly sends customers to
addresses the operator cannot spend. Money destroyed, silently, with every
status page green.

So nothing here is compared against output this code produced. The BIP84
account key is derived from the spec's own mnemonic — the private derivation
for that lives in this test and nowhere in the product, which never handles a
private key — and the resulting addresses are compared to the ones published
in the BIP. bech32 is checked against BIP173's vector, and BIP32's chain code
and public key against BIP32's own.
"""
import hashlib, hmac, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
sys.path.insert(0, os.path.join(H.REPO, "api"))
import chainwatch as cw

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

def eq(name, got, want):
    check(name, got == want, f"got  {got}\n          want {want}")


account_zpub_from_mnemonic = H.account_zpub_from_mnemonic


try:
    print("[1] BIP84 — the spec's mnemonic, the spec's addresses")
    ZPUB = account_zpub_from_mnemonic(" ".join(["abandon"] * 11 + ["about"]))
    eq("m/84'/0'/0'/0/0", cw.receive_address(ZPUB, 0),
       "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    eq("m/84'/0'/0'/0/1", cw.receive_address(ZPUB, 1),
       "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
    eq("m/84'/0'/0'/1/0 (change chain)", cw.receive_address(ZPUB, 0, chain=1),
       "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")

    print("\n[2] BIP173 bech32")
    eq("P2WPKH encoding",
       cw.bech32_encode("bc", 0, bytes.fromhex(
           "751e76e8199196d454941c45d1b3a323f1433bd6")),
       "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    print("\n[3] public derivation agrees with private derivation")
    # The property BIP32 unhardened derivation exists to have: deriving from
    # the public key must land on the same point as deriving from the private
    # key and then taking its public half. Two independent code paths — the
    # product's point arithmetic, and scalar arithmetic here — so agreement is
    # evidence, not a tautology.
    seed = hashlib.pbkdf2_hmac(
        "sha512", (" ".join(["abandon"] * 11 + ["about"])).encode(),
        b"mnemonic", 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k_priv, c = int.from_bytes(I[:32], "big"), I[32:]

    def ckd_priv(k, c, index):
        if index >= 0x80000000:
            data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:
            data = cw._serialize(cw._point_mul(k)) + index.to_bytes(4, "big")
        I = hmac.new(c, data, hashlib.sha512).digest()
        return (int.from_bytes(I[:32], "big") + k) % cw.N, I[32:]

    Hd = 0x80000000
    for idx in (84 + Hd, 0 + Hd, 0 + Hd, 0):      # m/84'/0'/0'/0
        k_priv, c = ckd_priv(k_priv, c, idx)
    pub_chain = cw.ExtendedPubkey(ZPUB).child(0)
    eq("chain code matches", pub_chain.chain_code.hex(), c.hex())
    eq("public key matches", pub_chain.key.hex(),
       cw._serialize(cw._point_mul(k_priv)).hex())
    for i in (0, 1, 7, 1000):
        kp, _cc = ckd_priv(k_priv, c, i)
        priv_addr_key = cw._serialize(cw._point_mul(kp))
        eq(f"index {i} public key matches private derivation",
           cw.ExtendedPubkey(ZPUB).child(0).child(i).key.hex(),
           priv_addr_key.hex())

    print("\n[4] every index gives a different address")
    addrs = [cw.receive_address(ZPUB, i) for i in range(8)]
    check("eight indices, eight addresses", len(set(addrs)) == 8, addrs)
    check("all native segwit", all(a.startswith("bc1q") for a in addrs), addrs)
    # A reused address makes two payments of the same amount impossible to
    # attribute, which is the whole reason for deriving per invoice.
    check("index 0 is stable across calls",
          cw.receive_address(ZPUB, 0) == addrs[0])

    print("\n[5] what must be refused")
    XPRV = ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkV"
            "vvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    for bad, why in (
        (XPRV, "an extended PRIVATE key"),
        ("notakey", "obvious garbage"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "a plain address"),
        (ZPUB[:-1] + ("q" if ZPUB[-1] != "q" else "p"), "a corrupted checksum"),
    ):
        try:
            cw.ExtendedPubkey(bad)
            check(f"{why} is refused", False, "it was accepted")
        except ValueError:
            check(f"{why} is refused", True)
    check("looks_like_xpub agrees", cw.looks_like_xpub(ZPUB)
          and not cw.looks_like_xpub(XPRV)
          and not cw.looks_like_xpub("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))

    print("\n[6] hardened derivation is impossible from a public key")
    # Not a limitation to work around — it is the property that makes it safe
    # to keep this key on an internet-facing box.
    try:
        cw.ExtendedPubkey(ZPUB).child(0x80000000)
        check("hardened child is refused", False, "it was derived")
    except ValueError:
        check("hardened child is refused", True)

finally:
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
