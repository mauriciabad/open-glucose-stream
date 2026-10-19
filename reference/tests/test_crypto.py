# Open Glucose Stream reference — https://github.com/mauriciabad/open-glucose-stream
# SPDX-FileCopyrightText: 2026 Maurici Abad
# SPDX-License-Identifier: CC0-1.0
"""Crypto against excerpts of the official vectors: NIP-44 (paulmillr/nip44, nip44.vectors.json; all 101 valid and
20 invalid cases pass against the full file) and BIP-340 (bitcoin/bips bip-0340/test-vectors.csv, all 19 rows)."""
import unittest

from ogs import crypto as c
from ogs.nostr import Keys

NIP44_ENCRYPT = [
    ("0000000000000000000000000000000000000000000000000000000000000001",
     "0000000000000000000000000000000000000000000000000000000000000002",
     "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
     "0000000000000000000000000000000000000000000000000000000000000001", "a",
     "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuT"
     "MxWfp1RTN9Xga8no+kF5Vsb"),
    ("0000000000000000000000000000000000000000000000000000000000000002",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
     "f00000000000000000000000000000f00000000000000000000000000000000f", "\U0001F355\U0001FAC3",
     "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8"
     "nDITO+QfaQ61+KbWQIOO2Yj"),
]
NIP44_CK = [("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
             "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
             "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1")]
NIP44_INVALID = [
    ("ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642",
     "#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/GrE92xAc1K5odTpCzUB+mjXgbaqt"
     "ntBUbTToSUoT0ovrlPwzGjyp"),
    ("36f04e558af246352dcf73b692fbd3646a2207bd8abd4b1cd26b234db84d9481",
     "AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBZFaha6EAIRueE9D1B1RuoiuFScC0Q94yjIuxZD3JStQtE8JMNacWFs9rlYP+Zyd"
     "tHhRucp+lxfdvFlaGV/sQlqZz"),
]
BIP340 = [  # secret, public, aux, message, signature, valid
    ("0000000000000000000000000000000000000000000000000000000000000003",
     "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "00" * 32, "00" * 32,
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F"
     "477DF4900D310536C0", True),
    ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "00" * 31 + "01",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA87"
     "1CFA95F6DE339E4B0A", True),
    ("", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE"
     "5EBEAFA34B1AC553E2", False),
]


class Crypto(unittest.TestCase):
    def test_nip44(self):
        for s1, s2, ck, nonce, pt, payload in NIP44_ENCRYPT:
            key = c.nip44_conversation_key(bytes.fromhex(s1), c.xonly(bytes.fromhex(s2)))
            self.assertEqual(key.hex(), ck)
            self.assertEqual(c.nip44_encrypt(pt, key, bytes.fromhex(nonce)), payload)
            self.assertEqual(c.nip44_decrypt(payload, key), pt)
        for s1, p2, ck in NIP44_CK:
            self.assertEqual(c.nip44_conversation_key(bytes.fromhex(s1), bytes.fromhex(p2)).hex(), ck)
        for ck, payload in NIP44_INVALID:
            with self.assertRaises(ValueError):
                c.nip44_decrypt(payload, bytes.fromhex(ck))

    def test_bip340(self):
        for sec, pub, aux, msg, sig, ok in BIP340:
            if sec:
                self.assertEqual(c.schnorr_sign(bytes.fromhex(msg), bytes.fromhex(sec), bytes.fromhex(aux)).hex(),
                                 sig.lower())
                self.assertEqual(c.xonly(bytes.fromhex(sec)).hex(), pub.lower())
            self.assertEqual(c.schnorr_verify(bytes.fromhex(msg), bytes.fromhex(pub), bytes.fromhex(sig)), ok)

    def test_hkdf_rfc5869_a1(self):
        okm = c.hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                     bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_nsec_roundtrip(self):
        k = Keys(bytes(31) + b"\x01")
        self.assertEqual(c.nsec_decode(k.nsec()), k.sec)


if __name__ == "__main__":
    unittest.main()
