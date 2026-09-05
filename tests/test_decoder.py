import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from jwt_audit.decoder import decode, signing_input
from tests.token_factory import make_token, now


class TestDecoder(unittest.TestCase):
    def test_valid_token_decodes_cleanly(self):
        tok = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "iat": now()}, secret="s3cret-enough")
        d = decode(tok)
        self.assertTrue(d.is_well_formed)
        self.assertEqual(d.structure_errors, [])
        self.assertEqual(d.header["alg"], "HS256")
        self.assertEqual(d.payload["sub"], "alice")

    def test_wrong_segment_count(self):
        d = decode("only.two")
        self.assertFalse(d.is_well_formed)
        self.assertTrue(any("3 dot-separated" in e for e in d.structure_errors))

    def test_empty_token(self):
        d = decode("")
        self.assertFalse(d.is_well_formed)
        self.assertIn("Token is empty", d.structure_errors)

    def test_invalid_base64_in_header(self):
        d = decode("not-valid-b64!!.eyJhIjoxfQ.sig")
        self.assertFalse(d.is_well_formed)
        self.assertTrue(any("Header" in e for e in d.structure_errors))

    def test_invalid_json_payload(self):
        from tests.token_factory import b64url
        header_b64 = b64url(b'{"alg":"HS256"}')
        payload_b64 = b64url(b'not-json{')
        d = decode(f"{header_b64}.{payload_b64}.sig")
        self.assertFalse(d.is_well_formed)
        self.assertTrue(any("not valid JSON" in e for e in d.structure_errors))

    def test_empty_signature_recorded(self):
        tok = make_token({"alg": "none"}, {"sub": "x"}, alg="none")
        d = decode(tok)
        self.assertTrue(any("Signature segment is empty" in e for e in d.structure_errors))

    def test_signing_input_reconstruction(self):
        tok = make_token({"alg": "HS256"}, {"a": 1}, secret="x")
        h, p, s = tok.split(".")
        self.assertEqual(signing_input(tok), f"{h}.{p}".encode())


if __name__ == "__main__":
    unittest.main()
