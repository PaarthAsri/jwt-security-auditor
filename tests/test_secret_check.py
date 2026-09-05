import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from jwt_audit.secret_check import check_weak_secret, BUILTIN_COMMON_WEAK_SECRETS
from tests.token_factory import make_token


class TestSecretCheck(unittest.TestCase):
    def test_finds_known_weak_secret(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x"}, secret="password")
        result = check_weak_secret(tok, "HS256", list(BUILTIN_COMMON_WEAK_SECRETS))
        self.assertEqual(result.match, "password")

    def test_does_not_match_strong_secret(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x"}, secret="Xk9#mP2$vL8qR5!wZ4nT7yB3")
        result = check_weak_secret(tok, "HS256", list(BUILTIN_COMMON_WEAK_SECRETS))
        self.assertIsNone(result.match)

    def test_hs384_and_hs512_supported(self):
        for alg in ("HS384", "HS512"):
            tok = make_token({"alg": alg}, {"sub": "x"}, secret="changeme", alg=alg)
            result = check_weak_secret(tok, alg, list(BUILTIN_COMMON_WEAK_SECRETS))
            self.assertEqual(result.match, "changeme")

    def test_rejects_non_hmac_algorithm(self):
        tok = make_token({"alg": "RS256"}, {"sub": "x"}, alg="RS256")
        with self.assertRaises(ValueError):
            check_weak_secret(tok, "RS256", list(BUILTIN_COMMON_WEAK_SECRETS))

    def test_max_candidates_cap_truncates(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x"}, secret="zzz-not-in-list")
        big_list = [f"candidate-{i}" for i in range(10)]
        result = check_weak_secret(tok, "HS256", big_list, max_candidates=3)
        self.assertTrue(result.truncated)
        self.assertEqual(result.attempted, 3)


if __name__ == "__main__":
    unittest.main()
