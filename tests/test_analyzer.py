import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from jwt_audit.analyzer import Severity, analyze
from jwt_audit.decoder import decode
from tests.token_factory import make_token, now


def finding_ids(result):
    return {f.id for f in result.findings}


class TestAlgorithmChecks(unittest.TestCase):
    def test_alg_none_flagged_critical(self):
        tok = make_token({"alg": "none", "typ": "JWT"}, {"sub": "admin", "exp": now() + 3600, "iat": now()}, alg="none")
        result = analyze(decode(tok))
        self.assertIn("ALG-002", finding_ids(result))
        self.assertEqual(result.max_severity, Severity.CRITICAL)

    def test_alg_none_case_variant_flagged(self):
        # "nOnE" style casing bypass attempts against naive string checks
        tok = make_token({"alg": "nOnE", "typ": "JWT"}, {"sub": "admin"}, alg="none")
        result = analyze(decode(tok))
        self.assertIn("ALG-002", finding_ids(result))

    def test_missing_alg_flagged(self):
        tok = make_token({"typ": "JWT"}, {"sub": "x"}, alg="none")
        result = analyze(decode(tok))
        self.assertIn("ALG-001", finding_ids(result))

    def test_unrecognized_alg_flagged(self):
        tok = make_token({"alg": "ROT13", "typ": "JWT"}, {"sub": "x"}, alg="ROT13")
        result = analyze(decode(tok))
        self.assertIn("ALG-003", finding_ids(result))

    def test_valid_hs256_alg_not_flagged(self):
        tok = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "x", "iat": now(), "exp": now() + 300,
                                                            "iss": "auth.example.com", "aud": "api.example.com"},
                          secret="a-reasonably-long-random-secret")
        result = analyze(decode(tok))
        self.assertNotIn("ALG-001", finding_ids(result))
        self.assertNotIn("ALG-002", finding_ids(result))
        self.assertNotIn("ALG-003", finding_ids(result))

    def test_jku_header_flagged(self):
        tok = make_token({"alg": "RS256", "jku": "https://attacker.example/keys.json"}, {"sub": "x"},
                          alg="RS256")
        result = analyze(decode(tok))
        self.assertIn("ALG-HDR-JKU", finding_ids(result))

    def test_suspicious_kid_path_traversal_flagged(self):
        tok = make_token({"alg": "HS256", "kid": "../../../../etc/passwd"}, {"sub": "x"},
                          secret="whatever")
        result = analyze(decode(tok))
        self.assertIn("ALG-KID-001", finding_ids(result))

    def test_suspicious_kid_sql_injection_flagged(self):
        tok = make_token({"alg": "HS256", "kid": "1' UNION SELECT key FROM keys--"}, {"sub": "x"},
                          secret="whatever")
        result = analyze(decode(tok))
        self.assertIn("ALG-KID-001", finding_ids(result))


class TestClaimChecks(unittest.TestCase):
    def test_expired_token_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "iat": now() - 7200, "exp": now() - 3600},
                          secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("CLAIM-EXP-002", finding_ids(result))

    def test_missing_exp_flagged_high(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "iat": now()}, secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("CLAIM-EXP-001", finding_ids(result))

    def test_not_yet_valid_nbf_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "iat": now(), "exp": now() + 3600, "nbf": now() + 1800},
                          secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("CLAIM-NBF-001", finding_ids(result))

    def test_future_iat_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "iat": now() + 9999, "exp": now() + 20000},
                          secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("CLAIM-IAT-001", finding_ids(result))

    def test_excessively_long_lifetime_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "iat": now(), "exp": now() + 60 * 60 * 24 * 400},
                          secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("CLAIM-LIFETIME-001", finding_ids(result))

    def test_reasonable_lifetime_not_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "iat": now(), "exp": now() + 900,
                                            "iss": "a", "aud": "b"}, secret="secretsecret")
        result = analyze(decode(tok))
        ids = finding_ids(result)
        self.assertNotIn("CLAIM-LIFETIME-001", ids)
        self.assertNotIn("CLAIM-LIFETIME-002", ids)

    def test_missing_iss_aud_sub_flagged(self):
        tok = make_token({"alg": "HS256"}, {"iat": now(), "exp": now() + 300}, secret="secretsecret")
        result = analyze(decode(tok))
        ids = finding_ids(result)
        self.assertIn("CLAIM-ISS-MISSING", ids)
        self.assertIn("CLAIM-AUD-MISSING", ids)
        self.assertIn("CLAIM-SUB-MISSING", ids)

    def test_bad_exp_type_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "exp": "tomorrow"}, secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("CLAIM-EXP-TYPE", finding_ids(result))


class TestSensitiveDataChecks(unittest.TestCase):
    def test_password_in_payload_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "password": "hunter2", "iat": now(), "exp": now() + 300},
                          secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("SENS-KEY-001", finding_ids(result))

    def test_credit_card_like_value_flagged(self):
        tok = make_token({"alg": "HS256"}, {"sub": "x", "note": "4111111111111111", "iat": now(), "exp": now() + 300},
                          secret="secretsecret")
        result = analyze(decode(tok))
        self.assertIn("SENS-VAL-PAN", finding_ids(result))

    def test_clean_payload_no_sensitive_findings(self):
        tok = make_token({"alg": "HS256"}, {"sub": "user-123", "role": "viewer", "iat": now(), "exp": now() + 300},
                          secret="secretsecret")
        result = analyze(decode(tok))
        sens_ids = [i for i in finding_ids(result) if i.startswith("SENS-")]
        self.assertEqual(sens_ids, [])


class TestStructuralChecks(unittest.TestCase):
    def test_malformed_token_flagged_critical(self):
        result = analyze(decode("garbage-not-a-jwt"))
        self.assertIn("STRUCT-001", finding_ids(result))
        self.assertEqual(result.max_severity, Severity.CRITICAL)


class TestRiskScoring(unittest.TestCase):
    def test_clean_token_scores_low(self):
        tok = make_token({"alg": "HS256"}, {
            "sub": "user-1", "iss": "auth.example.com", "aud": "api.example.com",
            "iat": now(), "exp": now() + 600,
        }, secret="secretsecret")
        result = analyze(decode(tok))
        self.assertLessEqual(result.risk_score, 15)

    def test_disastrous_token_scores_high(self):
        # alg:none + expired + no exp claims sanity + sensitive data
        tok = make_token({"alg": "none"}, {
            "sub": "admin", "password": "hunter2", "ssn": "123-45-6789",
        }, alg="none")
        result = analyze(decode(tok))
        self.assertGreaterEqual(result.risk_score, 50)
        self.assertEqual(result.max_severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
