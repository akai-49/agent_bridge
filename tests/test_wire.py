import base64
import hashlib
import hmac
import unittest

from server.wire import make_token, parse_token, sign, verify


class TestWire(unittest.TestCase):
    def setUp(self):
        self.relay_url = "https://relay.example.com:8080"
        self.invite_id = "inv_1234567890abcdef"
        self.join_secret = "sec_fedcba0987654321"
        self.e2e_key = "key_aabbccddeeff00112233"

    def test_roundtrip_token(self):
        token = make_token(
            self.relay_url,
            self.invite_id,
            self.join_secret,
            self.e2e_key,
        )
        self.assertTrue(token.startswith("brg1."))

        parsed = parse_token(token)
        self.assertEqual(parsed["relay_url"], self.relay_url)
        self.assertEqual(parsed["invite_id"], self.invite_id)
        self.assertEqual(parsed["join_secret"], self.join_secret)
        self.assertEqual(parsed["e2e_key"], self.e2e_key)

    def test_parse_rejects_wrong_prefix(self):
        bad_token = f"brg2.someb64.{self.invite_id}.{self.join_secret}.{self.e2e_key}"
        with self.assertRaises(ValueError):
            parse_token(bad_token)

        bad_token2 = f"token.{self.invite_id}.{self.join_secret}.{self.e2e_key}"
        with self.assertRaises(ValueError):
            parse_token(bad_token2)

    def test_verify_rejects_tampered_body(self):
        qid = "qid_001"
        body = '{"question": "How does login work?"}'
        sig = sign(self.e2e_key, qid, body)

        self.assertTrue(verify(self.e2e_key, qid, body, sig))
        self.assertFalse(verify(self.e2e_key, qid, body + " ", sig))
        self.assertFalse(verify(self.e2e_key, qid, '{"question": "other"}', sig))

    def test_verify_rejects_wrong_key(self):
        qid = "qid_002"
        body = '{"question": "Where are routes defined?"}'
        sig = sign(self.e2e_key, qid, body)

        wrong_key = "different_key_9999"
        self.assertFalse(verify(wrong_key, qid, body, sig))

    def test_verify_rejects_tampered_qid(self):
        qid = "qid_003"
        body = '{"answer": "In app.routes"}'
        sig = sign(self.e2e_key, qid, body)

        self.assertFalse(verify(self.e2e_key, "qid_tampered", body, sig))

    def test_sign_matches_spec(self):
        qid = "q123"
        body = "hello world"
        key = "secret_key"
        expected_sig = hmac.new(
            key.encode("utf-8"),
            f"{qid}\n{body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        actual_sig = sign(key, qid, body)
        self.assertEqual(actual_sig, expected_sig)

    def test_parse_rejects_malformed_tokens(self):
        # Too few parts
        with self.assertRaises(ValueError):
            parse_token("brg1.a.b.c")

        # Too many parts
        with self.assertRaises(ValueError):
            parse_token("brg1.a.b.c.d.e")

        # Non-string
        with self.assertRaises(ValueError):
            parse_token(123)  # type: ignore

        # Corrupted base64url relay_url
        with self.assertRaises(ValueError):
            parse_token(f"brg1.???InvalidB64???.{self.invite_id}.{self.join_secret}.{self.e2e_key}")

        # Empty components
        with self.assertRaises(ValueError):
            parse_token(f"brg1..{self.invite_id}.{self.join_secret}.{self.e2e_key}")

    def test_parse_token_handles_both_padded_and_unpadded_b64(self):
        url = "https://example.com"
        b64_padded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        b64_unpadded = b64_padded.rstrip("=")

        token_padded = f"brg1.{b64_padded}.id.sec.key"
        token_unpadded = f"brg1.{b64_unpadded}.id.sec.key"

        self.assertEqual(parse_token(token_padded)["relay_url"], url)
        self.assertEqual(parse_token(token_unpadded)["relay_url"], url)


if __name__ == "__main__":
    unittest.main()
