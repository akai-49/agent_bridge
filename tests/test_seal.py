from __future__ import annotations
import unittest

from server import wire


class TestSeal(unittest.TestCase):
    K = "k" * 43

    def test_roundtrip(self):
        for t in ("", "hello", "héllo 世界 🚀", "x" * 5000):
            self.assertEqual(wire.open_sealed(self.K, "q:A", wire.seal(self.K, "q:A", t)), t)

    def test_wrong_key_or_tag_fails(self):
        s = wire.seal(self.K, "q:A", "secret")
        self.assertIsNone(wire.open_sealed("z" * 43, "q:A", s))
        self.assertIsNone(wire.open_sealed(self.K, "a:A:1", s))

    def test_tamper_fails(self):
        s = wire.seal(self.K, "q:A", "secret text")
        i = len(s) - 5
        bad = s[:i] + ("A" if s[i] != "A" else "B") + s[i + 1:]
        self.assertIsNone(wire.open_sealed(self.K, "q:A", bad))
        self.assertIsNone(wire.open_sealed(self.K, "q:A", s[:-8]))
        self.assertIsNone(wire.open_sealed(self.K, "q:A", "garbage"))
        self.assertIsNone(wire.open_sealed(self.K, "q:A", None))

    def test_nondeterministic_and_hides_plaintext(self):
        a, b = wire.seal(self.K, "q:A", "same"), wire.seal(self.K, "q:A", "same")
        self.assertNotEqual(a, b)
        self.assertNotIn("same", a)


if __name__ == "__main__":
    unittest.main()
