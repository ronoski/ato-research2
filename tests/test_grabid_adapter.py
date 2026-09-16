"""GrabID adapter — offline contract tests.

These assert the adapter's SAFETY and SHAPE without touching the network. The live
validation (probe_structure reproducing MfaPreAuthPhoneOtpPostRequest on the real
target) is run by hand and recorded in the commit message; it is deliberately not
a unit test, because a test suite must not depend on a third party's availability.
"""
import unittest

from tpihunter.targets.grabid import BARRED, GrabIDAdapter
from tpihunter.types import Principal, SessionLevel


class TestSafety(unittest.TestCase):
    def setUp(self):
        self.a = GrabIDAdapter(bug_bounty_header="x", device_id="d")

    def test_register_is_refused(self):
        with self.assertRaises(PermissionError):
            self.a.register(Principal("attacker"), "a@b.c", "pw")

    def test_barred_routes_refused_before_a_request_is_built(self):
        for path in ("phone/reset/pin", "mfa/pinrecovery-reset",
                     "me/mfa/pin/google-recovery-setup", "mfa/device-consent/push/approve",
                     "mfa/pin/verify-login"):
            self.assertTrue(BARRED.search(path), path)
            with self.assertRaises(PermissionError, msg=path):
                self.a._post(path, {})

    def test_sms_leg_refuses_without_an_injected_driver(self):
        """The signed leg cannot be faked; absent a driver the adapter must say so
        rather than pretend it produced a credential."""
        with self.assertRaises(RuntimeError):
            self.a.first_factor(Principal("attacker"), "+840000000")

    def test_no_secret_is_generated_anywhere(self):
        self.assertIsNone(self.a.code_provider)
        self.assertIsNone(self.a.first_factor_driver)


class TestContexts(unittest.TestCase):
    def test_principals_have_independent_contexts(self):
        a = GrabIDAdapter(bug_bounty_header="x", device_id="d")
        v, atk = Principal("victim"), Principal("attacker")
        a._ctx(v).pre_auth = "tok-v"
        self.assertIsNone(a._ctx(atk).pre_auth)
        self.assertEqual(a._ctx(v).pre_auth, "tok-v")

    def test_fresh_context_starts_anon(self):
        a = GrabIDAdapter(bug_bounty_header="x", device_id="d")
        self.assertIs(a._ctx(Principal("p")).level, SessionLevel.ANON)

    def test_upgrade_without_credential_is_anon_not_crash(self):
        a = GrabIDAdapter(bug_bounty_header="x", device_id="d")
        o = a.session_upgrade(Principal("p"))
        self.assertFalse(o.ok)
        self.assertIs(o.session, SessionLevel.ANON)


class TestCodeExtraction(unittest.TestCase):
    def test_reads_both_error_envelopes(self):
        a = GrabIDAdapter(bug_bounty_header="x", device_id="d")
        self.assertEqual(a._code('{"errors":[{"code":10015}]}'), "10015")
        self.assertEqual(a._code('{"statusCode":10074,"error":{}}'), "10074")
        self.assertEqual(a._code("not json"), "")


if __name__ == "__main__":
    unittest.main()
