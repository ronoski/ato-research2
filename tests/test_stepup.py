"""TPI-6: the session-trust lattice must be enforced consistently across flows.

Self-validating in the project's existing style: the SAME probe must yield TAKEOVER
on the vulnerable target and SAFE on the patched one, and must refuse to call either
when the control does not fire.
"""
import unittest

from tpihunter.clauses import CLAUSES, FailureMode
from tpihunter.stepup import StepUpTarget, _Acct, probe_stepup
from tpihunter.types import Observation, SessionLevel


class TestClause(unittest.TestCase):
    def test_tpi6_registered(self):
        self.assertIn("TPI-6", CLAUSES)
        self.assertEqual(CLAUSES["TPI-6"].mode, FailureMode.GAP)
        self.assertEqual(CLAUSES["TPI-6"].title, "step-up-not-bypassable")


class TestObservationCarriesSession(unittest.TestCase):
    def test_session_defaults_none_and_is_settable(self):
        self.assertIsNone(Observation(ok=True).session)          # non-breaking
        self.assertIs(Observation(ok=True, session=SessionLevel.PARTIAL).session,
                      SessionLevel.PARTIAL)


class TestLattice(unittest.TestCase):
    def test_first_factor_yields_partial_not_full(self):
        o = StepUpTarget().first_factor()
        self.assertIs(o.session, SessionLevel.PARTIAL)
        self.assertNotEqual(o.session, SessionLevel.FULL)

    def test_primary_flow_refuses_partial(self):
        t = StepUpTarget()
        tok = t.first_factor().extracted["token"]
        up = t.session_upgrade(tok)
        self.assertFalse(up.ok)
        self.assertEqual(up.extracted.get("authz_req"), "STEP_UP")

    def test_second_factor_upgrades(self):
        t = StepUpTarget()
        tok = t.first_factor().extracted["token"]
        self.assertTrue(t.stepup_satisfy(tok).ok)
        self.assertTrue(t.session_upgrade(tok).ok)


class TestOracle(unittest.TestCase):
    def test_vulnerable_target_yields_tpi6_takeover(self):
        v = probe_stepup(StepUpTarget(patched=False))
        self.assertEqual(v.severity, "TAKEOVER")
        self.assertEqual(v.clause_id, "TPI-6")
        self.assertTrue(any("CONTROL FIRED" in e for e in v.evidence),
                        "a takeover must be backed by the primary flow's refusal")

    def test_patched_target_is_safe(self):
        v = probe_stepup(StepUpTarget(patched=True))
        self.assertEqual(v.severity, "SAFE")
        self.assertIsNone(v.clause_id)

    def test_same_probe_separates_them(self):
        self.assertNotEqual(probe_stepup(StepUpTarget(patched=False)).severity,
                            probe_stepup(StepUpTarget(patched=True)).severity)

    def test_no_stepup_enrolled_is_inconclusive_not_takeover(self):
        """If the primary flow never refuses, a sibling accepting the credential
        proves nothing — the tool must not call that a finding."""
        t = StepUpTarget(patched=False, acct=_Acct("acct-1", second_factor=False))
        v = probe_stepup(t)
        self.assertEqual(v.severity, "INCONCLUSIVE")
        self.assertIsNone(v.clause_id)

    def test_factor_actually_rewritten_on_vulnerable(self):
        t = StepUpTarget(patched=False)
        before = t.acct.pin
        probe_stepup(t)
        self.assertNotEqual(t.acct.pin, before)

    def test_factor_untouched_on_patched(self):
        t = StepUpTarget(patched=True)
        before = t.acct.pin
        probe_stepup(t)
        self.assertEqual(t.acct.pin, before)


if __name__ == "__main__":
    unittest.main()
