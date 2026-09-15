"""Regression suite (stdlib unittest — no third-party deps).

    python3 -m unittest tests.test_tpihunter        # or: python3 -m unittest discover

Codifies the invariants that must not regress across sessions:
  * the oracle discriminates (vuln -> TAKEOVER, patched -> SAFE);
  * the load-bearing invariant — no verdict fires on the patched target;
  * the learner recovers the auth machine's essential structure;
  * synthesis from the learned machine matches the hand-coded action model and
    reproduces the enumerator's findings.
"""
from __future__ import annotations

import unittest

from tpihunter.enumerator import ACTIONS, enumerate_plans
from tpihunter.harness import run_plan
from tpihunter.learner import LStar
from tpihunter.mock_target import MockAdapter
from tpihunter.oracle import AtoOracle
from tpihunter.probes import pre_hijacking_plan
from tpihunter.sul import MockSUL
from tpihunter.synthesis import specs_from_machine
from tpihunter.types import Principal

EMAIL = "victim@corp.example"


def _principals():
    return Principal("attacker"), Principal("victim")


def _verdict(plan, patched):
    attacker, victim = _principals()
    control = {victim.name: {EMAIL}}
    adapter = MockAdapter(patched=patched, control=control)
    oracle = AtoOracle(adapter, attacker, victim)
    return run_plan(adapter, plan, oracle)[0]


def _enumerate(specs=None):
    """Return (num_candidates, fired_clauses, patch_gaps) over the mock scenario."""
    attacker, victim = _principals()
    control = {victim.name: {EMAIL}}
    cands = enumerate_plans(attacker, victim, EMAIL, specs=specs)
    fired, patch_gaps = [], 0
    for c in cands:
        av = MockAdapter(patched=False, control=control)
        vv = run_plan(av, c.plan, AtoOracle(av, attacker, victim))[0]
        if vv.severity.value != "takeover":
            continue
        fired.append(vv.clause_id)
        ap = MockAdapter(patched=True, control=control)
        vp = run_plan(ap, c.plan, AtoOracle(ap, attacker, victim))[0]
        if vp.severity.value == "takeover":
            patch_gaps += 1
    return len(cands), fired, patch_gaps


def _learn():
    return LStar(MockSUL(patched=False), seed=1, eq_tests=1500).learn()


class TestOracle(unittest.TestCase):
    def test_takeover_on_vulnerable(self):
        attacker, victim = _principals()
        v = _verdict(pre_hijacking_plan(attacker, victim, EMAIL), patched=False)
        self.assertEqual(v.severity.value, "takeover")
        self.assertEqual(v.clause_id, "TPI-1")
        self.assertEqual(v.failure_mode, "laundering")

    def test_safe_on_patched(self):
        attacker, victim = _principals()
        v = _verdict(pre_hijacking_plan(attacker, victim, EMAIL), patched=True)
        self.assertEqual(v.severity.value, "safe")


class TestEnumerator(unittest.TestCase):
    def test_finds_both_clauses(self):
        _n, fired, _gaps = _enumerate()
        self.assertIn("TPI-1", fired)
        self.assertIn("TPI-4", fired)

    def test_load_bearing_invariant_no_patched_firing(self):
        # The core discipline: a verdict must never fire on the patched target.
        _n, _fired, patch_gaps = _enumerate()
        self.assertEqual(patch_gaps, 0, "a finding fired on the patched target")


class TestLearner(unittest.TestCase):
    def test_alphabet_and_structure(self):
        m = _learn()
        self.assertEqual(set(m.alphabet),
                         {"register", "login", "sso_login", "reset_request", "reset_consume", "logout"})
        # session + verified + reset-token + logged-out dimensions => several states
        self.assertGreaterEqual(len(m.states), 6)

    def test_reset_ordering_read_off(self):
        m = _learn()
        self.assertEqual(m.run(("reset_consume",)), "DENIED")
        self.assertEqual(m.run(("register", "reset_request", "reset_consume")), "OK_SESSION")

    def test_sso_is_observable_raise(self):
        m = _learn()
        self.assertEqual(m.run(("sso_login",)), "OK_VERIFIED")
        self.assertEqual(m.run(("register",)), "OK_SESSION")


class TestSynthesis(unittest.TestCase):
    def test_effects_match_handcoded(self):
        specs = specs_from_machine(_learn())
        for name, hand in ACTIONS.items():
            self.assertIn(name, specs, f"{name} missing from synthesized specs")
            self.assertEqual(specs[name].effect, hand.effect, f"{name} effect mismatch")
            self.assertEqual(specs[name].requires, hand.requires, f"{name} requires mismatch")

    def test_enumerate_from_learned_model(self):
        specs = specs_from_machine(_learn())
        _n, fired, patch_gaps = _enumerate(specs=specs)
        self.assertEqual(sorted(set(fired)), ["TPI-1", "TPI-4"])
        self.assertEqual(patch_gaps, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
