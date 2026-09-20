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

import json
import time

from tpihunter.agent import AgentHunter, EnumeratorStrategist, HuntState, LLMStrategist
from tpihunter.dedup import build_plan, deduplicate
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


def _vuln_verdict_fn(attacker, victim):
    control = {victim.name: {EMAIL}}

    def fn(plan):
        a = MockAdapter(patched=False, control=control)
        return run_plan(a, plan, AtoOracle(a, attacker, victim))[0]
    return fn


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


class TestOracleConfirmation(unittest.TestCase):
    """M13: a verdict must reproduce (strict majority of passes) before it fires, so a
    flaky/rate-limited target cannot flip it. `confirm=0` stays identical to before."""

    def _plan(self, attacker, victim):
        return pre_hijacking_plan(attacker, victim, EMAIL)

    def _flaky(self, patched, seed, drop=0.7):
        from tpihunter.flaky import FlakyAdapter
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}}
        return FlakyAdapter(MockAdapter(patched=patched, control=control),
                            attacker.name, drop=drop, seed=seed)

    def test_confirm_zero_matches_legacy_behaviour(self):
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}}
        for patched, expect in ((False, "takeover"), (True, "safe")):
            a = MockAdapter(patched=patched, control=control)
            v = run_plan(a, self._plan(attacker, victim),
                         AtoOracle(a, attacker, victim, confirm=0))[0]
            self.assertEqual(v.severity.value, expect)

    def test_flaky_single_probe_misses_but_confirmation_recovers(self):
        attacker, victim = _principals()
        # find a seed where a single flaky probe MISSES the real takeover, then show that
        # confirmation on the SAME flaky target recovers the true verdict
        missed = None
        for s in range(60):
            a = self._flaky(False, s)
            if run_plan(a, self._plan(attacker, victim),
                        AtoOracle(a, attacker, victim, confirm=0))[0].severity.value != "takeover":
                missed = s
                break
        self.assertIsNotNone(missed, "expected at least one flaky single-probe miss")
        a = self._flaky(False, missed)
        v = run_plan(a, self._plan(attacker, victim),
                     AtoOracle(a, attacker, victim, confirm=12))[0]
        self.assertEqual(v.severity.value, "takeover")

    def test_confirmation_never_fires_on_patched_when_flaky(self):
        # the load-bearing invariant survives flakiness at every seed and any confirm count
        attacker, victim = _principals()
        for seed in range(30):
            a = self._flaky(True, seed)
            v = run_plan(a, self._plan(attacker, victim),
                         AtoOracle(a, attacker, victim, confirm=6))[0]
            self.assertNotEqual(v.severity.value, "takeover")

    def test_wrapper_passes_non_attacker_calls_through(self):
        from tpihunter.flaky import FlakyAdapter
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}}
        w = FlakyAdapter(MockAdapter(patched=False, control=control),
                         attacker.name, drop=1.0, seed=0)
        w.register(victim, EMAIL, "VictimPw!1")       # pass-through mutating call
        self.assertTrue(w.whoami(victim).ok)          # victim is never flapped
        self.assertFalse(w.whoami(attacker).ok)       # attacker flapped at drop=1.0

    def test_agent_hunter_accepts_confirm(self):
        # threading confirm through the agent loop still finds the bugs on the (clean) mock
        attacker, victim = _principals()
        hunter = AgentHunter(_adapter_factory(victim), attacker, victim, EMAIL,
                             budget=300, confirm=2)
        res = hunter.hunt(EnumeratorStrategist())
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])


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


class TestWMethod(unittest.TestCase):
    """The W-method equivalence oracle: soundness within a state bound — it certifies a
    correct hypothesis (no false counterexample) AND catches any wrong one (no missed bug)."""

    def _learn_wmethod(self, extra_states=2):
        from tpihunter.learner import LStar
        from tpihunter.sul import MockSUL
        return LStar(MockSUL(patched=False), eq_method="wmethod",
                     extra_states=extra_states).learn()

    def test_state_cover_reaches_every_state(self):
        from tpihunter import wmethod
        m = self._learn_wmethod()
        reached = set()
        for acc in wmethod.state_cover(m):
            s = m.initial
            for a in acc:
                s, _ = m.trans[(s, a)]
            reached.add(s)
        self.assertEqual(reached, set(m.states))

    def test_characterization_set_separates_all_state_pairs(self):
        from tpihunter import wmethod
        m = self._learn_wmethod()
        W = wmethod.characterization_set(m)
        states = list(m.states)
        for i in range(len(states)):
            for j in range(i + 1, len(states)):
                self.assertTrue(
                    any(wmethod._hyp_trace(m, states[i], w) != wmethod._hyp_trace(m, states[j], w)
                        for w in W),
                    f"states {states[i]}/{states[j]} not separated by W")

    def test_no_false_counterexample_on_correct_hypothesis(self):
        from tpihunter import wmethod
        from tpihunter.sul import MockSUL
        m = self._learn_wmethod()
        # certified even at a wider margin than it was learned with
        self.assertIsNone(wmethod.find_counterexample(m, MockSUL(patched=False), extra_states=3))

    def test_catches_corrupted_output_hypothesis(self):
        import copy
        from tpihunter import wmethod
        from tpihunter.sul import MockSUL
        m = self._learn_wmethod()
        bad = copy.deepcopy(m)
        (s, a) = next(iter(bad.trans))
        ns, o = bad.trans[(s, a)]
        bad.trans[(s, a)] = (ns, o + "_WRONG")           # corrupt an output label
        ce = wmethod.find_counterexample(bad, MockSUL(patched=False), extra_states=0)
        self.assertIsNotNone(ce)
        self.assertNotEqual(bad.run(ce), self._sul_last(MockSUL(patched=False), ce))

    def test_catches_corrupted_transition_target(self):
        import copy
        from tpihunter import wmethod
        from tpihunter.sul import MockSUL
        m = self._learn_wmethod()
        bad = copy.deepcopy(m)
        (s, a) = next(iter(bad.trans))
        _ns, o = bad.trans[(s, a)]
        bad.trans[(s, a)] = (bad.initial, o)             # redirect a transition (structural)
        ce = wmethod.find_counterexample(bad, MockSUL(patched=False), extra_states=2)
        self.assertIsNotNone(ce)

    def test_learned_machine_is_exhaustively_conformant(self):
        from itertools import product
        from tpihunter.sul import MockSUL
        m = self._learn_wmethod()
        self.assertEqual(len(m.states), 9)               # the full auth FSM, not a partial one
        sul = MockSUL(patched=False)
        for L in range(1, 5):   # exhaustive to length 4; the certification test covers the bound
            for w in product(m.alphabet, repeat=L):
                self.assertEqual(m.run(w), self._sul_last(sul, w))

    @staticmethod
    def _sul_last(sul, word):
        sul.reset()
        out = "-"
        for a in word:
            out = sul.step(a)
        return out


class TestDedup(unittest.TestCase):
    def test_collapses_to_two_distinct_bugs(self):
        attacker, victim = _principals()
        cands = enumerate_plans(attacker, victim, EMAIL)
        vuln = _vuln_verdict_fn(attacker, victim)
        clusters = deduplicate(cands, attacker, victim, EMAIL, vuln)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(sorted(c.clause_id for c in clusters), ["TPI-1", "TPI-4"])

    def test_every_fired_candidate_is_clustered(self):
        attacker, victim = _principals()
        cands = enumerate_plans(attacker, victim, EMAIL)
        vuln = _vuln_verdict_fn(attacker, victim)
        fired = [c for c in cands if vuln(c.plan).severity.value == "takeover"]
        clusters = deduplicate(cands, attacker, victim, EMAIL, vuln)
        self.assertEqual(sum(c.size for c in clusters), len(fired))

    def test_representative_is_minimal_and_reproduces(self):
        attacker, victim = _principals()
        cands = enumerate_plans(attacker, victim, EMAIL)
        vuln = _vuln_verdict_fn(attacker, victim)
        clusters = deduplicate(cands, attacker, victim, EMAIL, vuln)
        for cl in clusters:
            # the minimal repro still triggers a takeover of the cluster's clause
            v = vuln(build_plan(tuple(cl.representative), attacker, victim, EMAIL))
            self.assertEqual(v.severity.value, "takeover")
            self.assertEqual(v.clause_id, cl.clause_id)
            # and it is genuinely minimal: TPI-1 in 2 steps, TPI-4 in 3
            expected_len = 2 if cl.clause_id == "TPI-1" else 3
            self.assertEqual(len(cl.representative), expected_len)


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


def _adapter_factory(victim):
    control = {victim.name: {EMAIL}}
    return lambda: MockAdapter(patched=False, control=control)


# --- a fake anthropic client, so the LLM wiring is testable with no network ---
class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text, stop_reason="end_turn"):
        self.content = [_Block(text)]
        self.stop_reason = stop_reason
        self.stop_details = None


class _FakeMessages:
    def __init__(self, text, stop_reason="end_turn"):
        self._text, self._stop = text, stop_reason
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return _Resp(self._text, self._stop)


class _FakeClient:
    def __init__(self, text, stop_reason="end_turn"):
        self.messages = _FakeMessages(text, stop_reason)


def _two_probes(_prompt):
    return json.dumps([
        {"steps": [["attacker", "register"], ["victim", "sso_login"]]},
        {"steps": [["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]]},
    ])


class TestAgent(unittest.TestCase):
    def test_enumerator_strategist_finds_two_bugs(self):
        attacker, victim = _principals()
        hunter = AgentHunter(_adapter_factory(victim), attacker, victim, EMAIL, budget=300)
        res = hunter.hunt(EnumeratorStrategist())
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])

    def test_llm_strategist_finds_two_bugs_in_two_probes(self):
        attacker, victim = _principals()
        hunter = AgentHunter(_adapter_factory(victim), attacker, victim, EMAIL, budget=300)
        res = hunter.hunt(LLMStrategist(_two_probes, max_rounds=1))
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])
        self.assertEqual(res.probes_used, 2)   # the agent adapts instead of brute-forcing

    def test_prompt_contains_contract(self):
        attacker, victim = _principals()
        state = HuntState(ACTIONS, attacker, victim, EMAIL, budget=10)
        prompt = LLMStrategist(_two_probes).render_prompt(state)
        for token in ("TPI-1", "register", "sso_login", "attacker", "victim"):
            self.assertIn(token, prompt)

    def test_parse_rejects_unknown_and_malformed(self):
        attacker, victim = _principals()
        state = HuntState(ACTIONS, attacker, victim, EMAIL, budget=10)
        strat = LLMStrategist(_two_probes)
        good = strat.parse_proposals(
            '[{"steps": [["attacker","register"],["victim","sso_login"]]}]', state)
        self.assertEqual(good, [(("attacker", "register"), ("victim", "sso_login"))])
        # unknown action dropped -> empty; malformed text -> empty
        self.assertEqual(strat.parse_proposals('[{"steps": [["attacker","nope"]]}]', state), [])
        self.assertEqual(strat.parse_proposals("not json at all", state), [])


class TestMcpSession(unittest.TestCase):
    def _session(self, target="mock-vulnerable"):
        from tpihunter.mcp_tools import HuntSession
        return HuntSession(target=target)

    def test_briefing_and_actions(self):
        s = self._session()
        b = s.briefing()
        self.assertIn("LAUNDERING", b["method"])
        self.assertTrue(any(c["id"] == "TPI-1" for c in b["clauses"]))
        self.assertEqual(set(s.list_actions()["actions"]),
                         {"register", "login", "sso_login", "reset_request", "reset_consume"})

    def test_run_probe_takeover_and_findings(self):
        s = self._session()
        r1 = s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
        self.assertEqual(r1["severity"], "takeover")
        self.assertEqual(r1["clause_id"], "TPI-1")
        self.assertTrue(r1["is_new_takeover"])
        s.run_probe([["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]])
        f = s.findings()
        self.assertEqual(f["distinct_bugs"], 2)
        self.assertEqual(sorted(b["clause_id"] for b in f["bugs"]), ["TPI-1", "TPI-4"])

    def test_run_probe_safe_and_invalid(self):
        s = self._session()
        # A probe with no victim step never plants a canary, so there is no ground truth to
        # compare against: the honest answer is INCONCLUSIVE, not a confident "safe" (which
        # would teach the agent this surface was tested and found secure).
        r = s.run_probe([["attacker", "register"]])
        self.assertEqual(r["severity"], "inconclusive")
        self.assertEqual(r["withheld"], "canary_not_planted")
        self.assertEqual(r["reason"], "inconclusive")
        self.assertEqual(s.run_probe([["attacker", "register"], ["victim", "sso_login"]],
                                     )["severity"], "takeover")   # a real probe still fires
        self.assertFalse(s.run_probe([["attacker", "reset_consume"]])["ok"])   # ordering
        self.assertFalse(s.run_probe([["attacker", "nope"]])["ok"])            # unknown action
        self.assertFalse(s.run_probe([["nobody", "register"]])["ok"])          # bad role

    def test_patched_target_is_safe(self):
        # the load-bearing invariant, exercised through the tool surface
        s = self._session(target="mock-patched")
        r = s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
        self.assertEqual(r["severity"], "safe")


class TestNewActionSynthesis(unittest.TestCase):
    def test_registered_action_finds_bug_beyond_alphabet(self):
        from tpihunter.enumerator import ACTIONS
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target="mock-patched")
        # known laundering is fixed on the patched target
        self.assertEqual(
            s.run_probe([["attacker", "register"], ["victim", "sso_login"]])["severity"], "safe")
        # the agent hypothesizes the parallel passwordless flow
        self.assertTrue(s.register_action("magic_link", "raise", needs_control=True)["ok"])
        self.assertIn("magic_link", s.list_actions()["actions"])
        r = s.run_probe([["attacker", "register"], ["victim", "magic_link"]])
        self.assertEqual(r["severity"], "takeover")
        self.assertEqual(r["clause_id"], "TPI-1")
        self.assertEqual(s.findings()["distinct_bugs"], 1)
        # never mutate the global alphabet
        self.assertNotIn("magic_link", ACTIONS)

    def test_register_action_validates_effect(self):
        from tpihunter.mcp_tools import HuntSession
        self.assertFalse(HuntSession().register_action("x", "not-an-effect")["ok"])

    def test_distinct_trigger_verbs_are_separate_bugs(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target="mock-vulnerable")
        s.register_action("magic_link", "raise", needs_control=True)
        s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
        s.run_probe([["attacker", "register"], ["victim", "magic_link"]])
        f = s.findings()
        # both are TPI-1 laundering, but via different flows -> two distinct findings
        self.assertEqual(f["distinct_bugs"], 2)
        self.assertEqual([b["clause_id"] for b in f["bugs"]], ["TPI-1", "TPI-1"])
        repros = " ".join(b["minimal_repro"] for b in f["bugs"])
        self.assertIn("sso_login", repros)
        self.assertIn("magic_link", repros)

    def test_api_strategist_can_synthesize_actions(self):
        # the LLM strategist declares a new action and a probe using it, in one reply
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}}
        reply = json.dumps({
            "new_actions": [{"id": "magic_link", "effect": "raise",
                             "requires": [], "needs_control": True}],
            "probes": [{"steps": [["attacker", "register"], ["victim", "magic_link"]]}],
        })
        hunter = AgentHunter(lambda: MockAdapter(patched=True, control=control),
                             attacker, victim, EMAIL, budget=20)
        res = hunter.hunt(LLMStrategist(lambda _p: reply, max_rounds=1))
        self.assertEqual([b.clause_id for b in res.bugs], ["TPI-1"])


class TestRicherParams(unittest.TestCase):
    """Synthesized actions can take params beyond the implicit email — a code, an invite
    token, or a SECOND identifier (a recovery/secondary email) — so a flow the agent can
    only *name* under email-only params can now actually be *driven*."""

    ALIAS_ACTIONS = (
        ("add_alias", "seed", ["register"]),
        ("alias_login", "raise", ["add_alias"]),
    )
    ALIAS_PROBE = [["attacker", "register"], ["attacker", "add_alias"],
                   ["victim", "sso_login"], ["attacker", "alias_login"]]

    def _session_with_alias(self, target="mock-patched"):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target=target)
        for aid, eff, req in self.ALIAS_ACTIONS:
            self.assertTrue(s.register_action(aid, eff, requires=req, needs_control=True,
                                              params={"alias": "{alias}"})["ok"])
        return s

    def test_recovery_email_flow_needs_a_second_identifier(self):
        # on patched, the rebind fix forgot the recovery-email data; only a probe that can
        # pass the non-email identifier reaches it
        s = self._session_with_alias()
        r = s.run_probe(self.ALIAS_PROBE)
        self.assertEqual(r["severity"], "takeover")
        self.assertEqual(r["clause_id"], "TPI-1")
        f = s.findings()
        self.assertEqual(f["distinct_bugs"], 1)
        repro = f["bugs"][0]["minimal_repro"]
        self.assertIn("add_alias", repro)
        self.assertIn("alias_login", repro)   # the second-identifier login is causal

    def test_oracle_discriminates_when_alias_is_revoked(self):
        # the fix control: dropping the alias on rebind closes the bug -> SAFE
        from tpihunter.enumerator import (ActionSpec, Effect, make_candidate, recovery_alias)
        attacker, victim = _principals()
        specs = dict(ACTIONS)
        specs["add_alias"] = ActionSpec("add_alias", Effect.SEED, requires=("register",),
                                        needs_control=True, params=(("alias", "{alias}"),))
        specs["alias_login"] = ActionSpec("alias_login", Effect.RAISE, requires=("add_alias",),
                                          needs_control=True, params=(("alias", "{alias}"),))
        merged = (("attacker", "register"), ("attacker", "add_alias"),
                  ("victim", "sso_login"), ("attacker", "alias_login"))
        control = {victim.name: {EMAIL}, attacker.name: {recovery_alias("attacker")}}
        effects = {n: sp.effect.value for n, sp in specs.items()}
        for revoke, expect in ((False, "takeover"), (True, "safe")):
            a = MockAdapter(patched=True, control=control, revoke_aliases=revoke)
            cand = make_candidate(merged, attacker, victim, EMAIL, specs)
            v = run_plan(a, cand.plan, AtoOracle(a, attacker, victim, effects=effects))[0]
            self.assertEqual(v.severity.value, expect)

    def test_param_template_renders_role_aware_alias(self):
        # {alias} renders to a recovery email the acting ROLE controls (a distinct identifier)
        from tpihunter.enumerator import _render_param, recovery_alias
        self.assertEqual(_render_param("{alias}", email=EMAIL, role="attacker"),
                         recovery_alias("attacker"))
        self.assertNotEqual(recovery_alias("attacker"), EMAIL)
        # {email} and a literal both resolve as expected
        self.assertEqual(_render_param("{email}", email=EMAIL, role="attacker"), EMAIL)
        self.assertEqual(_render_param("code-1234", email=EMAIL, role="victim"), "code-1234")

    def test_dispatch_drops_implicit_email_for_verbs_that_reject_it(self):
        # the generic dispatch filters params to what the method accepts, so a verb taking
        # `alias` (not `email`) still runs despite every step carrying the implicit {email}
        from tpihunter.harness import execute_action
        from tpihunter.enumerator import recovery_alias
        attacker, _ = _principals()
        a = MockAdapter(patched=False, control={attacker.name: {recovery_alias("attacker")}})
        a.register(attacker, EMAIL, "AttackerPw!1")
        obs = execute_action(a, attacker, "add_alias",
                             {"email": EMAIL, "alias": recovery_alias("attacker")})
        self.assertTrue(obs.ok)   # did not raise TypeError on the surplus email kwarg

    def test_register_action_rejects_malformed_params(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession()
        self.assertFalse(s.register_action("x", "seed", params=12345)["ok"])   # not a mapping/list

    def test_api_strategist_synthesizes_action_with_params(self):
        # the API path: the model declares an action WITH a non-email param and a probe using it
        from tpihunter.enumerator import recovery_alias
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}, attacker.name: {recovery_alias("attacker")}}
        reply = json.dumps({
            "new_actions": [
                {"id": "add_alias", "effect": "seed", "requires": ["register"],
                 "needs_control": True, "params": {"alias": "{alias}"}},
                {"id": "alias_login", "effect": "raise", "requires": ["add_alias"],
                 "needs_control": True, "params": {"alias": "{alias}"}},
            ],
            "probes": [{"steps": self.ALIAS_PROBE}],
        })
        hunter = AgentHunter(lambda: MockAdapter(patched=True, control=control),
                             attacker, victim, EMAIL, budget=20)
        res = hunter.hunt(LLMStrategist(lambda _p: reply, max_rounds=1))
        self.assertEqual([b.clause_id for b in res.bugs], ["TPI-1"])


class TestSituationalAwareness(unittest.TestCase):
    """M16: the agent gets diagnostic reason codes, a coverage map, and a principled stop, so it
    reasons about where it has looked instead of burning probes (live: requests) on settled ground."""

    def _hunter(self, patched=False):
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}}
        return AgentHunter(lambda: MockAdapter(patched=patched, control=control),
                           attacker, victim, EMAIL, budget=300)

    def test_enumerator_reports_coverage_and_stop(self):
        res = self._hunter().hunt(EnumeratorStrategist())
        self.assertEqual(res.stop_reason, "strategist_stopped")
        self.assertIsNotNone(res.coverage)
        self.assertEqual(res.coverage.distinct_bugs, 2)
        self.assertEqual(res.coverage.frontier_remaining, 0)      # fired the whole known space
        self.assertEqual(sorted(res.coverage.clauses_found), ["TPI-1", "TPI-4"])

    def test_patience_stops_when_a_round_adds_no_new_bug(self):
        replies = [
            json.dumps({"probes": [{"steps": [["attacker", "register"], ["victim", "sso_login"]]}]}),
            json.dumps({"probes": [{"steps": [["attacker", "register"], ["attacker", "login"],
                                              ["victim", "sso_login"]]}]}),
            json.dumps({"probes": [{"steps": [["victim", "sso_login"], ["attacker", "register"]]}]}),
        ]
        box = {"i": 0}

        def complete(_p):
            r = replies[min(box["i"], len(replies) - 1)]
            box["i"] += 1
            return r
        res = self._hunter().hunt(LLMStrategist(complete, max_rounds=5), patience=1)
        self.assertEqual(res.stop_reason, "patience")
        self.assertEqual(res.probes_used, 2)          # round 3 never runs
        self.assertEqual(len(res.bugs), 1)
        self.assertEqual(res.coverage.distinct_bugs, 1)

    def test_reason_codes_via_huntsession(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target="mock-vulnerable")
        self.assertEqual(s.run_probe([["attacker", "register"], ["victim", "sso_login"]])["reason"],
                         "new_bug")
        self.assertEqual(s.run_probe([["attacker", "register"], ["victim", "reset_request"],
                                      ["victim", "reset_consume"]])["reason"], "new_bug")
        # a padded second path to the SAME TPI-1 bug -> duplicate, not a new distinct bug
        dup = s.run_probe([["attacker", "register"], ["attacker", "login"], ["victim", "sso_login"]])
        self.assertEqual(dup["reason"], "duplicate")
        self.assertFalse(dup["is_new_takeover"])
        # a registered verb the target does not implement -> unbound_action
        s.register_action("device_pair", "raise")
        self.assertEqual(
            s.run_probe([["attacker", "register"], ["victim", "device_pair"]])["reason"],
            "unbound_action")

    def test_enforced_reason_on_patched(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target="mock-patched")
        r = s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
        self.assertEqual(r["severity"], "safe")
        self.assertEqual(r["reason"], "enforced")     # ran fully, target revoked -> secure

    def test_coverage_tool_reports_progress(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target="mock-vulnerable")
        base = s.coverage()["frontier_remaining"]
        s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
        s.run_probe([["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]])
        cov = s.coverage()
        self.assertEqual(cov["distinct_bugs"], 2)
        self.assertEqual(sorted(cov["clauses_found"]), ["TPI-1", "TPI-4"])
        self.assertLess(cov["frontier_remaining"], base)   # probing consumed known-alphabet frontier
        self.assertIn("distinct", cov["summary"])


class TestRevocationMatrix(unittest.TestCase):
    def _factory(self, patched, revokes, **kw):
        owner = Principal("owner")
        control = {owner.name: {"owner@corp.example"}}
        return lambda: MockAdapter(patched=patched, control=control, revokes=revokes, **kw)

    def _matrix(self):
        from tpihunter.matrix import RevocationMatrix, default_mints, default_mutations
        owner = Principal("owner")
        return owner, RevocationMatrix(owner, default_mints("owner@corp.example"),
                                       default_mutations("owner@corp.example"))

    def test_patched_target_still_leaks_via_logout_and_factor(self):
        # a 'patched' target: sessions fixed for reset/email-change, but two holes remain —
        # logout still leaks the session, and an enrolled factor outlives a password reset
        from tpihunter.matrix import Survival
        owner, matrix = self._matrix()
        results = matrix.run(self._factory(patched=True, revokes=set()))
        self.assertEqual(results[("password_session", "logout")].survival, Survival.SURVIVED)
        self.assertEqual(results[("password_session", "password_reset")].survival, Survival.REVOKED)
        self.assertEqual(results[("password_session", "email_change")].survival, Survival.REVOKED)
        # the crown-jewel cell: a passkey survives the victim's password reset
        self.assertEqual(results[("passkey_factor", "password_reset")].survival, Survival.SURVIVED)
        # ...and a passkey surviving a logout is NOT a finding (logout need not revoke factors)
        self.assertEqual(results[("passkey_factor", "logout")].survival, Survival.NOT_APPLICABLE)
        findings = matrix.findings(results)
        self.assertEqual(len(findings), 3)                 # 2 session×logout + 1 factor×reset
        self.assertTrue(all(f.clause_id == "TPI-4" for f in findings))

    def test_factor_not_a_finding_when_not_obliged(self):
        from tpihunter.matrix import Survival
        owner, matrix = self._matrix()
        results = matrix.run(self._factory(patched=True, revokes=set()))
        na = results[("passkey_factor", "logout")]
        self.assertEqual(na.survival, Survival.NOT_APPLICABLE)
        self.assertFalse(na.is_finding)            # measured, but never a finding

    def test_full_revocation_is_clean(self):
        from tpihunter.matrix import Survival
        owner, matrix = self._matrix()
        results = matrix.run(self._factory(patched=True, revokes={"logout"},
                                           revoke_factors={"reset_consume"}))
        self.assertEqual(matrix.findings(results), [])
        self.assertTrue(all(v.survival in (Survival.REVOKED, Survival.NOT_APPLICABLE)
                            for v in results.values()))

    def test_cell_negative_control_guards_false_positive(self):
        # if present_binding accepted anything, the cell must refuse to call it a finding
        from tpihunter.matrix import run_cell, Survival, default_mints, default_mutations
        owner = Principal("owner")
        control = {owner.name: {"owner@corp.example"}}

        class BrokenAdapter(MockAdapter):
            def present_binding(self, handle, plane=None):
                from tpihunter.types import Observation
                return Observation(True, identity="owner@corp.example")  # accepts everything

        mint = default_mints("owner@corp.example")[0]
        mutation = default_mutations("owner@corp.example")[0]
        v = run_cell(lambda: BrokenAdapter(patched=True, control=control),
                     mint, mutation, owner)
        self.assertEqual(v.survival, Survival.INCONCLUSIVE)

    def test_huntsession_exposes_matrix(self):
        from tpihunter.mcp_tools import HuntSession
        m = HuntSession(target="mock-patched").revocation_matrix()
        # 2 session×logout leaks + 1 factor×reset leak
        self.assertEqual(m["laundering_cells"], 3)
        self.assertIn("SURVIVED", m["rendered"])
        self.assertTrue(any("passkey_factor" in f["mint"] for f in m["findings"]))

    def test_cross_plane_split_is_detected(self):
        # logout revokes only the plane it is issued on; the binding lives on another
        from tpihunter.matrix import Survival
        owner, matrix = self._matrix()
        factory = lambda: MockAdapter(patched=True, control={owner.name: {"owner@corp.example"}},
                                      planes=("auth", "mts"), revokes={"logout"},
                                      plane_local={"logout"})
        results = matrix.run(factory)
        cell = results[("password_session", "logout")]
        self.assertEqual(cell.survival, Survival.SPLIT)
        self.assertEqual(cell.per_plane["mts"], Survival.REVOKED)
        self.assertEqual(cell.per_plane["auth"], Survival.SURVIVED)
        self.assertEqual(cell.clause_id, "TPI-4")
        self.assertTrue(cell.is_finding)
        # the reset column is clean for sessions (global revoke) but the factor still leaks
        self.assertEqual(results[("password_session", "password_reset")].survival, Survival.REVOKED)
        self.assertEqual(results[("passkey_factor", "password_reset")].survival, Survival.SURVIVED)

    def test_plane_split_target_via_huntsession(self):
        from tpihunter.mcp_tools import HuntSession
        m = HuntSession(target="mock-plane-split").revocation_matrix()
        # 2 session×logout SPLITs + 1 factor×reset SURVIVED
        self.assertEqual(m["laundering_cells"], 3)
        self.assertIn("SPLIT", m["rendered"])
        self.assertTrue(any("plane-local" in f["note"] for f in m["findings"]))

    def test_global_revocation_across_planes_is_clean(self):
        from tpihunter.matrix import Survival
        owner, matrix = self._matrix()
        factory = lambda: MockAdapter(patched=True, control={owner.name: {"owner@corp.example"}},
                                      planes=("auth", "mts"), revokes={"logout"},
                                      revoke_factors={"reset_consume"})   # sessions + factors, not plane_local
        results = matrix.run(factory)
        self.assertTrue(all(v.survival in (Survival.REVOKED, Survival.NOT_APPLICABLE)
                            for v in results.values()))

    def test_survived_cell_renders_as_report(self):
        from tpihunter.matrix import RevocationMatrix, default_mints, default_mutations
        from tpihunter.report import revocation_report
        owner = Principal("owner")
        control = {owner.name: {"owner@corp.example"}}
        matrix = RevocationMatrix(owner, default_mints("owner@corp.example"),
                                  default_mutations("owner@corp.example"))
        res = matrix.run(lambda: MockAdapter(patched=True, control=control))
        rep = revocation_report(matrix.findings(res)[0], email="owner@corp.example")
        self.assertEqual(rep.clause_id, "TPI-4")
        md = rep.to_markdown()
        self.assertIn("single account you own", md)   # mode-aware preamble
        self.assertIn("Remediation", md)


class TestReport(unittest.TestCase):
    def _session_with_bugs(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession(target="mock-vulnerable")
        s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
        s.run_probe([["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]])
        return s

    def test_markdown_report_has_key_sections(self):
        md = self._session_with_bugs().report("markdown")["content"]
        for token in ("Steps to reproduce", "Evidence", "Root cause", "Remediation",
                      "TPI-1", "TPI-4", "attacker", "victim", "canary"):
            self.assertIn(token, md)
        # the laundered proof (root cause) is surfaced
        self.assertIn("P<victim", md)

    def test_json_report_is_valid_and_structured(self):
        out = self._session_with_bugs().report("json")
        data = json.loads(out["content"])
        self.assertEqual(data["distinct_bugs"], 2)
        clauses = sorted(b["tpi_clause"] for b in data["bugs"])
        self.assertEqual(clauses, ["TPI-1", "TPI-4"])
        for b in data["bugs"]:
            self.assertTrue(b["steps_to_reproduce"])
            self.assertTrue(b["evidence"])
            self.assertTrue(b["remediation"])
            self.assertEqual(b["severity"], "takeover")

    def test_build_report_reproduces_the_bug(self):
        from tpihunter.report import build_report, make_run_fn
        attacker, victim = _principals()
        control = {victim.name: {EMAIL}}
        cands = enumerate_plans(attacker, victim, EMAIL)
        vuln = _vuln_verdict_fn(attacker, victim)
        clusters = deduplicate(cands, attacker, victim, EMAIL, vuln)
        run_fn = make_run_fn(lambda: MockAdapter(patched=False, control=control), attacker, victim)
        for cl in clusters:
            r = build_report(cl, attacker=attacker, victim=victim, email=EMAIL, run_fn=run_fn)
            self.assertEqual(r.severity, "takeover")
            self.assertEqual(r.clause_id, cl.clause_id)
            self.assertTrue(r.steps and r.evidence)
            self.assertIn("Enforce", r.to_markdown())

    def test_empty_bundle_is_graceful(self):
        from tpihunter.report import bundle_to_markdown
        self.assertIn("No distinct bugs", bundle_to_markdown([]))


class TestLLM(unittest.TestCase):
    def test_complete_returns_text_and_sends_opus(self):
        from tpihunter.llm import anthropic_complete
        fake = _FakeClient('[{"steps": [["attacker","register"]]}]')
        out = anthropic_complete("hi", client=fake)
        self.assertEqual(out, '[{"steps": [["attacker","register"]]}]')
        # defaults: Opus-tier model + adaptive thinking
        self.assertEqual(fake.messages.last_kwargs["model"], "claude-opus-5")
        self.assertEqual(fake.messages.last_kwargs["thinking"], {"type": "adaptive"})

    def test_refusal_raises(self):
        from tpihunter.llm import anthropic_complete, RefusalError
        fake = _FakeClient("", stop_reason="refusal")
        with self.assertRaises(RefusalError):
            anthropic_complete("hi", client=fake)

    def test_live_wiring_finds_bugs_with_fake_client(self):
        # the whole path: fake model -> complete_fn -> LLMStrategist -> AgentHunter
        from tpihunter.llm import make_complete_fn
        attacker, victim = _principals()
        fake = _FakeClient(_two_probes(""))
        complete_fn = make_complete_fn(client=fake)
        hunter = AgentHunter(_adapter_factory(victim), attacker, victim, EMAIL, budget=50)
        res = hunter.hunt(LLMStrategist(complete_fn, max_rounds=1))
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])
        self.assertEqual(res.probes_used, 2)


# =========================================================================== #
#  Safety: the oracle's controls, the alphabet's input validation, and the
#  engagement policy. These are the invariants that decide whether this tool is
#  fit to point at something real.
# =========================================================================== #
SHARED = "ops-shared@corp.example"


def _shared_probe(merged, control, patched=False, **oracle_kw):
    from tpihunter.enumerator import make_candidate
    attacker, victim = _principals()
    a = MockAdapter(patched=patched, control=control)
    cand = make_candidate(merged, attacker, victim, SHARED)
    return run_plan(a, cand.plan,
                    AtoOracle(a, attacker, victim, resource=SHARED, **oracle_kw))[0]


class TestOracleControls(unittest.TestCase):
    """The load-bearing invariant is 'never a false takeover'. Before these controls it
    was false: a legitimately shared account, or two principals wired to one context,
    graded TAKEOVER at 0.90-0.99 on zero adversarial steps. The mirror-image defect was
    just as bad: a probe whose canary never got planted graded SAFE at 0.95, which is how
    an agent is taught a surface is secure when it was never measured."""

    def test_co_owner_is_not_a_takeover(self):
        # both principals prove control of the identifier at the IdP: a shared ops mailbox,
        # a family plan, a tenant seat. The attacker's access has justifying provenance.
        attacker, victim = _principals()
        v = _shared_probe((("attacker", "sso_login"), ("victim", "sso_login")),
                          {victim.name: {SHARED}, attacker.name: {SHARED}})
        self.assertEqual(v.severity.value, "safe")
        self.assertEqual(v.withheld, "attacker_proved_control")

    def test_confirmation_does_not_rescue_a_systematic_false_positive(self):
        # M13 confirmation defends against transient noise; a shared account reproduces on
        # every pass, so only the attribution guard can catch it.
        attacker, victim = _principals()
        for confirm in (0, 4):
            v = _shared_probe((("attacker", "sso_login"), ("victim", "sso_login")),
                              {victim.name: {SHARED}, attacker.name: {SHARED}}, confirm=confirm)
            self.assertNotEqual(v.severity.value, "takeover", f"confirm={confirm}")

    def test_principals_sharing_one_context_is_void_not_a_finding(self):
        from tpihunter.adapter import Trace
        attacker, victim = _principals()
        a = MockAdapter(patched=False, control={victim.name: {SHARED}})
        a.sso_login(victim, SHARED)
        a.sess[attacker.name] = a.sess[victim.name]      # one session, two "principals"
        o = AtoOracle(a, attacker, victim, resource=SHARED).arm(Trace())
        v = o.plant().assess(Trace())
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "principals_not_independent")

    def test_access_with_no_attacker_action_is_unattributable(self):
        from tpihunter.adapter import Trace
        attacker, victim = _principals()
        a = MockAdapter(patched=False, control={victim.name: {SHARED}, attacker.name: {SHARED}})
        a.sso_login(victim, SHARED)
        a.sso_login(attacker, SHARED)
        o = AtoOracle(a, attacker, victim, resource=SHARED)
        o.arm(); o.plant()
        v = o.assess(Trace())                            # nothing in the trace to blame
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "no_attacker_action")

    def test_unplanted_canary_is_inconclusive_not_safe(self):
        # the POSITIVE control: the victim never establishes a session, so no canary exists
        # and every comparison is vacuous. "safe" here would be a silent false negative.
        attacker, victim = _principals()
        v = _shared_probe((("attacker", "register"), ("victim", "reset_request")),
                          {victim.name: {SHARED}})
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "canary_not_planted")
        self.assertFalse(v.controls["canary_planted"])

    def test_unscoped_read_endpoint_cannot_fake_a_by_ref_read(self):
        # the NEGATIVE control: a target that answers ANY reference would otherwise hand the
        # oracle a by-reference canary read for free.
        from tpihunter.adapter import Trace
        from tpihunter.types import Observation
        attacker, victim = _principals()

        class UnscopedReads(MockAdapter):
            def read_marker(self, p, ref=None):
                if ref is None:
                    return super().read_marker(p)
                acc = self.t.accounts.get(ref)
                return Observation(True, extracted={"value": acc.marker if acc else "anything"})

        a = UnscopedReads(patched=True, control={victim.name: {SHARED}})
        a.sso_login(victim, SHARED)
        o = AtoOracle(a, attacker, victim, resource=SHARED)
        o.arm(Trace()); o.plant()
        v = o.assess(Trace())
        self.assertFalse(v.controls["ref_reads_scoped"])
        self.assertFalse([e for e in v.evidence if e.kind == "canary_read" and e.strength == 2])

    def test_real_laundering_still_fires_at_full_confidence(self):
        # the controls must not cost recall: the bug the tool exists for is untouched
        attacker, victim = _principals()
        v = _shared_probe((("attacker", "register"), ("victim", "sso_login")),
                          {victim.name: {SHARED}})
        self.assertEqual(v.severity.value, "takeover")
        self.assertEqual(v.clause_id, "TPI-1")
        self.assertIsNone(v.withheld)
        self.assertGreaterEqual(v.confidence, 0.99)

    def test_destructive_write_probe_is_off_by_default(self):
        from tpihunter.adapter import Trace
        attacker, victim = _principals()
        a = MockAdapter(patched=False, control={victim.name: {SHARED}})
        a.register(attacker, SHARED, "x")
        a.sso_login(victim, SHARED)
        o = AtoOracle(a, attacker, victim, resource=SHARED)
        o.arm(Trace()); o.plant()
        v = o.assess(Trace())
        self.assertFalse([e for e in v.evidence if e.kind == "canary_write"])
        self.assertEqual(a.t.accounts[o._victim_ref].marker, o._canary)   # untouched

    def test_write_probe_when_enabled_proves_mutation_and_restores(self):
        from tpihunter.adapter import Trace
        attacker, victim = _principals()
        a = MockAdapter(patched=False, control={victim.name: {SHARED}})
        a.register(attacker, SHARED, "x")
        a.sso_login(victim, SHARED)
        o = AtoOracle(a, attacker, victim, resource=SHARED, mutate=True)
        o.arm(Trace()); o.plant()
        v = o.assess(Trace())
        self.assertTrue([e for e in v.evidence if e.kind == "canary_write"])
        self.assertTrue(v.controls["write_probe_restored"])
        self.assertEqual(a.t.accounts[o._victim_ref].marker, o._canary)   # restored
        self.assertNotIn(o._canary, o._stamp)     # the ground truth is never what we write


class TestSynthesizedActionValidation(unittest.TestCase):
    """A synthesized action name becomes getattr(adapter, name) at run time, and the name
    is chosen by a model reading the target's own output. It is untrusted input."""

    BAD = ["__init__", "_inner", "Register", "a.b", "", "x" * 64, "register-action"]

    def test_register_action_rejects_unsafe_ids(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession()
        for aid in self.BAD:
            r = s.register_action(aid, "seed")
            self.assertFalse(r["ok"], f"accepted {aid!r}")
            self.assertNotIn(aid, s.specs)

    def test_register_action_rejects_harness_reserved_ids(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession()
        for aid in ("arm", "plant", "assess", "capture_binding", "whoami", "write_marker"):
            self.assertFalse(s.register_action(aid, "seed")["ok"], f"accepted {aid!r}")

    def test_register_action_still_accepts_a_real_flow(self):
        from tpihunter.mcp_tools import HuntSession
        s = HuntSession()
        self.assertTrue(s.register_action("magic_link", "raise", needs_control=True)["ok"])

    def test_llm_strategist_drops_unsafe_ids(self):
        attacker, victim = _principals()
        state = HuntState(dict(ACTIONS), attacker, victim, EMAIL)
        LLMStrategist.parse_proposals(
            LLMStrategist(lambda _p: ""),
            json.dumps({"new_actions": [{"id": "__init__", "effect": "seed"},
                                        {"id": "magic_link", "effect": "raise"}],
                        "probes": []}), state)
        self.assertNotIn("__init__", state.specs)
        self.assertIn("magic_link", state.specs)

    def test_dispatch_contains_a_non_observation_return(self):
        # defence in depth: if a name ever does reach getattr, a foreign return value is
        # contained here rather than crashing the loop far from the cause
        from tpihunter.harness import execute_action
        attacker, _ = _principals()

        class Odd(MockAdapter):
            def weird(self, p):
                return "not an Observation"

        obs = execute_action(Odd(), attacker, "weird", {})
        self.assertFalse(obs.ok)
        self.assertIn("not an alphabet action", obs.note)


class TestEngagementPolicy(unittest.TestCase):
    """Rules of engagement enforced per action, so the common accidents are impossible
    rather than unlikely."""

    EMAIL = "pentest-v@acme.example"

    def _policy(self, **kw):
        from tpihunter.policy import EngagementPolicy
        base = dict(name="acme", authorized_by="security@acme.example / SEC-1421",
                    identifiers=frozenset({self.EMAIL}),
                    hosts=frozenset({"staging.acme.example"}),
                    allow_credential_change=True)
        base.update(kw)
        return EngagementPolicy(**base)

    def _guarded(self, policy=None, **adapter_kw):
        from tpihunter.policy import guard
        victim = Principal("victim")
        return guard(MockAdapter(control={victim.name: {self.EMAIL}}, **adapter_kw),
                     policy or self._policy())

    def test_preflight_names_what_is_missing(self):
        from tpihunter.policy import EngagementPolicy
        problems = EngagementPolicy(name="x").preflight()
        self.assertTrue(any("authorized_by" in p for p in problems))
        self.assertTrue(any("identifiers" in p for p in problems))
        self.assertEqual(self._policy().preflight(), [])

    def test_guard_refuses_to_build_on_an_unready_policy(self):
        from tpihunter.policy import EngagementPolicy, ScopeViolation, guard
        with self.assertRaises(ScopeViolation):
            guard(MockAdapter(), EngagementPolicy(name="x"))

    def test_out_of_scope_identifier_raises_even_when_passed_positionally(self):
        # the alphabet is dispatched positionally; a guard that only read kwargs would
        # check nothing on exactly the calls that matter
        from tpihunter.policy import ScopeViolation
        g = self._guarded()
        with self.assertRaises(ScopeViolation):
            g.register(Principal("attacker"), "ceo@acme.example", "pw")

    def test_in_scope_hunt_still_finds_the_bug_and_is_audited(self):
        from tpihunter.enumerator import make_candidate
        attacker, victim = _principals()
        g = self._guarded(patched=False)
        plan = make_candidate((("attacker", "register"), ("victim", "sso_login")),
                              attacker, victim, self.EMAIL).plan
        v = run_plan(g, plan, AtoOracle(g, attacker, victim, resource=self.EMAIL))[0]
        self.assertEqual(v.severity.value, "takeover")
        self.assertTrue(g.actions_used > 0)
        self.assertEqual(len(g.audit.records), g.actions_used)

    def test_credential_change_is_gated(self):
        g = self._guarded(self._policy(allow_credential_change=False))
        obs = g.reset_consume(Principal("victim"), self.EMAIL, "pw")
        self.assertFalse(obs.ok)
        self.assertIn("engagement policy", obs.note)

    def test_cross_principal_write_is_gated(self):
        g = self._guarded()
        self.assertFalse(g.write_marker(Principal("attacker"), "x", ref="acct_1").ok)
        g2 = self._guarded(self._policy(allow_cross_principal_write=True))
        g2.write_marker(Principal("attacker"), "x", ref="acct_1")   # permitted: no refusal note
        self.assertNotIn("refused", [r.outcome for r in g2.audit.records])

    def test_budget_fails_closed_and_counts_reads(self):
        from tpihunter.policy import BudgetExhausted
        g = self._guarded(self._policy(max_actions=3))
        with self.assertRaises(BudgetExhausted):
            for _ in range(10):
                g.whoami(Principal("victim"))
        self.assertEqual(g.actions_used, 3)

    def test_dry_run_executes_nothing(self):
        g = self._guarded(self._policy(dry_run=True))
        g.register(Principal("attacker"), self.EMAIL, "pw")
        g.sso_login(Principal("victim"), self.EMAIL)
        self.assertEqual(g.audit.counts(), {"dry-run": 2})
        self.assertEqual(len(g._inner.t.accounts), 0)

    def test_an_exactly_listed_host_does_not_admit_its_subdomains(self):
        # A programme lists `example.com` and `*.example.com` as different entries.
        # Admitting subdomains of an exact entry grants more than the programme did —
        # this is the rule that let api.accounts.nintendo.com through on a real scope.
        p = self._policy()      # hosts = {"staging.acme.example"}, exact
        self.assertIsNone(p.check_url("https://staging.acme.example/login"))
        for bad in ("https://api.staging.acme.example/login", "https://evil.example/",
                    "https://notstaging.acme.example/",
                    "https://staging.acme.example.evil.test/", "file:///etc/passwd"):
            self.assertIsNotNone(p.check_url(bad), bad)

    def test_a_wildcard_entry_admits_subdomains_but_not_the_apex(self):
        p = self._policy(hosts=frozenset({"*.acme.example"}))
        self.assertIsNone(p.check_url("https://staging.acme.example/login"))
        self.assertIsNone(p.check_url("https://a.b.acme.example/login"))
        for bad in ("https://acme.example/", "https://acme.example.evil.test/"):
            self.assertIsNotNone(p.check_url(bad), bad)

    def test_guard_is_transparent_to_the_hunt(self):
        # the policy layer must not change what the loop finds, only what it is allowed to do
        from tpihunter.policy import guard
        attacker, victim = _principals()
        policy = self._policy(max_actions=100_000)

        def factory():
            return guard(MockAdapter(patched=False, control={victim.name: {self.EMAIL}}), policy)

        res = AgentHunter(factory, attacker, victim, self.EMAIL, budget=300).hunt(
            EnumeratorStrategist())
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])

    def test_synthesized_verb_dispatches_through_the_guard(self):
        # the guard must keep the inner signature visible, or a verb taking `alias` and not
        # `email` would break on the implicit email every step carries
        from tpihunter.enumerator import recovery_alias
        from tpihunter.harness import execute_action
        from tpihunter.policy import EngagementPolicy, guard
        attacker = Principal("attacker")
        alias = recovery_alias("attacker")
        g = guard(MockAdapter(control={attacker.name: {alias}}),
                  EngagementPolicy(name="a", authorized_by="x",
                                   identifiers=frozenset({self.EMAIL, alias}),
                                   allow_credential_change=True))
        g.register(attacker, self.EMAIL, "pw")
        obs = execute_action(g, attacker, "add_alias", {"email": self.EMAIL, "alias": alias})
        self.assertTrue(obs.ok)

    def test_audit_redacts_credentials(self):
        g = self._guarded()
        g.register(Principal("attacker"), self.EMAIL, "hunter2-correct-horse")
        rendered = g.audit.render()
        self.assertNotIn("hunter2-correct-horse", rendered)
        self.assertIn("redacted", rendered)


class TestRedaction(unittest.TestCase):
    def test_masks_secret_shapes(self):
        from tpihunter.redact import redact
        for secret, text in (
                ("b3f1c2d4e5f60718293a4b5c6d7e8f90",
                 "Reset: http://t/reset?token=b3f1c2d4e5f60718293a4b5c6d7e8f90"),
                ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghij",
                 "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghij"),
                ("s3cret-value", '{"password": "s3cret-value"}')):
            out = redact(text)
            self.assertNotIn(secret, out)
            self.assertIn("redacted", out)

    def test_leaves_identifiers_readable(self):
        from tpihunter.redact import redact
        for text in ("attacker registered victim@corp.example (email still 'claimed')",
                     "P<victim, email:victim@corp.example, idp>", "acct_1", "TPI-4"):
            self.assertEqual(redact(text), text)

    def test_recurses_and_is_idempotent(self):
        from tpihunter.redact import redact
        once = redact({"a": ["token=b3f1c2d4e5f60718293a4b5c6d7e8f90"], "b": 3})
        self.assertNotIn("b3f1c2d4e5f60718293a4b5c6d7e8f90", str(once))
        self.assertEqual(redact(once), once)
        self.assertEqual(once["b"], 3)

    def test_report_bundle_scrubs_a_leaked_token(self):
        from tpihunter.report import build_bundle
        from tpihunter.types import Observation
        attacker, victim = _principals()
        token = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

        class Chatty(MockAdapter):
            def sso_login(self, p, email):
                obs = super().sso_login(p, email)
                obs.note += f" (set-cookie: session={token})"
                return obs

        cands = enumerate_plans(attacker, victim, EMAIL)
        fired = [c for c in cands
                 if _verdict_via(Chatty, c.plan, attacker, victim).severity.value == "takeover"]
        clusters = deduplicate(fired[:3], attacker, victim, EMAIL,
                               lambda pl: _verdict_via(Chatty, pl, attacker, victim))
        reports = build_bundle(clusters, attacker=attacker, victim=victim, email=EMAIL,
                               run_fn=lambda pl: _run_via(Chatty, pl, attacker, victim))
        doc = "\n".join(r.to_markdown() for r in reports)
        self.assertNotIn(token, doc)


def _run_via(cls, plan, attacker, victim):
    a = cls(patched=False, control={victim.name: {EMAIL}})
    return run_plan(a, plan, AtoOracle(a, attacker, victim, resource=EMAIL))


def _verdict_via(cls, plan, attacker, victim):
    return _run_via(cls, plan, attacker, victim)[0]


class TestCredentialHygiene(unittest.TestCase):
    """A password literal in source is a password published on GitHub, and after a live
    run it is the password on the account under test."""

    def test_no_credential_this_tool_presents_appears_in_source(self):
        import pathlib
        from tpihunter import creds
        root = pathlib.Path(creds.__file__).parent
        source = "\n".join(f.read_text() for f in root.glob("*.py"))
        for label in ("attacker:account", "victim:account", "owner:account",
                      "attacker:reset", "fallback:seed"):
            self.assertNotIn(creds.password(label), source)

    def test_passwords_are_stable_per_label_and_distinct_across_labels(self):
        from tpihunter import creds
        self.assertEqual(creds.password("attacker:account"), creds.password("attacker:account"))
        self.assertNotEqual(creds.password("attacker:account"), creds.password("victim:account"))
        self.assertGreaterEqual(len(creds.password("x")), 20)

    def test_recovery_alias_is_tagged_and_non_routable(self):
        from tpihunter.enumerator import recovery_alias
        alias = recovery_alias("attacker")
        from tpihunter.creds import session_id
        self.assertIn(session_id(), alias)
        self.assertTrue(alias.endswith(".example"))   # RFC 2606 reserved: cannot resolve


class TestBystanderControl(unittest.TestCase):
    """The diagnosis control. A takeover is not automatically a *provenance* takeover: if an
    account that took no part in the probe reaches the victim's resource just as well, the
    bug is object-level authorization and citing a TPI clause would ship the wrong fix."""

    class FlatIdor(MockAdapter):
        """Correct auth, correct revocation — object reads simply are not scoped to the owner."""
        def read_marker(self, p, ref=None):
            from tpihunter.types import Observation
            if ref is None:
                return super().read_marker(p)
            acc = self.t.accounts.get(ref)
            return Observation(acc is not None, extracted={"value": acc.marker if acc else None})

    def _run(self, cls, merged, patched=True, **oracle_kw):
        from tpihunter.enumerator import make_candidate
        attacker, victim = _principals()
        a = cls(patched=patched, control={victim.name: {EMAIL}})
        return run_plan(a, make_candidate(merged, attacker, victim, EMAIL).plan,
                        AtoOracle(a, attacker, victim, resource=EMAIL, **oracle_kw))[0]

    PROBE = (("attacker", "register"), ("victim", "sso_login"))

    def test_flat_idor_is_not_diagnosed_as_laundering(self):
        v = self._run(self.FlatIdor, self.PROBE)
        self.assertEqual(v.severity.value, "takeover")
        self.assertEqual(v.clause_id, "AUTHZ-1")
        self.assertEqual(v.failure_mode, "authorization")
        self.assertNotIn("TPI", v.clause_id)
        self.assertTrue([e for e in v.evidence if e.kind == "bystander_read"])
        self.assertEqual(v.controls["bystander"], "enrolled and independent")

    def test_real_laundering_is_unaffected_by_the_control(self):
        v = self._run(MockAdapter, self.PROBE, patched=False)
        self.assertEqual(v.clause_id, "TPI-1")
        self.assertFalse([e for e in v.evidence if e.kind == "bystander_read"])
        self.assertEqual(v.controls["bystander"], "enrolled and independent")

    def test_taxonomy_is_not_widened_to_absorb_its_complement(self):
        from tpihunter.clauses import BROAD_AUTHORIZATION, CATALOG, CLAUSES
        self.assertNotIn(BROAD_AUTHORIZATION.id, CLAUSES)   # CLAUSES stays pure TPI
        self.assertIn(BROAD_AUTHORIZATION.id, CATALOG)      # but a verdict still resolves
        self.assertIsNone(BROAD_AUTHORIZATION.mode)         # not one of the three modes

    def test_missing_adapter_support_is_recorded_not_assumed(self):
        class NoBystander(MockAdapter):
            enrol_bystander = None
        v = self._run(NoBystander, self.PROBE, patched=False)
        self.assertIn("unavailable", v.controls["bystander"])
        self.assertEqual(v.clause_id, "TPI-1")       # still detects, just cannot discriminate

    def test_a_bystander_that_is_not_independent_is_refused(self):
        from tpihunter.types import Observation

        class FakeBystander(MockAdapter):
            def enrol_bystander(self, p):
                self.sess[p.name] = self.sess.get("victim")   # the victim's own context
                return Observation(True, identity="whatever")

        v = self._run(FakeBystander, self.PROBE, patched=False)
        self.assertIn("not independent", v.controls["bystander"])
        self.assertEqual(v.clause_id, "TPI-1")

    def test_control_can_be_disabled(self):
        v = self._run(self.FlatIdor, self.PROBE, bystander=None)
        self.assertEqual(v.controls["bystander"], "disabled")
        self.assertNotEqual(v.clause_id, "AUTHZ-1")   # without the control, misdiagnosed

    def test_authz_findings_collapse_to_one_bug_and_report_as_non_tpi(self):
        from tpihunter.report import build_bundle
        attacker, victim = _principals()

        def run(plan):
            a = self.FlatIdor(patched=True, control={victim.name: {EMAIL}})
            return run_plan(a, plan, AtoOracle(a, attacker, victim, resource=EMAIL))

        cands = enumerate_plans(attacker, victim, EMAIL)
        fired = [c for c in cands if run(c.plan)[0].severity.value == "takeover"]
        self.assertGreater(len(fired), 20)
        clusters = deduplicate(fired, attacker, victim, EMAIL, lambda pl: run(pl)[0])
        self.assertEqual([c.clause_id for c in clusters], ["AUTHZ-1"])
        doc = build_bundle(clusters, attacker=attacker, victim=victim, email=EMAIL,
                           run_fn=run)[0].to_markdown()
        self.assertIn("NOT a Trust-Provenance Integrity failure", doc)
        self.assertIn("not the identity lifecycle", doc)


# =========================================================================== #
#  The live path: a target described as data, proved to work, then hunted over
#  real HTTP. These are the tests that say an AI session could use this on
#  something other than the in-memory mock.
# =========================================================================== #
def _live_bits(url):
    from tpihunter.http_mock import engagement_for, profile_for
    from tpihunter.policy import EngagementPolicy
    from tpihunter.profile import TargetProfile
    return (TargetProfile.from_dict(profile_for(url)),
            EngagementPolicy.from_dict(engagement_for(url)))


class TestTargetProfile(unittest.TestCase):
    def test_a_valid_profile_parses_and_describes_itself_without_credentials(self):
        from tpihunter.http_mock import profile_for
        from tpihunter.profile import TargetProfile
        prof = TargetProfile.from_dict(profile_for("http://127.0.0.1:1/"))
        d = prof.describe()
        self.assertEqual(d["session"], "cookie")
        self.assertIn("register", d["actions"])
        self.assertNotIn("password", json.dumps(d).lower())

    def test_every_problem_is_reported_at_once(self):
        from tpihunter.profile import ProfileError, TargetProfile
        with self.assertRaises(ProfileError) as cm:
            TargetProfile.from_dict({"name": "", "base_url": "ftp://x/",
                                     "actions": {}, "oracle": {}})
        text = str(cm.exception)
        for expected in ("name", "base_url", "accounts.victim", "oracle.whoami"):
            self.assertIn(expected, text)

    def test_an_action_path_may_not_leave_the_profiles_origin(self):
        from tpihunter.profile import ProfileError, TargetProfile
        from tpihunter.http_mock import profile_for
        raw = profile_for("http://127.0.0.1:1/")
        raw["actions"]["login"]["path"] = "https://elsewhere.example/api/login"
        with self.assertRaises(ProfileError) as cm:
            TargetProfile.from_dict(raw)
        self.assertIn("path", str(cm.exception))

    def test_unknown_placeholders_are_rejected_not_passed_through(self):
        from tpihunter.profile import ProfileError, TargetProfile
        from tpihunter.http_mock import profile_for
        raw = profile_for("http://127.0.0.1:1/")
        raw["actions"]["login"]["json"]["otp"] = "{secret_from_nowhere}"
        with self.assertRaises(ProfileError) as cm:
            TargetProfile.from_dict(raw)
        self.assertIn("secret_from_nowhere", str(cm.exception))

    def test_rendering_substitutes_values_and_cannot_restructure_a_request(self):
        from tpihunter.profile import render
        body = render({"email": "{email}", "note": "{value}"},
                      {"email": 'a"@x.example', "value": '", "admin": true, "x": "'})
        self.assertEqual(body["email"], 'a"@x.example')
        self.assertNotIn("admin", json.loads(json.dumps(body)))   # still two fields
        self.assertEqual(set(body), {"email", "note"})

    def test_a_regex_extractor_scans_the_whole_response(self):
        # Caught live: the value sat at offset 69,800 of a 74 KiB page and a 64 KiB scan
        # window silently returned nothing, which reads as "the field is empty".
        from tpihunter.live import Response
        from tpihunter.profile import Extract
        body = ("x" * 69_800) + 'obfuscatedId&quot;:&quot;d0f0e3efa65ac9fa&quot;' + ("y" * 4_000)
        ex = Extract("regex", r"obfuscatedId&quot;:&quot;([0-9a-f]{16})")
        self.assertEqual(ex.apply(Response(200, {}, {}, body)), "d0f0e3efa65ac9fa")

    def test_unsettable_headers_and_bad_regexes_are_refused(self):
        from tpihunter.profile import ProfileError, TargetProfile
        from tpihunter.http_mock import profile_for
        raw = profile_for("http://127.0.0.1:1/")
        raw["actions"]["login"]["headers"] = {"Host": "elsewhere.example"}
        raw["channel"]["extract"]["token"] = {"regex": "("}
        with self.assertRaises(ProfileError) as cm:
            TargetProfile.from_dict(raw)
        self.assertIn("Host", str(cm.exception))
        self.assertIn("regex", str(cm.exception))


class TestScopedTransport(unittest.TestCase):
    def test_scope_holds_for_direct_requests_and_for_redirects(self):
        from tpihunter.http_mock import serve
        from tpihunter.live import ScopedTransport
        from tpihunter.policy import AuditLog, ScopeViolation
        with serve() as url:
            _prof, policy = _live_bits(url)
            t = ScopedTransport(policy, AuditLog())
            self.assertEqual(t.send("GET", url + "/api/health", {}, None).status, 200)
            for target in ("http://example.invalid/x",
                           url + "/testing/redirect?to=http://example.invalid/x"):
                with self.assertRaises(ScopeViolation):
                    t.send("GET", target, {}, None)

    def test_budget_fails_closed(self):
        from tpihunter.http_mock import serve
        from tpihunter.live import ScopedTransport
        from tpihunter.policy import AuditLog, BudgetExhausted
        from dataclasses import replace
        with serve() as url:
            _prof, policy = _live_bits(url)
            t = ScopedTransport(replace(policy, max_actions=3), AuditLog())
            with self.assertRaises(BudgetExhausted):
                for _ in range(10):
                    t.send("GET", url + "/api/health", {}, None)
            self.assertEqual(t.requests, 3)

    def test_adapter_refuses_a_profile_the_policy_does_not_cover(self):
        from dataclasses import replace
        from tpihunter.http_mock import serve
        from tpihunter.live import LiveAdapter
        from tpihunter.policy import ScopeViolation
        with serve() as url:
            prof, policy = _live_bits(url)
            with self.assertRaises(ScopeViolation):
                LiveAdapter(prof, replace(policy, identifiers=frozenset({"only@x.example"})))
            with self.assertRaises(ScopeViolation):
                LiveAdapter(prof, replace(policy, hosts=frozenset({"elsewhere.example"})))


class TestLiveHunt(unittest.TestCase):
    """The same bugs, through sockets, cookies and JSON — driven by a profile, not code."""

    def _hunt(self, url, **hunter_kw):
        from tpihunter.http_mock import VICTIM_EMAIL
        from tpihunter.live import live_adapter
        attacker, victim = _principals()
        prof, policy = _live_bits(url)
        hunter = AgentHunter(
            lambda: live_adapter(prof, policy, control={victim.name: {VICTIM_EMAIL}}),
            attacker, victim, VICTIM_EMAIL, budget=300, **hunter_kw)
        return hunter.hunt(EnumeratorStrategist(max_attacker=1, max_victim=2))

    def test_live_path_finds_the_same_bugs_as_the_in_process_path(self):
        from tpihunter.http_mock import serve
        with serve(patched=False) as url:
            res = self._hunt(url)
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])

    def test_the_load_bearing_invariant_holds_over_http(self):
        from tpihunter.http_mock import serve
        with serve(patched=True) as url:
            res = self._hunt(url)
        self.assertEqual(res.bugs, [])

    def test_bystander_control_reclassifies_a_flat_idor_over_http(self):
        from tpihunter.enumerator import make_candidate
        from tpihunter.http_mock import VICTIM_EMAIL, serve
        from tpihunter.live import live_adapter
        attacker, victim = _principals()
        with serve(patched=True, flat_idor=True) as url:
            prof, policy = _live_bits(url)
            a = live_adapter(prof, policy, control={victim.name: {VICTIM_EMAIL}})
            plan = make_candidate((("attacker", "register"), ("victim", "sso_login")),
                                  attacker, victim, VICTIM_EMAIL).plan
            v = run_plan(a, plan, AtoOracle(a, attacker, victim, resource=VICTIM_EMAIL))[0]
        self.assertEqual(v.severity.value, "takeover")
        self.assertEqual(v.clause_id, "AUTHZ-1")


class TestValidateTarget(unittest.TestCase):
    """A profile is not evidence of anything until it has been shown to work."""

    def _validate(self, mutate=lambda d: d, **serve_kw):
        from tpihunter.http_mock import engagement_for, profile_for, serve
        from tpihunter.policy import EngagementPolicy
        from tpihunter.profile import TargetProfile
        from tpihunter.validate import validate_target
        with serve(**serve_kw) as url:
            prof = TargetProfile.from_dict(mutate(profile_for(url)))
            return validate_target(prof, EngagementPolicy.from_dict(engagement_for(url)))

    def _status(self, v, name):
        return next(c.status for c in v.checks if c.name == name)

    def test_a_correct_profile_passes_every_check(self):
        v = self._validate()
        self.assertTrue(v.ready)
        self.assertTrue(all(c.status == "pass" for c in v.checks),
                        [c.name for c in v.checks if c.status != "pass"])
        self.assertTrue(v.artifacts)      # it says what it left behind

    def test_a_wrong_identity_field_blocks_hunting(self):
        def m(d):
            d["oracle"]["whoami"]["extract"]["identity"] = {"json": "no_such_field"}
            return d
        v = self._validate(m)
        self.assertFalse(v.ready)
        self.assertEqual(self._status(v, "identity:victim"), "fail")
        self.assertIn("oracle.whoami.extract.identity",
                      next(c.fix for c in v.checks if c.name == "identity:victim"))

    def test_a_marker_route_that_does_not_round_trip_blocks_hunting(self):
        def m(d):
            d["oracle"]["read_marker"]["path"] = "/api/me"
            return d
        v = self._validate(m)
        self.assertFalse(v.ready)
        self.assertEqual(self._status(v, "canary"), "fail")

    def test_a_broken_channel_warns_but_does_not_block(self):
        def m(d):
            d["channel"]["extract"]["token"] = {"regex": "nomatch=([0-9]+)"}
            return d
        v = self._validate(m)
        self.assertTrue(v.ready)
        self.assertEqual(self._status(v, "channel"), "fail")

    def test_a_target_that_already_leaks_is_reported_as_a_finding(self):
        v = self._validate(flat_idor=True)
        self.assertTrue(v.ready)          # the profile is fine; the target is not
        self.assertEqual(self._status(v, "baseline_scoping"), "fail")
        self.assertIn("AUTHZ-1",
                      next(c.detail for c in v.checks if c.name == "baseline_scoping"))


class TestLiveSessionGating(unittest.TestCase):
    """The trust boundary: the operator authorizes the scope, the agent only describes
    the target, and nothing is hunted until the description has been proved."""

    def _session(self, url, engagement=None):
        import os
        from unittest import mock
        from tpihunter.http_mock import engagement_for
        import json as _json
        import tempfile
        import pathlib as _p
        path = _p.Path(tempfile.mkdtemp()) / "engagement.json"
        path.write_text(_json.dumps(engagement if engagement is not None
                                    else engagement_for(url)))
        with mock.patch.dict(os.environ, {"TPIHUNTER_ENGAGEMENT": str(path)}):
            from tpihunter.mcp_tools import HuntSession
            return HuntSession()

    def test_without_an_engagement_file_no_live_target_is_possible(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {}, clear=True):
            from tpihunter.mcp_tools import HuntSession
            s = HuntSession()
            r = s.set_target({})
            self.assertFalse(r["ok"])
            self.assertIn("OPERATOR", r["error"])
            self.assertEqual(s.validate_target()["ok"], False)

    def test_the_agent_cannot_widen_the_authorized_scope(self):
        from tpihunter.http_mock import profile_for, serve
        with serve() as url:
            s = self._session(url)
            bad = profile_for(url)
            bad["accounts"]["attacker"]["email"] = "ceo@corp.example"
            r = s.set_target(bad)
            self.assertFalse(r["ok"])
            self.assertIn("ceo@corp.example", r["error"])

            off = profile_for(url)
            off["base_url"] = "http://elsewhere.example"
            self.assertFalse(s.set_target(off)["ok"])

    def test_probing_is_blocked_until_the_profile_is_validated(self):
        from tpihunter.http_mock import profile_for, serve
        with serve(patched=False) as url:
            s = self._session(url)
            self.assertTrue(s.set_target(profile_for(url))["ok"])
            s.reset("live")
            r = s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
            self.assertFalse(r["ok"])
            self.assertIn("not been validated", r["error"])

            v = s.validate_target()
            self.assertTrue(v["ready"])
            self.assertEqual(s.target, "live")
            hit = s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
            self.assertEqual(hit["severity"], "takeover")
            self.assertEqual(hit["clause_id"], "TPI-1")

    def test_a_profile_with_blocking_failures_cannot_be_hunted(self):
        from tpihunter.http_mock import profile_for, serve
        with serve() as url:
            s = self._session(url)
            broken = profile_for(url)
            broken["oracle"]["whoami"]["extract"]["identity"] = {"json": "nope"}
            self.assertTrue(s.set_target(broken)["ok"])
            self.assertFalse(s.validate_target()["ready"])
            s.reset("live")
            r = s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
            self.assertFalse(r["ok"])
            self.assertIn("identity:victim", r["blocking_failures"])


class TestNaturalCanary(unittest.TestCase):
    """Most engagements authorise reads and not writes, so the oracle must be able to use
    a private value the victim ALREADY holds instead of planting one. That value is weaker
    evidence by construction, so each property a planted secret gets for free — stable,
    distinct, informative, not attacker-supplied — is measured instead of assumed."""

    NATURAL = "e0c4f6e08459dc42a91b77c3"      # what an account id / wallet handle looks like

    class NoWrites(MockAdapter):
        """A read-only target: it exposes a private per-account value and REFUSES writes,
        the shape a read-only rule of engagement forces. The value is per-account, as real
        private state is — a fixture that returned one constant would (correctly) be
        rejected by the distinctness control rather than testing anything."""

        def read_marker(self, p, ref=None):
            obs = super().read_marker(p, ref=ref)
            if ref is None and obs.extracted.get("value") is None:
                acc = self.t.account_of(self.sess.get(p.name))
                if acc is not None:
                    obs.extracted["value"] = (self._preset_marker if acc.email == EMAIL
                                              else "other-" + acc.id + "-8f3b1d9c4e7a")
            return obs

        def plant_marker(self, p, value):
            raise AssertionError("natural mode must never write")

        def write_marker(self, p, value, ref=None):
            raise AssertionError("natural mode must never write")

    def _probe(self, adapter_cls=MockAdapter, patched=False, marker=None, **kw):
        from tpihunter.enumerator import make_candidate
        attacker, victim = _principals()
        a = adapter_cls(patched=patched, control={victim.name: {EMAIL}}, **kw)
        plan = make_candidate((("attacker", "register"), ("victim", "sso_login")),
                              attacker, victim, EMAIL).plan
        a._preset_marker = marker if marker is not None else self.NATURAL
        return run_plan(a, plan, AtoOracle(a, attacker, victim, resource=EMAIL,
                                           canary="natural"))[0]

    def test_a_natural_canary_finds_the_bug_without_writing_anything(self):
        v = self._probe(self.NoWrites)
        self.assertEqual(v.severity.value, "takeover")
        self.assertEqual(v.clause_id, "TPI-1")
        self.assertEqual(v.controls["canary_mode"], "natural")
        self.assertTrue(v.controls["natural_canary_stable"])
        self.assertTrue(v.controls["natural_canary_distinct"])
        self.assertGreaterEqual(v.controls["natural_canary_bits"], 32)

    def test_natural_mode_still_discriminates_on_the_patched_target(self):
        self.assertEqual(self._probe(self.NoWrites, patched=True).severity.value, "safe")

    def test_a_constant_is_not_a_canary(self):
        # every account's field holds the same value -> it is a schema default, not state
        class Constant(MockAdapter):
            def read_marker(self, p, ref=None):
                from tpihunter.types import Observation
                return Observation(True, extracted={"value": self._preset_marker})
        v = self._probe(Constant)
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "canary_not_distinct")
        self.assertFalse(v.controls["natural_canary_distinct"])

    def test_a_value_that_changes_between_reads_is_not_a_canary(self):
        class Nonce(MockAdapter):
            def read_marker(self, p, ref=None):
                import secrets as _s
                from tpihunter.types import Observation
                return Observation(True, extracted={"value": _s.token_hex(12)})
        v = self._probe(Nonce)
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "canary_unstable")

    def test_a_low_entropy_value_is_not_a_canary(self):
        class Flag(MockAdapter):
            def read_marker(self, p, ref=None):
                from tpihunter.types import Observation
                return Observation(True, extracted={"value": self._preset_marker})
        v = self._probe(Flag, marker="0")
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "canary_low_entropy")

    def test_a_value_the_attacker_supplied_is_not_evidence(self):
        # the victim's "private" field holds the shared email, which the attacker typed in:
        # reading it back may be reflection, not access
        class Reflects(MockAdapter):
            def read_marker(self, p, ref=None):
                from tpihunter.types import Observation
                acc = self.t.account_of(self.sess.get(p.name))
                return Observation(acc is not None,
                                   extracted={"value": acc.email if acc else None})
        v = self._probe(Reflects)
        self.assertEqual(v.severity.value, "inconclusive")
        self.assertEqual(v.withheld, "canary_attacker_known")

    def test_natural_mode_refuses_to_enable_the_write_probe(self):
        attacker, victim = _principals()
        a = MockAdapter(control={victim.name: {EMAIL}})
        self.assertFalse(AtoOracle(a, attacker, victim, canary="natural", mutate=True).mutate)
        self.assertTrue(AtoOracle(a, attacker, victim, canary="planted", mutate=True).mutate)

    def test_an_unknown_canary_mode_is_refused(self):
        attacker, victim = _principals()
        with self.assertRaises(ValueError):
            AtoOracle(MockAdapter(), attacker, victim, canary="borrowed")


class TestNaturalCanaryOverHttp(unittest.TestCase):
    """The read-only shape, end to end: a profile with no write route at all, validated
    and hunted over HTTP. This is what a rules-of-engagement that authorises reads and
    not writes forces, which is most of them."""

    def _bits(self, url):
        from tpihunter.http_mock import engagement_for, readonly_profile_for
        from tpihunter.policy import EngagementPolicy
        from tpihunter.profile import TargetProfile
        return (TargetProfile.from_dict(readonly_profile_for(url)),
                EngagementPolicy.from_dict(engagement_for(url)))

    def test_profile_rejects_a_write_route_in_natural_mode(self):
        from tpihunter.http_mock import readonly_profile_for
        from tpihunter.profile import ProfileError, TargetProfile
        raw = readonly_profile_for("http://127.0.0.1:1/")
        raw["oracle"]["write_marker"] = {"method": "PUT", "path": "/api/me/wallet"}
        with self.assertRaises(ProfileError) as cm:
            TargetProfile.from_dict(raw)
        self.assertIn("must declare no write route", str(cm.exception))

    def test_profile_requires_a_write_route_in_planted_mode(self):
        from tpihunter.http_mock import profile_for
        from tpihunter.profile import ProfileError, TargetProfile
        raw = profile_for("http://127.0.0.1:1/")
        raw["oracle"].pop("plant_marker"); raw["oracle"].pop("write_marker")
        raw["oracle"].pop("write_marker_by_ref")
        with self.assertRaises(ProfileError) as cm:
            TargetProfile.from_dict(raw)
        self.assertIn('"canary": "natural"', str(cm.exception))

    def test_validation_measures_the_natural_canary_instead_of_planting(self):
        from tpihunter.http_mock import serve
        from tpihunter.validate import validate_target
        with serve() as url:
            prof, policy = self._bits(url)
            v = validate_target(prof, policy)
        self.assertTrue(v.ready)
        by = {c.name: c for c in v.checks}
        self.assertEqual(by["canary"].status, "pass")
        self.assertIn("no write issued", by["canary"].detail)
        self.assertEqual(by["canary_distinct"].status, "pass")
        self.assertFalse([a for a in v.artifacts if "marker" in a])   # nothing written

    def test_read_only_hunt_finds_the_same_bugs_and_writes_nothing(self):
        from tpihunter.http_mock import VICTIM_EMAIL, serve
        from tpihunter.live import live_adapter
        attacker, victim = _principals()

        def hunt(url, prof, policy):
            return AgentHunter(
                lambda: live_adapter(prof, policy, control={victim.name: {VICTIM_EMAIL}}),
                attacker, victim, VICTIM_EMAIL, budget=300, canary=prof.canary).hunt(
                    EnumeratorStrategist(max_attacker=1, max_victim=2))

        with serve(patched=False) as url:
            prof, policy = self._bits(url)
            res = hunt(url, prof, policy)
            audit = None
        self.assertEqual(sorted(b.clause_id for b in res.bugs), ["TPI-1", "TPI-4"])

        with serve(patched=True) as url:
            prof, policy = self._bits(url)
            self.assertEqual(hunt(url, prof, policy).bugs, [])

    def test_no_write_request_is_ever_issued_in_natural_mode(self):
        # the audit trail is the evidence: every request, and not one of them a write
        from tpihunter.http_mock import VICTIM_EMAIL, serve
        from tpihunter.live import live_adapter
        from tpihunter.policy import AuditLog
        from tpihunter.enumerator import make_candidate
        attacker, victim = _principals()
        log = AuditLog()
        with serve(patched=False) as url:
            prof, policy = self._bits(url)
            a = live_adapter(prof, policy, control={victim.name: {VICTIM_EMAIL}}, audit=log)
            plan = make_candidate((("attacker", "register"), ("victim", "sso_login")),
                                  attacker, victim, VICTIM_EMAIL).plan
            v = run_plan(a, plan, AtoOracle(a, attacker, victim, resource=VICTIM_EMAIL,
                                            canary="natural"))[0]
        self.assertEqual(v.severity.value, "takeover")
        self.assertEqual(v.controls["canary_mode"], "natural")
        writes = [r for r in log.records if r.action.startswith(("PUT ", "PATCH ", "DELETE "))]
        self.assertEqual(writes, [], f"natural mode issued writes: {[r.action for r in writes]}")


class TestHackerOneScopeImport(unittest.TestCase):
    """A programme's published scope is the authoritative statement of what may be
    touched. Transcribing it by hand is where an engagement acquires a host it was never
    granted, so the engagement file is generated from the export."""

    CSV = ("identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission\n"
           "a.example,URL,Please limit testing to 100 requests/minute due to db.,true,true\n"
           "https://b.example/app/,URL,Please limit testing to 2 requests per second.,true,true\n"
           "c.example,URL,Please do not register for accounts as this is a production site.,true,true\n"
           "d.example,URL,,true,true\n"
           "e.example,URL,Only branded content is in scope. All other content is OOS.,true,true\n"
           "f.example,URL,Accounts must be prefixed with vrp_ for identification.,false,false\n")

    def _write(self):
        import pathlib as _p, tempfile
        path = _p.Path(tempfile.mkdtemp()) / "scopes.csv"
        path.write_text(self.CSV)
        return str(path)

    def test_instructions_become_rules(self):
        from tpihunter.h1_scope import parse_instruction
        self.assertEqual(parse_instruction("limit to 100 requests/minute")[0]["min_interval"], 0.6)
        self.assertEqual(parse_instruction("100 requests per minute or less")[0]["min_interval"], 0.6)
        self.assertEqual(parse_instruction("2 requests per second")[0]["min_interval"], 0.5)
        self.assertTrue(parse_instruction("Please do not register for accounts here.")[0]
                        ["no_registration"])

    def test_an_unrecognised_instruction_is_surfaced_not_dropped(self):
        from tpihunter.h1_scope import parse_instruction
        rules, unparsed = parse_instruction("Accounts must be prefixed with vrp_.")
        self.assertEqual(rules, {})
        self.assertIn("vrp_", unparsed)
        # a phrase with no operational constraint does not clutter the review list
        self.assertIsNone(parse_instruction("Other languages at fr-support.")[1])

    def test_export_becomes_a_usable_engagement(self):
        from tpihunter.h1_scope import from_hackerone_csv
        from tpihunter.policy import EngagementPolicy
        eng, review = from_hackerone_csv(self._write(), name="p", authorized_by="ticket-1")
        self.assertEqual(sorted(eng["hosts"]),
                         ["a.example", "c.example", "d.example", "e.example",
                          "https://b.example/app/"])
        self.assertEqual(eng["excluded"], ["f.example"])
        self.assertEqual(eng["min_interval"], 0.6)        # the strictest asset sets the floor
        self.assertFalse(eng["allow_cross_principal_write"])
        self.assertTrue(any("vrp_" in r["instruction"] for r in review))

        policy = EngagementPolicy.from_dict({**eng, "identifiers": ["me@x.example"]})
        self.assertEqual(policy.preflight(), [])
        self.assertIsNone(policy.check_url("https://b.example/app/x"))
        self.assertIsNotNone(policy.check_url("https://b.example/elsewhere"))
        self.assertIsNotNone(policy.check_url("https://f.example/"))     # excluded wins

    def test_per_asset_rules_merge_most_restrictive_first(self):
        from tpihunter.policy import EngagementPolicy
        p = EngagementPolicy(name="p", authorized_by="x",
                             identifiers=frozenset({"a@b.example"}),
                             hosts=frozenset({"a.example", "*.a.example"}), min_interval=0.2,
                             asset_rules={"a.example": {"min_interval": 0.6},
                                          "*.a.example": {"min_interval": 1.5,
                                                          "no_registration": True}})
        self.assertEqual(p.rules_for("https://a.example/")["min_interval"], 0.6)
        sub = p.rules_for("https://x.a.example/")
        self.assertEqual(sub["min_interval"], 1.5)        # slowest wins
        self.assertTrue(sub["no_registration"])           # any prohibition wins
        # the global floor still applies where no asset rule matches
        self.assertEqual(EngagementPolicy(name="p", authorized_by="x",
                                          identifiers=frozenset({"a@b.example"}),
                                          hosts=frozenset({"z.example"}), min_interval=0.9)
                         .rules_for("https://z.example/")["min_interval"], 0.9)

    def test_a_no_registration_asset_refuses_a_profile_that_registers(self):
        from tpihunter.http_mock import engagement_for, profile_for, serve
        from tpihunter.live import LiveAdapter
        from tpihunter.policy import EngagementPolicy, ScopeViolation
        from tpihunter.profile import TargetProfile
        with serve() as url:
            raw = engagement_for(url)
            raw["asset_rules"] = {"127.0.0.1": {"no_registration": True,
                                                "note": "production site"}}
            policy = EngagementPolicy.from_dict(raw)
            prof = TargetProfile.from_dict(profile_for(url))
            with self.assertRaises(ScopeViolation) as cm:
                LiveAdapter(prof, policy)
            self.assertIn("forbids account registration", str(cm.exception))


class TestSuppliedSessions(unittest.TestCase):
    """The tool must not authenticate. Real consumer auth is gated by CAPTCHA, a device
    check or a push approval — defeating any of those is a hard stop on every programme
    worth testing — so a human logs in and hands the credential over, and the framework
    drives everything after that. Confirmed necessary on a real target: the login form of
    the in-scope Nintendo account host is gated by reCAPTCHA Enterprise."""

    def _login_out_of_band(self, url, email, password):
        """Stand in for the human: log in however a person would, keep the credential."""
        import json as _j, urllib.request
        req = urllib.request.Request(
            url + "/api/signup", _j.dumps({"email": email, "password": password}).encode(),
            {"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req) as r:
            return r.headers.get("Set-Cookie", "").split(";")[0]      # "sid=..."

    def test_a_supplied_cookie_authenticates_without_this_tool_logging_in(self):
        from tpihunter.http_mock import (ATTACKER_EMAIL, VICTIM_EMAIL, engagement_for,
                                         profile_for, serve)
        from tpihunter.live import LiveAdapter
        from tpihunter.policy import EngagementPolicy
        from tpihunter.profile import TargetProfile
        attacker, victim = _principals()
        with serve(patched=False) as url:
            sessions = {victim.name: self._login_out_of_band(url, VICTIM_EMAIL, "Vv!1234567"),
                        attacker.name: self._login_out_of_band(url, ATTACKER_EMAIL, "Aa!1234567")}
            prof = TargetProfile.from_dict(profile_for(url))
            policy = EngagementPolicy.from_dict(engagement_for(url))
            a = LiveAdapter(prof, policy, sessions=sessions)
            self.assertTrue(a.has_supplied_session(victim))
            vi, ai = a.whoami(victim), a.whoami(attacker)
            self.assertTrue(vi.ok and ai.ok)
            self.assertNotEqual(vi.identity, ai.identity)     # two independent contexts
            # login/register are satisfied without touching the flow we may not automate
            obs = a.login(victim, VICTIM_EMAIL, "whatever")
            self.assertTrue(obs.ok)
            self.assertIn("not performed by this tool", obs.note)

    def test_validation_checks_a_supplied_session_instead_of_logging_in(self):
        from tpihunter.http_mock import (ATTACKER_EMAIL, VICTIM_EMAIL, engagement_for,
                                         readonly_profile_for, serve)
        from tpihunter.policy import EngagementPolicy
        from tpihunter.profile import TargetProfile
        from tpihunter.validate import validate_target
        attacker, victim = _principals()
        with serve() as url:
            sessions = {victim.name: self._login_out_of_band(url, VICTIM_EMAIL, "Vv!1234567"),
                        attacker.name: self._login_out_of_band(url, ATTACKER_EMAIL, "Aa!1234567")}
            v = validate_target(TargetProfile.from_dict(readonly_profile_for(url)),
                                EngagementPolicy.from_dict(engagement_for(url)),
                                sessions=sessions)
        by = {c.name: c for c in v.checks}
        self.assertEqual(by["session:victim"].status, "pass")
        self.assertIn("supplied session", by["session:victim"].detail)
        self.assertEqual(by["independence"].status, "pass")
        # nothing was created by validation: the accounts already existed
        self.assertFalse([a for a in v.artifacts if "created by validation" in a])

    def test_an_expired_supplied_session_fails_loudly(self):
        from tpihunter.http_mock import engagement_for, readonly_profile_for, serve
        from tpihunter.policy import EngagementPolicy
        from tpihunter.profile import TargetProfile
        from tpihunter.validate import validate_target
        _attacker, victim = _principals()
        with serve() as url:
            v = validate_target(TargetProfile.from_dict(readonly_profile_for(url)),
                                EngagementPolicy.from_dict(engagement_for(url)),
                                sessions={victim.name: "sid=expired-and-invalid"})
        by = {c.name: c for c in v.checks}
        self.assertEqual(by["session:victim"].status, "fail")
        self.assertIn("does not resolve to an identity", by["session:victim"].detail)
        self.assertFalse(v.ready)


class TestMutationControl(unittest.TestCase):
    """A cell may only report on a mutation it can show took effect.

    Found live, not by reasoning: a real target's /logout is a CONFIRMATION page. Fetching
    it returns HTTP 200 and logs nobody out. The captured session then "survives" a
    mutation that never happened, and every cell reads SURVIVED — a false Critical
    produced by a measurement that never ran. (The same target, once the button was
    actually clicked, revoked the session correctly: 403.)"""

    from tpihunter.matrix import MintSpec, MutationSpec
    MINT = MintSpec("password_session", (("register", {"email": EMAIL, "password": "Pw!1"}),),
                    "a password session")

    def _cell(self, mutation, **adapter_kw):
        from tpihunter.matrix import run_cell
        owner = Principal("owner")
        return run_cell(lambda: MockAdapter(control={owner.name: {EMAIL}}, **adapter_kw),
                        self.MINT, mutation, owner)

    def test_a_mutation_that_silently_does_nothing_is_inconclusive_not_survived(self):
        from tpihunter.matrix import MutationSpec, Survival
        noop = MutationSpec("confirmation_page", (("noop_logout", {}),), "a logout that asks",
                            verify=lambda a, p: not a.whoami(p).ok)

        class ConfirmationPage(MockAdapter):
            """Reports success and changes nothing — the live shape."""
            def noop_logout(self, p):
                from tpihunter.types import Observation
                return Observation(True, note="signed-out confirmation page rendered")

        v = self._cell(noop, **{})
        # the adapter above is supplied through the factory, so build it explicitly:
        from tpihunter.matrix import run_cell
        owner = Principal("owner")
        v = run_cell(lambda: ConfirmationPage(control={owner.name: {EMAIL}}),
                     self.MINT, noop, owner)
        self.assertEqual(v.survival, Survival.INCONCLUSIVE)
        self.assertIn("did not take effect", v.note)
        self.assertFalse(v.is_finding)

    def test_a_mutation_whose_steps_fail_is_inconclusive(self):
        from tpihunter.matrix import MutationSpec, Survival
        missing = MutationSpec("absent", (("no_such_verb", {}),), "a verb the target lacks")
        v = self._cell(missing)
        self.assertEqual(v.survival, Survival.INCONCLUSIVE)
        self.assertIn("did not execute", v.note)

    def test_a_verified_mutation_still_reports_normally(self):
        from tpihunter.matrix import Survival, default_mutations
        logout = next(m for m in default_mutations(EMAIL) if m.id == "logout")
        survived = self._cell(logout)                       # logout does not revoke by default
        self.assertEqual(survived.survival, Survival.SURVIVED)
        self.assertEqual(survived.mutation_verified, "witnessed")
        revoked = self._cell(logout, revokes={"logout"})
        self.assertEqual(revoked.survival, Survival.REVOKED)
        self.assertEqual(revoked.mutation_verified, "witnessed")

    def test_a_witness_that_does_not_move_beats_a_verify_that_claims_success(self):
        """The control that would have caught both false SURVIVEDs this framework produced
        against a real target. A boolean is a claim and code can claim without looking; a
        witness has to be read twice, and an unchanged reading is indistinguishable from a
        mutation that never ran."""
        from tpihunter.matrix import MutationSpec, Survival
        lying = MutationSpec(
            "noop", (("noop_logout", {}),), "a mutation that changes nothing",
            verify=lambda a, p: True,                      # claims success
            witness=lambda a, p: a.whoami(p).identity)     # but nothing moved

        class ConfirmationPage(MockAdapter):
            def noop_logout(self, p):
                from tpihunter.types import Observation
                return Observation(True, note="confirmation page rendered")

        from tpihunter.matrix import run_cell
        owner = Principal("owner")
        v = run_cell(lambda: ConfirmationPage(control={owner.name: {EMAIL}}),
                     self.MINT, lying, owner)
        self.assertEqual(v.survival, Survival.INCONCLUSIVE)
        self.assertIn("left the witness unchanged", v.note)
        self.assertFalse(v.is_finding)

    def test_an_unreadable_witness_is_inconclusive_not_assumed(self):
        from tpihunter.matrix import MutationSpec, Survival, run_cell
        def boom(a, p): raise RuntimeError("cannot read")
        m = MutationSpec("logout", (("logout", {}),), "logout", witness=boom)
        owner = Principal("owner")
        v = run_cell(lambda: MockAdapter(control={owner.name: {EMAIL}}), self.MINT, m, owner)
        self.assertEqual(v.survival, Survival.INCONCLUSIVE)
        self.assertIn("could not be read", v.note)

    def test_a_cell_without_a_verifier_says_so_rather_than_implying_one(self):
        from tpihunter.matrix import MutationSpec, Survival
        unverified = MutationSpec("logout", (("logout", {}),), "logout")   # no verify=
        v = self._cell(unverified)
        self.assertEqual(v.survival, Survival.SURVIVED)
        self.assertIn("unverified", v.mutation_verified)


class _FakeDriver:
    """A PageDriver with no browser: pages are (url -> text/cookies/selectors) data.
    Lets the whole flow engine be tested without Playwright, which is why the driver is
    injected at all."""

    def __init__(self, pages, cookies_on=None):
        self.pages = pages            # {url_substring: {"text":..., "sets":{cookie:val}, "sel":[...]}}
        self._url = "about:blank"
        self._cookies = dict(cookies_on or {})
        self.filled = {}
        self.clicked = []
        self.closed = False

    def _page(self):
        for frag, page in self.pages.items():
            if frag in self._url:
                return page
        return {"text": "", "sets": {}, "sel": []}

    def goto(self, url):
        self._url = url
        self._cookies.update(self._page().get("sets", {}))

    def url(self): return self._url
    def text(self): return self._page().get("text", "")
    def cookies(self): return dict(self._cookies)
    def set_cookies(self, c): self._cookies.update(c)
    def has(self, sel): return sel in self._page().get("sel", [])
    def close(self): self.closed = True

    def fill(self, sel, val):
        if sel not in self._page().get("sel", []):
            return False
        self.filled[sel] = val
        return True

    def click(self, target):
        page = self._page()
        if target not in page.get("sel", []) and target not in page.get("labels", []):
            return False
        self.clicked.append(target)
        goes = page.get("goes", {}).get(target)
        if goes:
            self.goto(goes)
        return True


class TestBrowserAdapter(unittest.TestCase):
    """UI flows as an ordinary TargetAdapter, so the framework's controls reach them.
    Every wrong answer this framework produced against a real target came from browser
    work that bypassed those controls."""

    BASE = "https://t.example"

    def _policy(self, **kw):
        from tpihunter.policy import EngagementPolicy
        base = dict(name="t", authorized_by="x", identifiers=frozenset({"v@t.example"}),
                    hosts=frozenset({"t.example"}))
        base.update(kw)
        return EngagementPolicy(**base)

    def _profile(self, flows, **kw):
        from tpihunter.browser import BrowserProfile
        base = dict(name="t", base_url=self.BASE,
                    accounts={"victim": {"email": "v@t.example", "password": "pw"},
                              "attacker": {"email": "v@t.example", "password": "pw"}},
                    flows=flows, session_cookie="sid",
                    identity_from=r"id:([0-9a-f]{8})", marker_from=r"handle:([0-9a-f]{12})")
        base.update(kw)
        return BrowserProfile(**base)

    LOGIN_OK = {"text": "id:aaaa1111 handle:0123456789ab Welcome", "sets": {"sid": "S-1"},
                "sel": ["#email", "#pw"], "labels": ["Sign in"], "goes": {}}

    def _login_flow(self, expect):
        from tpihunter.browser import Flow, UiStep
        return Flow("login", (
            UiStep(goto="/login", fill=(("#email", "{email}"), ("#pw", "{password}")),
                   click="Sign in", expect=expect),), proof=None)

    def test_a_flow_that_lands_on_the_error_page_reports_failure(self):
        # THE regression. Three logins in this engagement were recorded as successful
        # while sitting on /cdn/display_error, because the check was "not on /login".
        from tpihunter.browser import BrowserAdapter, Expect
        pages = {"/login": {"text": "The request contains an error.", "sets": {},
                            "sel": ["#email", "#pw"], "labels": ["Sign in"],
                            "goes": {"Sign in": self.BASE + "/cdn/display_error"}},
                 "/cdn/display_error": {"text": "The request contains an error.",
                                        "sets": {}, "sel": [], "labels": []}}
        prof = self._profile({"login": self._login_flow(Expect(cookie="sid"))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver(pages))
        obs = a.login(Principal("victim"))
        self.assertFalse(obs.ok)
        self.assertIn("cookie 'sid' absent", obs.note)

    def test_a_flow_that_genuinely_succeeds_reports_success_with_identity(self):
        from tpihunter.browser import BrowserAdapter, Expect
        pages = {"/login": {**self.LOGIN_OK, "goes": {"Sign in": self.BASE + "/home"}},
                 "/home": self.LOGIN_OK}
        prof = self._profile({"login": self._login_flow(Expect(cookie="sid",
                                                               text_contains="Welcome"))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver(pages))
        obs = a.login(Principal("victim"))
        self.assertTrue(obs.ok)
        self.assertEqual(a.whoami(Principal("victim")).identity, "aaaa1111")
        self.assertEqual(a.read_marker(Principal("victim")).extracted["value"], "0123456789ab")

    def test_each_principal_gets_its_own_context(self):
        from tpihunter.browser import BrowserAdapter, Expect
        pages = {"/login": {**self.LOGIN_OK, "goes": {"Sign in": self.BASE + "/home"}},
                 "/home": self.LOGIN_OK}
        prof = self._profile({"login": self._login_flow(Expect(cookie="sid"))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver(pages))
        v, at = Principal("victim"), Principal("attacker")
        self.assertIsNot(a.driver(v), a.driver(at))
        a.login(v)
        self.assertIn("sid", a.driver(v).cookies())
        self.assertNotIn("sid", a.driver(at).cookies())   # independence, the oracle's premise

    def test_a_ui_step_leaving_scope_raises(self):
        from tpihunter.browser import BrowserAdapter, Expect, Flow, UiStep
        from tpihunter.policy import ScopeViolation
        prof = self._profile({"login": Flow("login", (
            UiStep(goto="https://elsewhere.example/login", expect=Expect(cookie="sid")),))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver({}))
        with self.assertRaises(ScopeViolation):
            a.login(Principal("victim"))

    def test_present_binding_uses_a_fresh_context(self):
        from tpihunter.browser import BrowserAdapter, Expect
        made = []
        def factory():
            d = _FakeDriver({"t.example": {"text": "id:bbbb2222", "sets": {}, "sel": []}})
            made.append(d); return d
        prof = self._profile({"login": self._login_flow(Expect(cookie="sid"))})
        a = BrowserAdapter(prof, self._policy(), factory)
        obs = a.present_binding("S-1")
        self.assertTrue(obs.ok)
        self.assertEqual(obs.identity, "bbbb2222")
        self.assertTrue(made[-1].closed)          # the throwaway context is disposed

    def test_a_browser_profile_never_writes(self):
        from tpihunter.browser import BrowserAdapter, Expect
        prof = self._profile({"login": self._login_flow(Expect(cookie="sid"))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver({}))
        p = Principal("victim")
        self.assertFalse(a.plant_marker(p, "x").ok)
        self.assertFalse(a.write_marker(p, "x").ok)
        byref = a.read_marker(p, ref="anything")
        self.assertFalse(byref.ok)
        self.assertIn("no by-reference read", byref.note)

    def test_missing_field_or_control_is_reported_not_silently_passed(self):
        from tpihunter.browser import BrowserAdapter, Expect
        pages = {"/login": {"text": "", "sets": {}, "sel": ["#email"], "labels": []}}
        prof = self._profile({"login": self._login_flow(Expect(cookie="sid"))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver(pages))
        obs = a.login(Principal("victim"))
        self.assertFalse(obs.ok)
        self.assertIn("'#pw' not found", obs.note)

    def test_an_out_of_band_value_is_fetched_when_the_step_runs(self):
        # the e-mail challenge code exists only AFTER the credentials are submitted;
        # fetching it earlier yields the previous code, which fails quietly
        from tpihunter.browser import BrowserAdapter, Expect, Flow, UiStep
        pages = {"/login": {"text": "", "sets": {}, "sel": ["#email", "#code"],
                            "labels": ["Sign in"], "goes": {}},
                 }
        calls = []
        def code_provider(vars):
            calls.append(vars.get("email"))
            return "424242"
        prof = self._profile({"login": Flow("login", (
            UiStep(goto="/login", fill=(("#email", "{email}"),), click="Sign in"),
            UiStep(fill=(("#code", "{code}"),), expect=Expect(selector="#code")),))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver(pages),
                           providers={"code": code_provider})
        obs = a.login(Principal("victim"))
        self.assertTrue(obs.ok, obs.note)
        self.assertEqual(a.driver(Principal("victim")).filled["#code"], "424242")
        self.assertEqual(calls, ["v@t.example"])          # called once, at step time

    def test_an_out_of_band_value_that_never_arrives_fails_loudly(self):
        from tpihunter.browser import BrowserAdapter, Expect, Flow, UiStep
        pages = {"/login": {"text": "", "sets": {}, "sel": ["#code"], "labels": []}}
        prof = self._profile({"login": Flow("login", (
            UiStep(goto="/login", fill=(("#code", "{code}"),), expect=Expect(selector="#code")),))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver(pages),
                           providers={"code": lambda v: None})
        obs = a.login(Principal("victim"))
        self.assertFalse(obs.ok)
        self.assertIn("never arrived", obs.note)

    def test_channel_control_is_enforced_before_a_request_is_made(self):
        from tpihunter.browser import BrowserAdapter, Expect, Flow, UiStep
        prof = self._profile({"sso_login": Flow("sso_login", (
            UiStep(goto="/sso", expect=Expect(cookie="sid")),))})
        a = BrowserAdapter(prof, self._policy(), lambda: _FakeDriver({}),
                           control={"victim": {"v@t.example"}})
        self.assertFalse(a.sso_login(Principal("attacker")).ok)   # attacker lacks control
        self.assertIn("does not control", a.sso_login(Principal("attacker")).note)


class TestIdentifierEquivalence(unittest.TestCase):
    """The takeover class the state machine cannot represent. TPI treats an identifier as
    an atom, so a system whose CLAIM layer and RESOLVE layer disagree about whether two
    strings are the same identity is invisible to it — no binding survives anything and
    justifies(prov(B), B) holds at every step, yet registering a variant takes the account."""

    BASE, ACCT = "v@x.example", "acct_1"

    def test_one_representative_per_class_never_a_product(self):
        from tpihunter.identifiers import MAX_VARIANTS, variants
        vs = variants(self.BASE)
        kinds = [v.kind for v in vs]
        self.assertEqual(len(kinds), len(set(kinds)))        # no class twice
        self.assertLessEqual(len(vs), MAX_VARIANTS)
        self.assertTrue(all(v.rationale for v in vs))        # every value has a reason
        self.assertNotIn(self.BASE, [v.value for v in vs])   # the base is not a variant

    def test_a_claimable_variant_that_authenticates_is_a_takeover_primitive(self):
        from tpihunter.identifiers import probe_identifier
        # the classic shape: the claim layer is case-sensitive, the resolve layer is not
        def claimable(x): return x != self.BASE
        def resolves(x): return self.ACCT if x.lower().strip() == self.BASE else None
        rep = probe_identifier(self.BASE, self.ACCT, claimable, resolves)
        self.assertTrue(rep.sound)
        kinds = {f.kind for f in rep.findings}
        self.assertIn("takeover_primitive", kinds)
        hit = next(f for f in rep.findings if f.kind == "takeover_primitive")
        self.assertIn("takeover of that account", hit.render())

    def test_a_consistent_system_yields_nothing(self):
        from tpihunter.identifiers import probe_identifier
        # both layers canonicalise identically -> no disagreement -> no finding
        def canon(x): return x.lower().strip()
        def claimable(x): return canon(x) != canon(self.BASE)
        def resolves(x): return self.ACCT if canon(x) == canon(self.BASE) else None
        rep = probe_identifier(self.BASE, self.ACCT, claimable, resolves)
        self.assertTrue(rep.sound)
        self.assertEqual(rep.findings, [])

    def test_a_layer_that_resolves_everything_is_caught_by_the_control(self):
        from tpihunter.identifiers import probe_identifier
        rep = probe_identifier(self.BASE, self.ACCT,
                               claimable=lambda x: True,
                               resolves_to=lambda x: self.ACCT)      # resolves anything
        self.assertFalse(rep.sound)
        self.assertEqual(rep.findings, [])
        self.assertIn("INCONCLUSIVE", rep.summary())

    def test_a_resolve_that_misses_the_base_is_caught_by_the_control(self):
        from tpihunter.identifiers import probe_identifier
        rep = probe_identifier(self.BASE, self.ACCT,
                               claimable=lambda x: True,
                               resolves_to=lambda x: None)           # resolves nothing
        self.assertFalse(rep.sound)
        self.assertIn("INCONCLUSIVE", rep.summary())

    def test_an_unanswerable_layer_is_skipped_not_guessed(self):
        from tpihunter.identifiers import probe_identifier
        rep = probe_identifier(self.BASE, self.ACCT,
                               claimable=lambda x: None,             # cannot tell
                               resolves_to=lambda x: self.ACCT
                               if x.lower().strip() == self.BASE else None)
        self.assertTrue(rep.sound)
        self.assertEqual(rep.findings, [])
        self.assertTrue(rep.skipped)


class TestBoundedProbe(unittest.TestCase):
    """Enumeration belongs in the loop; a wordlist does not. The difference is not the
    number of requests, it is whether each value was chosen for a reason."""

    def test_a_candidate_without_a_hypothesis_cannot_exist(self):
        from tpihunter.probe import Candidate
        for bad in ("", "   ", None):
            with self.assertRaises((ValueError, TypeError)):
                Candidate("arg", "value", bad)

    def test_the_bound_refuses_rather_than_trims(self):
        from tpihunter.probe import Budget, Candidate, run_probe
        cands = [Candidate("a", str(i), "shape guess") for i in range(5)]
        res = run_probe(Budget(per_argument=2, total=99), cands, lambda c: (200, "ok", False))
        self.assertEqual(len(res.outcomes), 2)
        self.assertIn("widen the hypothesis", res.exhausted)
        self.assertFalse(res.complete)          # stopping early is not a clean negative

    def test_a_rate_limit_halts_the_probe_and_says_so(self):
        from tpihunter.probe import Budget, Candidate, run_probe
        cands = [Candidate("a", str(i), "h") for i in range(4)]
        res = run_probe(Budget(), cands, lambda c: (429, "slow down", False))
        self.assertIn("429", res.halted)
        self.assertFalse(res.complete)
        self.assertIn("not a clean negative", res.summary())

    def test_a_challenge_halts_rather_than_being_worked_around(self):
        from tpihunter.probe import Budget, Candidate, run_probe
        res = run_probe(Budget(), [Candidate("a", "1", "h")],
                        lambda c: (200, "please complete the captcha", False))
        self.assertIn("challenge", res.halted)
        self.assertFalse(res.complete)

    def test_a_clean_run_reports_complete(self):
        from tpihunter.probe import Budget, Candidate, run_probe
        res = run_probe(Budget(), [Candidate("a", "1", "h"), Candidate("a", "2", "h")],
                        lambda c: (200, "ok", c.value == "2"))
        self.assertTrue(res.complete)
        self.assertEqual(len(res.interesting()), 1)


class TestRaceMode(unittest.TestCase):
    """Concurrency: the failure the engine could not express though the theory names it.
    A single-use proof consumed twice is two bindings from one proof — but run_plan walks
    steps in order, so the only interleaving it can build is an ordering, and token
    double-spend is not an ordering."""

    class _Store:
        """A single-use token store. `window` inserts a check-then-act gap; with a lock
        the same code is atomic — the two differ only in whether the gap is guarded."""

        def __init__(self, window=0.0, atomic=False):
            import threading
            self.window, self.atomic = window, threading.Lock() if atomic else None
            self.tokens = set()

        def mint(self, tok):
            self.tokens.add(tok)

        def consume(self, tok):
            import time
            from tpihunter.types import Observation
            if self.atomic:
                with self.atomic:
                    if tok not in self.tokens:
                        return Observation(False, note="spent")
                    time.sleep(self.window)
                    self.tokens.discard(tok)
                    return Observation(True)
            if tok not in self.tokens:                 # CHECK
                return Observation(False, note="spent")
            time.sleep(self.window)                    # ...the window...
            self.tokens.discard(tok)                   # ACT
            return Observation(True)

    SPEC = None

    def _spec(self, **kw):
        from tpihunter.race import RaceSpec
        base = dict(name="single-use token", parallelism=8,
                    invariant="a single-use token is consumed at most once")
        base.update(kw)
        return RaceSpec(**base)

    def _run(self, window, atomic, **kw):
        from tpihunter.race import run_race
        def prepare():
            st = self._Store(window=window, atomic=atomic)
            st.mint("T")
            return st
        return run_race(self._spec(**kw), prepare=prepare,
                        fire=lambda st, i: st.consume("T"),
                        negative=lambda st, i: st.consume("NEVER-VALID"))

    def test_a_check_then_act_window_is_caught(self):
        from tpihunter.race import RaceOutcome
        v = self._run(window=0.05, atomic=False)
        self.assertEqual(v.outcome, RaceOutcome.RACE, v.note)
        self.assertGreater(v.concurrent_successes, 1)
        self.assertEqual(v.sequential_successes, 1)     # it IS single-use in sequence
        self.assertTrue(v.controls["overlapped"])
        self.assertTrue(v.is_finding)
        self.assertIn("Invariant broken", v.render())

    def test_the_same_code_with_the_window_guarded_is_not_a_finding(self):
        from tpihunter.race import RaceOutcome
        v = self._run(window=0.05, atomic=True)
        self.assertEqual(v.outcome, RaceOutcome.ATOMIC, v.note)
        self.assertEqual(v.concurrent_successes, 1)
        self.assertFalse(v.is_finding)

    def test_an_action_that_is_not_single_use_in_sequence_measures_nothing(self):
        from tpihunter.race import RaceOutcome, RaceSpec, run_race
        from tpihunter.types import Observation
        v = run_race(self._spec(), prepare=lambda: None,
                     fire=lambda ctx, i: Observation(True))      # always succeeds
        self.assertEqual(v.outcome, RaceOutcome.INCONCLUSIVE)
        self.assertEqual(v.sequential_successes, 2)
        self.assertIn("not single-use even without concurrency", v.note)

    def test_an_endpoint_that_accepts_anything_is_caught_by_the_negative_control(self):
        from tpihunter.race import RaceOutcome, run_race
        from tpihunter.types import Observation
        calls = {"n": 0}
        def fire(ctx, i):
            calls["n"] += 1
            return Observation(calls["n"] == 1)          # single-use in sequence
        v = run_race(self._spec(), prepare=lambda: None, fire=fire,
                     negative=lambda ctx, i: Observation(True))   # accepts anything
        self.assertEqual(v.outcome, RaceOutcome.INCONCLUSIVE)
        self.assertIn("accepts anything", v.note)

    def test_attempts_that_serialise_are_not_reported_as_no_race(self):
        # the false NEGATIVE this mode is most prone to: a lock, a pool or a rate limiter
        # serialises the requests and "nothing raced" looks like "nothing to find"
        from tpihunter.race import RaceOutcome, RaceSpec, run_race
        from tpihunter.types import Observation
        import threading
        gate = threading.Lock()
        state = {"spent": False, "seq": 0}
        def fire(ctx, i):
            with gate:                                   # forces strict serialisation
                if state["spent"]:
                    return Observation(False)
                state["spent"] = True
                return Observation(True)
        def prepare():
            state["spent"] = False
            return None
        v = run_race(RaceSpec("serialised", invariant="x", parallelism=4),
                     prepare=prepare, fire=fire)
        self.assertIn(v.outcome, (RaceOutcome.ATOMIC, RaceOutcome.INCONCLUSIVE))
        if v.outcome is RaceOutcome.INCONCLUSIVE:
            self.assertIn("serialised", v.note)

    def test_over_http_the_same_probe_discriminates_racy_from_atomic(self):
        """The discriminator, over real sockets and a threaded server: identical probe,
        opposite verdicts. A detector that fired on both would be worthless."""
        import json as _j, urllib.error, urllib.request
        from tpihunter.http_mock import VICTIM_EMAIL, serve
        from tpihunter.race import RaceOutcome, RaceSpec, run_race
        from tpihunter.types import Observation

        def post(url, path, body):
            req = urllib.request.Request(url + path, _j.dumps(body).encode(),
                                         {"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code

        def verdict(racy):
            with serve(patched=False, racy_reset=racy) as url:
                def prepare():
                    post(url, "/api/signup", {"email": VICTIM_EMAIL, "password": "Pw!1"})
                    post(url, "/api/reset", {"email": VICTIM_EMAIL})
                    link = _j.load(urllib.request.urlopen(
                        url + "/testing/inbox?address=" + VICTIM_EMAIL, timeout=10))["link"]
                    return link.split("token=")[-1]
                return run_race(
                    RaceSpec("reset token double-spend", parallelism=8,
                             invariant="a single-use reset token is consumed at most once"),
                    prepare=prepare,
                    fire=lambda tok, i: Observation(
                        post(url, "/api/reset/confirm", {"token": tok, "password": f"N!{i}"}) == 200),
                    negative=lambda tok, i: Observation(
                        post(url, "/api/reset/confirm", {"token": "never", "password": "x"}) == 200))

        racy = verdict(0.08)
        self.assertEqual(racy.outcome, RaceOutcome.RACE, racy.note)
        self.assertGreater(racy.concurrent_successes, 1)
        self.assertGreaterEqual(racy.controls["max_in_flight"], 2)

        clean = verdict(0.0)
        self.assertEqual(clean.outcome, RaceOutcome.ATOMIC, clean.note)
        self.assertEqual(clean.concurrent_successes, 1)
        self.assertEqual(clean.sequential_successes, 1)   # single-use either way

    def test_overlap_is_measured_from_the_windows_not_assumed(self):
        from tpihunter.race import Attempt, max_overlap
        self.assertEqual(max_overlap([Attempt(0, True, 0.0, 1.0),
                                      Attempt(1, False, 0.5, 1.5)]), 2)
        self.assertEqual(max_overlap([Attempt(0, True, 0.0, 1.0),
                                      Attempt(1, False, 1.1, 2.0)]), 1)


class TestCredentialStructure(unittest.TestCase):
    """The other thing the state machine treats as opaque. A binding's HANDLE that is
    derivable rather than unguessable gives an attacker a binding with no proof event
    behind it — and the trace the oracle reads contains nothing at all."""

    def _samples(self, values, **kw):
        from tpihunter.credentials import CredentialSample
        return [CredentialSample(v, "t", **kw) for v in values]

    def test_randomness_is_not_flagged_at_small_sample_counts(self):
        """The trap this mode exists to avoid: with six tokens no position can show more
        than six values, so a naive reading calls every set structured."""
        import secrets
        from tpihunter.credentials import analyse
        rep = analyse(self._samples([secrets.token_hex(16) for _ in range(6)],
                                    authenticates=True))
        self.assertEqual(rep.findings, [], rep.render())
        self.assertTrue(rep.sound)

    def test_a_sequential_handle_is_caught(self):
        from tpihunter.credentials import CredentialSample, analyse
        vals = [f"{'a'*24}{i:08x}" for i in range(6)]
        rep = analyse([CredentialSample(v, "t", minted_at=float(i), authenticates=True)
                       for i, v in enumerate(vals)])
        kinds = {f.kind for f in rep.findings}
        self.assertIn("structured-handle", kinds)
        self.assertIn("monotonic-handle", kinds)

    def test_entropy_is_not_a_finding_until_the_value_is_shown_to_authenticate(self):
        """Measured live: a 10-digit browser-state cookie beside a real session cookie was
        flagged 'low-entropy handle' — true of the string, meaningless as a finding."""
        from tpihunter.credentials import analyse
        vals = [f"7198{i:06d}" for i in range(6)]
        unknown = analyse(self._samples(vals))
        self.assertEqual(unknown.findings, [])
        self.assertTrue(any("authenticates anything" in n for n in unknown.notes))
        shown = analyse(self._samples(vals, authenticates=True))
        self.assertTrue(any(f.kind == "low-entropy-handle" for f in shown.findings))

    def test_a_jwt_is_never_flagged_for_its_fixed_layout(self):
        """Measured live: a sound HS256 session cookie scored 173 bits against a 619-bit
        baseline purely because the header and claim names repeat. Running the structural
        test on a JWT guarantees a false positive on every correct token."""
        import base64, json as _j, secrets
        from tpihunter.credentials import Shape, analyse
        def jwt(sub):
            def seg(d): return base64.urlsafe_b64encode(_j.dumps(d).encode()).rstrip(b"=").decode()
            return (seg({"alg": "HS256"}) + "." +
                    seg({"jti": secrets.token_hex(5), "sub": sub, "typ": "session",
                         "iat": 1789880264, "exp": 1789880264 + 3600}) + "." +
                    secrets.token_urlsafe(32))
        rep = analyse(self._samples([jwt("acct") for _ in range(6)], authenticates=True))
        self.assertEqual(rep.shape, Shape.JWT)
        self.assertFalse([f for f in rep.findings if f.kind == "structured-handle"])
        self.assertFalse(rep.controls["structure_measured"])

    def test_alg_none_and_missing_expiry_are_findings(self):
        import base64, json as _j
        from tpihunter.credentials import analyse
        def seg(d): return base64.urlsafe_b64encode(_j.dumps(d).encode()).rstrip(b"=").decode()
        tok = seg({"alg": "none"}) + "." + seg({"sub": "acct"}) + "." + "x"
        rep = analyse(self._samples([tok], authenticates=True))
        kinds = {f.kind for f in rep.findings}
        self.assertIn("jwt-alg-none", kinds)
        self.assertIn("jwt-no-exp", kinds)

    def test_a_long_lifetime_defers_to_the_revocation_matrix(self):
        """A two-year expiry is only a bearer problem if revocation is NOT server-side,
        and this mode cannot see that. It says so rather than guessing."""
        import base64, json as _j, secrets
        from tpihunter.credentials import analyse
        def seg(d): return base64.urlsafe_b64encode(_j.dumps(d).encode()).rstrip(b"=").decode()
        iat = 1789880264
        tok = (seg({"alg": "HS256"}) + "." +
               seg({"sub": "a", "iat": iat, "exp": iat + 730*86400}) + "." +
               secrets.token_urlsafe(32))
        rep = analyse(self._samples([tok], authenticates=True))
        self.assertEqual(rep.controls["lifetime_days"], 730.0)
        self.assertTrue(any("revocation matrix" in n for n in rep.notes))
        self.assertFalse([f for f in rep.findings if "lifetime" in f.kind])

    def test_too_few_samples_claims_nothing(self):
        from tpihunter.credentials import analyse
        rep = analyse(self._samples(["abc123def456"], authenticates=True))
        self.assertFalse(rep.controls["structure_measured"])
        self.assertTrue(any("too few" in n for n in rep.notes))


class TestSurfaceTriage(unittest.TestCase):
    """Choosing WHERE to point the modes. A framework with five modes and no targeting
    will be aimed at the most obvious asset, which on a mature estate is the most hardened
    one — eleven of twelve cells went to a flagship consumer IdP while eleven other
    in-scope auth surfaces, two of them named `-dev`, were never touched."""

    def _s(self, **kw):
        from tpihunter.surface import Surface, score
        base = dict(url="https://h/", host="h", reachable=True, status=200)
        base.update(kw)
        return score(Surface(**base))

    def test_a_non_production_identity_api_outranks_a_marketing_page(self):
        dev = self._s(host="library-dev.accountportal.example", status=401, json_api=True)
        www = self._s(host="www.example.com", status=200)
        self.assertGreater(dev.score, www.score)
        self.assertTrue(any("non-production" in x for x in dev.signals))

    def test_the_reason_is_recorded_not_just_the_rank(self):
        s = self._s(host="id.example.net", status=403, sets_cookie=("SID",))
        self.assertTrue(s.signals)
        self.assertTrue(any("identity surface" in x for x in s.signals))
        self.assertTrue(any("gated" in x for x in s.signals))

    def test_an_unreachable_asset_scores_nothing_and_says_so(self):
        s = self._s(reachable=False, status=None)
        self.assertEqual(s.score, 0)
        self.assertIn("unreachable", s.signals)

    def test_a_catch_all_makes_every_path_look_reachable(self):
        """The regression. Measured live: a developer portal served a byte-identical page
        for /, /welcome, /j_spring_security_logout and a nonsense path — three false
        'reachable without auth' results."""
        from tpihunter.surface import catchall_baseline

        class _R:
            def __init__(self, status, text): self.status, self.text = status, text
            headers = {}

        CATCHALL = "<html>portal landing</html>"
        send = lambda u: _R(200, CATCHALL)
        base = catchall_baseline("https://h", send)
        self.assertIsNotNone(base)
        # every path returns the catch-all, so nothing is distinct
        self.assertFalse(base.distinct(200, CATCHALL))
        # a genuinely different page clears the floor
        self.assertTrue(base.distinct(200, "<html>admin console</html>"))
        # so does a different status
        self.assertTrue(base.distinct(403, CATCHALL))

    def test_testability_gates_exploitability(self):
        """The correction this made to itself. Its first run ranked a legacy identity
        system on a dev host top — and that surface turned out untestable: we hold no
        account on it and its only unauthenticated flows MAIL their result to the
        registered owner, so every probe with an identifier we do not own touches a third
        party. Juicy and unreachable is worth zero."""
        juicy = self._s(host="game-dev.id.example.net", status=200,
                        principals=0, can_enrol=False)
        ordinary = self._s(host="accounts.example.com", status=200,
                           sets_cookie=("SID",), principals=3)
        self.assertGreater(ordinary.score, juicy.score)
        self.assertTrue(any("NO PRINCIPAL" in x for x in juicy.signals))
        self.assertTrue(any("two-principal modes runnable" in x for x in ordinary.signals))

    def test_one_principal_allows_own_account_modes_only(self):
        one = self._s(host="a.example", status=200, sets_cookie=("S",), principals=1)
        two = self._s(host="b.example", status=200, sets_cookie=("S",), principals=2)
        self.assertGreater(two.score, one.score)
        self.assertTrue(any("own-account modes only" in x for x in one.signals))

    def test_an_available_enrolment_path_beats_no_principal_at_all(self):
        # the surfaces must carry positive exploitability first: the gate SCALES value,
        # and a surface with none to scale cannot show the difference
        enrol = self._s(host="a.example.net", status=401, sets_cookie=("S",), can_enrol=True)
        none_ = self._s(host="b.example.net", status=401, sets_cookie=("S",), can_enrol=False)
        self.assertGreater(enrol.score, none_.score)
        self.assertTrue(any("enrolment is available" in x for x in enrol.signals))

    def test_an_unattractive_surface_is_not_rescued_by_the_gate(self):
        # multiplying a NEGATIVE score by a smaller factor makes it larger; the gate
        # scales only positive value, which the suite caught when it did not
        plain = self._s(host="www.example.com", status=200, can_enrol=True)
        self.assertLessEqual(plain.score, 0)

    def test_the_baseline_path_is_unguessable_so_it_cannot_be_special_cased(self):
        from tpihunter.surface import catchall_baseline
        seen = []
        class _R:
            status, text, headers = 200, "x", {}
        catchall_baseline("https://h", lambda u: seen.append(u) or _R())
        catchall_baseline("https://h", lambda u: seen.append(u) or _R())
        self.assertNotEqual(seen[0], seen[1])


class TestSessionLifecycle(unittest.TestCase):
    """Sessions as scarce, degrading inventory — the constraint that ended the first live
    engagement. Sixteen scripts each minted their own login, eight sessions were captured
    and discarded when their browser closed, and by evening every account answered the
    login form with an error page, including one rested seven hours."""

    def _store(self, **kw):
        import tempfile, os
        from tpihunter.sessions import SessionStore
        path = os.path.join(tempfile.mkdtemp(), "s.json")
        return SessionStore(path, **kw), path

    def _login(self, counter):
        from tpihunter.sessions import Session
        def fn():
            counter["n"] += 1
            return Session("victim", cookies={"sid": f"S{counter['n']}"})
        return fn

    def test_a_live_session_is_reused_instead_of_reminted(self):
        st, _ = self._store(validate=lambda s: True)
        c = {"n": 0}
        for _ in range(6):
            st.acquire("victim", login=self._login(c))
        self.assertEqual(c["n"], 1)      # six acquires, ONE authentication

    def test_a_dead_session_is_discarded_and_not_kept_around(self):
        st, _ = self._store(validate=lambda s: False)
        c = {"n": 0}
        st.acquire("victim", login=self._login(c))
        st.acquire("victim", login=self._login(c))
        self.assertEqual(c["n"], 2)
        self.assertEqual(st.ledger.spent("victim"), 2)

    def test_sessions_and_the_ledger_survive_a_new_process(self):
        from tpihunter.sessions import SessionStore
        st, path = self._store(validate=lambda s: True)
        c = {"n": 0}
        st.acquire("victim", login=self._login(c))
        reopened = SessionStore(path, validate=lambda s: True)
        reopened.acquire("victim", login=self._login(c))
        self.assertEqual(c["n"], 1)      # the new process reused it — no login at all
        self.assertEqual(reopened.ledger.total(), 1)

    def test_the_per_principal_cap_refuses_rather_than_continuing(self):
        from tpihunter.sessions import LoginLedger, NoSessionAvailable
        st, _ = self._store(validate=lambda s: False,
                            ledger=LoginLedger(max_per_principal=2, max_total=99))
        c = {"n": 0}
        st.acquire("victim", login=self._login(c))
        st.acquire("victim", login=self._login(c))
        with self.assertRaises(NoSessionAvailable) as cm:
            st.acquire("victim", login=self._login(c))
        self.assertIn("already spent", str(cm.exception))
        self.assertEqual(c["n"], 2)

    def test_two_failed_logins_stop_the_retry_loop(self):
        """The behaviour that matters most: on a real target a failed login and a
        throttled one return the same error page, so retrying is what deepens it."""
        from tpihunter.sessions import LoginLedger, NoSessionAvailable
        st, _ = self._store(validate=lambda s: False,
                            ledger=LoginLedger(max_per_principal=9, max_total=99))
        for _ in range(2):
            with self.assertRaises(NoSessionAvailable):
                st.acquire("victim", login=lambda: None)
        with self.assertRaises(NoSessionAvailable) as cm:
            st.acquire("victim", login=lambda: None)
        self.assertIn("retrying is what deepens it", str(cm.exception))

    def test_an_unverifiable_session_expires_instead_of_being_trusted_forever(self):
        """With no validator there is no evidence, so age has to decide. Handing back a
        dead cookie would turn every downstream verdict into an INCONCLUSIVE wearing a
        result's clothes."""
        from tpihunter.sessions import Session
        st, _ = self._store(validate=None, max_age=1800.0)
        stale = Session("victim", cookies={"sid": "old"})
        st.put("victim", stale)
        stale.acquired_at = time.time() - 7200          # the seven-hour rest that did not help
        c = {"n": 0}
        got = st.acquire("victim", login=self._login(c))
        self.assertEqual(c["n"], 1)                     # re-minted, not trusted
        self.assertEqual(got.cookies["sid"], "S1")

    def test_a_session_supplied_out_of_band_costs_nothing(self):
        from tpihunter.sessions import Session
        st, _ = self._store(validate=lambda s: True)
        st.put("victim", Session("victim", cookies={"sid": "from-a-human-browser"}))
        c = {"n": 0}
        got = st.acquire("victim", login=self._login(c))
        self.assertEqual(c["n"], 0)
        self.assertEqual(got.cookies["sid"], "from-a-human-browser")
        self.assertEqual(st.ledger.total(), 0)

    def test_status_makes_exhaustion_visible_while_it_is_recoverable(self):
        st, _ = self._store(validate=lambda s: True)
        c = {"n": 0}
        st.acquire("victim", login=self._login(c))
        out = st.status()
        self.assertIn("victim", out)
        self.assertIn("total spent: 1", out)


class TestStepUpMatrix(unittest.TestCase):
    """TPI-6 as a mode. The clause is about two equally-privileged flows disagreeing,
    so most of these tests are about NOT reporting the many ways they legitimately differ."""

    def _t(self):
        from tpihunter.stepup_matrix import nintendo_account_transitions
        return nintendo_account_transitions()

    def _probe(self, levels, seen=True):
        from tpihunter.stepup_matrix import Level, Reading
        def probe(t):
            if t.id not in levels:
                return Reading(Level.INCONCLUSIVE, "not read")
            lv = levels[t.id]
            return Reading(lv, f"observed {lv.value}", principal_seen=seen)
        return probe

    def test_equal_privilege_disagreement_is_a_tpi6_finding(self):
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe({
            "login_id/edit": Level.DEMANDED, "passkey": Level.NOT_DEMANDED}), session_age=7200)
        self.assertEqual(len(r.findings), 1)
        f = r.findings[0]
        self.assertEqual(f.clause_id, "TPI-6")
        self.assertEqual(f.privilege, "login-credential")
        self.assertIn("passkey", f.accepted)
        self.assertIn("login_id/edit", f.demanded)

    def test_different_privilege_classes_are_not_compared(self):
        """Editing a nickname needs less proof than changing a password. That is not a
        bug, and a mode that reports it is a mode nobody will run twice."""
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe({
            "password/edit": Level.DEMANDED, "profile/edit": Level.NOT_DEMANDED}), session_age=7200)
        self.assertEqual(r.findings, [])

    def test_a_logged_out_page_never_reads_as_no_step_up(self):
        """The control that makes the mode sound. A logged-out page shows no password
        prompt either, so without a positive marker it would score as the single most
        exploitable cell on the board."""
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe(
            {"login_id/edit": Level.DEMANDED, "passkey": Level.NOT_DEMANDED}, seen=False),
            session_age=7200)
        self.assertEqual(r.findings, [])
        self.assertTrue(any("logged out" in w for w in r.withheld))
        cell = [c for c in r.cells if c.transition.id == "passkey"][0]
        self.assertIs(cell.level, Level.INCONCLUSIVE)

    def test_a_demanded_reading_needs_no_liveness_marker(self):
        """A 302 to /reauthenticate is self-evidencing: a logged-out surface does not ask
        this principal to re-authenticate, it asks it to log in."""
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe({"login_id/edit": Level.DEMANDED}, seen=False),
                       session_age=7200)
        cell = [c for c in r.cells if c.transition.id == "login_id/edit"][0]
        self.assertIs(cell.level, Level.DEMANDED)

    def test_a_fresh_session_withholds_the_verdict(self):
        """Most surfaces run a freshness window, so an asymmetry measured a minute after
        login is about being freshly logged in, not about provenance."""
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe({
            "login_id/edit": Level.DEMANDED, "passkey": Level.NOT_DEMANDED}), session_age=60)
        self.assertEqual(r.findings, [])
        self.assertTrue(any("freshness window" in w for w in r.withheld))

    def test_an_inconclusive_cell_is_not_an_acceptance(self):
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe({"login_id/edit": Level.DEMANDED}), session_age=7200)
        self.assertEqual(r.findings, [])

    def test_uniform_refusal_is_not_a_finding(self):
        from tpihunter.stepup_matrix import Level, run_stepup
        r = run_stepup(self._t(), self._probe({
            "login_id/edit": Level.DEMANDED, "passkey": Level.DEMANDED,
            "password/edit": Level.DEMANDED}), session_age=7200)
        self.assertEqual(r.findings, [])
        self.assertIn("agree", r.render())

    def test_a_probe_that_raises_is_inconclusive_not_evidence(self):
        from tpihunter.stepup_matrix import Level, run_stepup
        def probe(t):
            raise RuntimeError("connection reset")
        r = run_stepup(self._t(), probe, session_age=7200)
        self.assertEqual(r.findings, [])
        self.assertTrue(all(c.level is Level.INCONCLUSIVE for c in r.cells))


if __name__ == "__main__":
    unittest.main(verbosity=2)
