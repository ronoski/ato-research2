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

    def test_host_scope_rejects_lookalikes_and_accepts_subdomains(self):
        p = self._policy()
        self.assertIsNone(p.check_url("https://staging.acme.example/login"))
        self.assertIsNone(p.check_url("https://api.staging.acme.example/login"))
        for bad in ("https://evil.example/", "https://notstaging.acme.example/",
                    "https://staging.acme.example.evil.test/", "file:///etc/passwd"):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
