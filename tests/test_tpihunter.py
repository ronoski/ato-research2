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
        self.assertEqual(s.run_probe([["attacker", "register"]])["severity"], "safe")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
