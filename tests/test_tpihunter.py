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
