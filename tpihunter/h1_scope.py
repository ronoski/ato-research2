"""Build an engagement file from a HackerOne scope export.

    python3 -m tpihunter.h1_scope scopes_for_<programme>_at_<ts>.csv > engagement.json

The scope a programme publishes is the authoritative statement of what may be touched,
and transcribing it by hand is exactly the step where an engagement acquires a host it
was never granted. So the engagement file is *generated* from the export: in-scope
entries with their paths preserved, exclusions that beat them, and the per-asset
instructions turned into rules.

Two things this deliberately does not do:

  * **It does not fill in `identifiers`.** The accounts a tool may act on are the test
    accounts the researcher created, and no export knows them. The generated file carries
    placeholders and `preflight()` refuses until they are replaced.
  * **It does not silently drop an instruction it could not parse.** Anything unrecognised
    is copied verbatim into `review`, because "the generator ignored it" and "the programme
    did not say anything" must never look the same. Read that list before the first run.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from typing import Optional

# "limit testing to 100 requests/minute", "100 requests per minute or less"
_RPM = re.compile(r"(\d{1,5})\s*(?:requests?|reqs?)\s*(?:/|per\s+)\s*min", re.I)
_RPS = re.compile(r"(\d{1,5})\s*(?:requests?|reqs?)\s*(?:/|per\s+)\s*sec", re.I)
# "Please do not register for accounts as this is a production site."
_NO_REG = re.compile(r"do\s+not\s+(?:register|create)\b[^.]{0,40}\baccounts?\b", re.I)

# Phrases that carry no operational constraint — recognised so they do not clutter `review`.
_BENIGN = re.compile(r"(?i)^(other languages|alternate name|only nintendo branded|"
                     r"staging sites|my nintendo store|.*redirect to their respective)")


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "yes", "1", "t")


def parse_instruction(text: str) -> tuple[dict, Optional[str]]:
    """(rules, unparsed). `unparsed` is the instruction when nothing was recognised."""
    rules: dict = {}
    t = (text or "").strip()
    if not t:
        return rules, None
    m = _RPM.search(t)
    if m and int(m.group(1)) > 0:
        rules["min_interval"] = round(60.0 / int(m.group(1)), 4)
    m = _RPS.search(t)
    if m and int(m.group(1)) > 0:
        rules["min_interval"] = max(rules.get("min_interval", 0.0), 1.0 / int(m.group(1)))
    if _NO_REG.search(t):
        rules["no_registration"] = True
    if rules:
        rules["note"] = " ".join(t.split())[:200]
        return rules, None
    return rules, (None if _BENIGN.match(t) else " ".join(t.split())[:300])


def from_hackerone_csv(path: str, *, name: str = "", authorized_by: str = "",
                       max_actions: int = 400) -> dict:
    """Turn a HackerOne scope export into a `policy.EngagementPolicy` dict."""
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows or "identifier" not in rows[0]:
        raise ValueError(f"{path} does not look like a HackerOne scope export "
                         f"(expected an `identifier` column)")

    hosts, excluded, rules, review = [], [], {}, []
    for r in rows:
        ident = (r.get("identifier") or "").strip()
        if not ident or (r.get("asset_type") or "").strip().upper() == "CIDR":
            continue
        if " " in ident:                      # a vulnerability-class tag, not a host
            continue
        (hosts if _truthy(r.get("eligible_for_submission")) else excluded).append(ident)
        got, unparsed = parse_instruction(r.get("instruction") or "")
        if got:
            rules[ident] = got
        if unparsed:
            review.append({"asset": ident, "instruction": unparsed})

    # The strictest per-asset rate becomes the floor for everything, so an asset with no
    # instruction is not tested faster than the most fragile one the programme named.
    rates = [v["min_interval"] for v in rules.values() if "min_interval" in v]
    engagement = {
        "name": name or "hackerone-engagement",
        "authorized_by": authorized_by or "<who authorized this, and where it is recorded>",
        "identifiers": ["<test account 1>", "<test account 2>", "<bystander account>"],
        "hosts": sorted(set(hosts)),
        "excluded": sorted(set(excluded)),
        "asset_rules": rules,
        "allow_credential_change": False,
        "allow_cross_principal_write": False,
        "max_actions": max_actions,
        "min_interval": max(rates) if rates else 0.5,
    }
    return engagement, review


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    engagement, review = from_hackerone_csv(argv[0], name=(argv[1] if len(argv) > 1 else ""))
    print(json.dumps(engagement, indent=2))
    if review:
        print(f"\n{len(review)} instruction(s) NOT turned into a rule — read these before "
              f"the first run:", file=sys.stderr)
        for r in review:
            print(f"  {r['asset']}: {r['instruction']}", file=sys.stderr)
    print("\nFill in `identifiers` with your test accounts before use; the policy refuses "
          "to run until you do.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
