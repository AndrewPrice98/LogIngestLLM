"""Known-answer scenarios (evals/scenarios.json): rules, tools, indicators, ATT&CK and false-alarm guards."""
import pytest

from logagent import engine, evals

SPEC = evals.load_scenarios()


@pytest.mark.parametrize("sc", SPEC["scenarios"], ids=[s["name"] for s in SPEC["scenarios"]])
def test_scenario(sc):
    if evals.files_for(sc) is None:
        pytest.skip(f"optional data: set {sc.get('files_env')}")
    scan = evals.run_scan(sc, engine.load_config(None), use_llm=False)
    failed = [f"{c['check']} {c['detail']}".strip() for c in evals.static_checks(sc, scan) if not c["ok"]]
    assert not failed, failed
