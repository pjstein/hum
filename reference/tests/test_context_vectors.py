import json

from hum_reference.vectors import context_vectors as cv

RULES = [f"C{i}" for i in range(1, 17)]


def test_context_vectors_counts_and_determinism():
    files = cv.generate()
    by_name = {f.name: f for f in files}
    manifests = by_name["manifests"]
    accepting = [c for c in manifests.cases if "expected" in c]
    rejecting = [c for c in manifests.cases if "rejection" in c]
    assert len(accepting) == 7  # valid-discovery (run 5), valid-v2-logs (C11, run 6)
    rules = {c["rejection"]["rule"] for c in rejecting}
    assert rules == set(RULES)
    assert sum(1 for c in rejecting if c["rejection"]["rule"] == "C16") == 4
    assert len(by_name["policy-eval"].cases) == 11
    assert len(by_name["count"].cases) == 4
    assert len(by_name["results-key"].cases) == 4
    again = cv.generate()
    assert json.dumps([f.cases for f in files], sort_keys=True) == json.dumps(
        [f.cases for f in again], sort_keys=True
    )
