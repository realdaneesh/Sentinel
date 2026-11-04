from itertools import permutations
from types import MappingProxyType

import pytest

from services.detection.risk_scoring import DEFAULT_WEIGHTS, score_risk


def test_empty_signals():
    assert score_risk([]) == {
        "risk_score": 0,
        "severity": "LOW",
        "reasons": [],
        "triggered_signals": [],
        "scorer_version": "1.0.0",
    }


@pytest.mark.parametrize("signal,weight,severity", [
    ("failed_login_burst", 35, "MEDIUM"),
    ("unfamiliar_device", 20, "LOW"),
    ("unusual_login_hour", 15, "LOW"),
    ("unfamiliar_ip", 20, "LOW"),
])
def test_individual_signals(signal, weight, severity):
    result = score_risk([signal])
    assert result["risk_score"] == weight
    assert type(result["risk_score"]) is int
    assert result["severity"] == severity
    assert result["triggered_signals"] == [signal]
    assert result["reasons"] == [f"{signal}: +{weight} risk points."]


@pytest.mark.parametrize("signals,score,severity", [
    (["unfamiliar_device", "unusual_login_hour"], 35, "MEDIUM"),
    (["failed_login_burst", "unusual_login_hour"], 50, "HIGH"),
    (["failed_login_burst", "unfamiliar_device", "unfamiliar_ip"], 75, "CRITICAL"),
    (list(DEFAULT_WEIGHTS), 90, "CRITICAL"),
])
def test_combinations(signals, score, severity):
    result = score_risk(signals)
    assert result["risk_score"] == score
    assert result["severity"] == severity


def test_duplicates_and_order_do_not_change_any_output():
    expected = score_risk(list(DEFAULT_WEIGHTS))
    assert expected["triggered_signals"] == [
        "failed_login_burst", "unfamiliar_device", "unfamiliar_ip", "unusual_login_hour",
    ]
    assert expected["reasons"] == [
        "failed_login_burst: +35 risk points.",
        "unfamiliar_device: +20 risk points.",
        "unfamiliar_ip: +20 risk points.",
        "unusual_login_hour: +15 risk points.",
    ]
    for order in permutations(DEFAULT_WEIGHTS):
        assert score_risk(order + order) == expected
    assert score_risk(set(DEFAULT_WEIGHTS)) == expected
    assert score_risk(signal for signal in DEFAULT_WEIGHTS) == expected


def test_partial_custom_weights_preserve_unspecified_defaults():
    signals = ["unfamiliar_device", "failed_login_burst"]
    weights = {"failed_login_burst": 5}
    result = score_risk(signals, weights=weights)
    assert result["risk_score"] == 25
    assert result["severity"] == "MEDIUM"
    assert result["reasons"] == [
        "failed_login_burst: +5 risk points.", "unfamiliar_device: +20 risk points.",
    ]
    assert signals == ["unfamiliar_device", "failed_login_burst"]
    assert weights == {"failed_login_burst": 5}
    assert score_risk(signals)["risk_score"] == 55


def test_empty_and_read_only_weight_mappings():
    assert score_risk(DEFAULT_WEIGHTS.keys(), weights={}) == score_risk(DEFAULT_WEIGHTS.keys())
    result = score_risk(["failed_login_burst"], weights=MappingProxyType({"failed_login_burst": 0}))
    assert result["risk_score"] == 0
    assert result["triggered_signals"] == ["failed_login_burst"]
    assert result["reasons"] == ["failed_login_burst: +0 risk points."]


def test_defaults_are_immutable_and_result_lists_are_independent():
    with pytest.raises(TypeError):
        DEFAULT_WEIGHTS["failed_login_burst"] = 99
    result = score_risk(["failed_login_burst"])
    result["reasons"].clear()
    result["triggered_signals"].append("unfamiliar_ip")
    fresh = score_risk(["failed_login_burst"])
    assert fresh["triggered_signals"] == ["failed_login_burst"]
    assert fresh["reasons"] == ["failed_login_burst: +35 risk points."]


@pytest.mark.parametrize("score,severity", [
    (0, "LOW"), (24, "LOW"), (25, "MEDIUM"), (49, "MEDIUM"),
    (50, "HIGH"), (74, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL"),
])
def test_severity_boundaries(score, severity):
    result = score_risk(["failed_login_burst"], weights={"failed_login_burst": score})
    assert result["risk_score"] == score
    assert result["severity"] == severity
    assert len(result["reasons"]) == 1


def test_score_capping_is_explained_and_deterministic():
    weights = {signal: 100 for signal in DEFAULT_WEIGHTS}
    result = score_risk(list(DEFAULT_WEIGHTS) * 2, weights=weights)
    assert result["risk_score"] == 100
    assert result["severity"] == "CRITICAL"
    assert result["reasons"] == [
        "failed_login_burst: +100 risk points.",
        "unfamiliar_device: +100 risk points.",
        "unfamiliar_ip: +100 risk points.",
        "unusual_login_hour: +100 risk points.",
        "Total of 400 risk points capped at 100.",
    ]
    assert score_risk(reversed(DEFAULT_WEIGHTS), weights=dict(reversed(list(weights.items())))) == result


@pytest.mark.parametrize("signals", [
    None, True, 42, 1.5, "failed_login_burst", b"failed_login_burst",
    bytearray(b"failed_login_burst"), {}, {"failed_login_burst": True},
    {"event_id": "evt-1", "event_type": "LOGIN_FAILURE"},
])
def test_invalid_signal_collections(signals):
    with pytest.raises(TypeError, match="signals must be an iterable"):
        score_risk(signals)


@pytest.mark.parametrize("signal", [None, True, 35, 1.5, b"failed_login_burst", [], {}])
def test_invalid_signal_element_types(signal):
    with pytest.raises(TypeError, match="identifiers must be strings"):
        score_risk(["failed_login_burst", signal])


@pytest.mark.parametrize("signal", ["", " ", "unknown", "FAILED_LOGIN_BURST", " failed_login_burst", "failed_login_burst "])
def test_unknown_and_non_normalized_signals(signal):
    with pytest.raises(ValueError, match="unknown signal identifier"):
        score_risk([signal])


@pytest.mark.parametrize("weights", [True, 1, "weights", [], [("failed_login_burst", 10)]])
def test_invalid_weight_containers(weights):
    with pytest.raises(TypeError, match="weights must be a mapping"):
        score_risk([], weights=weights)


@pytest.mark.parametrize("weight", [True, False, 20.0, 1.5, float("nan"), float("inf"), "20", None, [], {}])
def test_invalid_weight_types_even_for_absent_signals(weight):
    with pytest.raises(TypeError, match="weights must be integers"):
        score_risk([], weights={"failed_login_burst": weight})


@pytest.mark.parametrize("weight", [-1, 101, 10**100])
def test_out_of_range_weights(weight):
    with pytest.raises(ValueError, match="between 0 and 100"):
        score_risk([], weights={"failed_login_burst": weight})


@pytest.mark.parametrize("key,error", [
    ("unknown", ValueError), ("", ValueError), ("unfamiliar_ip ", ValueError),
    (1, TypeError), (None, TypeError), (False, TypeError),
])
def test_invalid_weight_keys_even_for_empty_signals(key, error):
    with pytest.raises(error):
        score_risk([], weights={key: 10})
