"""Scenario template + mix parsing tests (T1)."""

import pytest

from demo_server.scenarios import (
    CATEGORY_FILES,
    MIX_GROUPS,
    ScenarioBook,
    ScenarioError,
    load_category,
    parse_mix,
)

EXPECTED_COUNTS = {"net_critical": 3, "net_benign": 5, "ato_critical": 3, "ato_benign": 3}


def test_scenario_files_complete_with_metadata():
    for category, expected_count in EXPECTED_COUNTS.items():
        templates = load_category(category)
        assert len(templates) == expected_count, category
        for t in templates:
            assert t.action in {"analyze_network", "analyze_ato"}, category
            assert isinstance(t.data, dict) and t.data, category
            assert set(t.metadata) == {"source", "description"}, category
            assert t.metadata["description"], category


def test_parse_mix_valid_and_default():
    assert parse_mix(None) == {"net": 15, "ato": 15, "benign": 70}
    assert parse_mix("") == {"net": 15, "ato": 15, "benign": 70}
    assert parse_mix("net=30,ato=20,benign=50") == {"net": 30.0, "ato": 20.0, "benign": 50.0}
    with pytest.raises(ScenarioError, match="sum to 100"):
        parse_mix("net=50,ato=20")
    with pytest.raises(ScenarioError, match="not a number"):
        parse_mix("net=abc,benign=100")
    with pytest.raises(ScenarioError, match="must look like"):
        parse_mix("net30")


def test_scenario_book_group_mapping_and_rotation():
    book = ScenarioBook()
    assert book.categories_for_group("net") == ("net_critical",)
    assert book.categories_for_group("benign") == ("net_benign", "ato_benign")
    with pytest.raises(ScenarioError, match="unknown mix group"):
        book.categories_for_group("bogus")

    picked = [book.pick("benign") for _ in range(6)]
    cats = {t.category for t in picked}
    assert cats == {"net_benign", "ato_benign"}  # rotates across both
    assert all(t.action == "analyze_network" for t in [book.pick("net")])
    assert set(MIX_GROUPS["net"]) == {"net_critical"}
    assert set(CATEGORY_FILES) == {"net_critical", "net_benign", "ato_critical", "ato_benign"}
