"""Baseline policy settings round-trip through settings.json."""

from leetha.config import (
    LeethaConfig, _PERSISTABLE_FIELDS, save_config, load_config,
)


def test_defaults():
    c = LeethaConfig()
    assert c.baseline_learning_mode == "automatic"
    assert c.baseline_quiet_period_minutes == 30
    assert c.baseline_max_window_days == 7


def test_fields_are_persistable():
    for key in ("baseline_learning_mode", "baseline_quiet_period_minutes",
                "baseline_max_window_days"):
        assert key in _PERSISTABLE_FIELDS


def test_round_trip(tmp_path):
    c = LeethaConfig(data_dir=tmp_path)
    c.baseline_learning_mode = "always_learning"
    c.baseline_quiet_period_minutes = 90
    c.baseline_max_window_days = 14
    save_config(c)

    loaded = load_config(data_dir=tmp_path)
    assert loaded.baseline_learning_mode == "always_learning"
    assert loaded.baseline_quiet_period_minutes == 90
    assert loaded.baseline_max_window_days == 14
