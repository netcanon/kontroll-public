"""eval_pred / eval_vector truth tables — the heart of the classifier.

The engine is THREE-valued on purpose: True (signal present), False (absent),
None (unconfirmable at this probe depth). The None case is what lets a Galaxy
shallow result honestly show `?` instead of a wrong `no`. These tables pin every
combinator's None-propagation so a refactor can't silently collapse it to boolean.
"""
import pytest

import galaxy

pytestmark = pytest.mark.unit


# --- leaf predicates --------------------------------------------------------- #
def test_plugin_present_and_absent(make_facts):
    """A `plugin` predicate is True when that plugin type is present in the facts, False when absent."""
    f = make_facts(plugins={"cliconf": ["ios"]})
    assert galaxy.eval_pred({"plugin": "cliconf"}, f) is True
    assert galaxy.eval_pred({"plugin": "httpapi"}, f) is False


def test_module_suffix(make_facts):
    """A `module_suffix` predicate is True iff some module name ends with the suffix, else False."""
    f = make_facts(modules=["ios_config", "ios_command"])
    assert galaxy.eval_pred({"module_suffix": "_config"}, f) is True
    assert galaxy.eval_pred({"module_suffix": "_resource"}, f) is False


def test_module_option_unknown_when_no_options(make_facts):
    """No module_options probed (shallow/Galaxy) -> None, never a false 'no'."""
    f = make_facts(modules=["ios_config"], module_options={})
    assert galaxy.eval_pred(
        {"module_option": {"suffix": "_config", "option": "backup"}}, f) is None


def test_module_option_present_and_absent(make_facts):
    """When options ARE probed (deep), a `module_option` predicate resolves to a real True/False —
    present (the option exists on a matching module) vs absent — not the unknown None case."""
    f = make_facts(module_options={"ios_config": ["backup", "lines"]})
    assert galaxy.eval_pred(
        {"module_option": {"suffix": "_config", "option": "backup"}}, f) is True
    assert galaxy.eval_pred(
        {"module_option": {"suffix": "_config", "option": "nope"}}, f) is False


# --- combinators: three-valued propagation ----------------------------------- #
def test_any_of(make_facts):
    """`any_of` is True if any sub-predicate is True; False only when all are confirmed False."""
    f = make_facts(plugins={"cliconf": ["ios"]})           # cliconf True, httpapi False
    assert galaxy.eval_pred({"any_of": [{"plugin": "cliconf"}, {"plugin": "httpapi"}]}, f) is True
    assert galaxy.eval_pred({"any_of": [{"plugin": "httpapi"}, {"plugin": "netconf"}]}, f) is False


def test_any_of_none_when_only_unknown_and_false(make_facts):
    """`any_of` of an unknown (None) + a False is None, not False — it could still be True deeper.
    Guards against collapsing 'unconfirmed' into a wrong negative."""
    # one None (module_option, no options) + one False -> None (could still be yes deeper)
    f = make_facts(modules=["x_config"], plugins={})
    pred = {"any_of": [{"module_option": {"suffix": "_config", "option": "backup"}},
                       {"plugin": "cliconf"}]}
    assert galaxy.eval_pred(pred, f) is None


def test_all_of(make_facts):
    """`all_of` is True when every sub-predicate is True; a single confirmed False short-circuits
    to False regardless of any unknowns (this is the `api` backend's classify rule)."""
    f = make_facts(plugins={"httpapi": ["fortios"]})
    # httpapi True AND (not cliconf) True -> True  (this is the `api` backend's rule)
    pred = {"all_of": [{"plugin": "httpapi"}, {"none_of": [{"plugin": "cliconf"}]}]}
    assert galaxy.eval_pred(pred, f) is True
    # one False short-circuits to False regardless of unknowns
    pred_false = {"all_of": [{"plugin": "httpapi"}, {"plugin": "cliconf"}]}
    assert galaxy.eval_pred(pred_false, f) is False


def test_all_of_none(make_facts):
    """`all_of` of True + None (no confirmed False) is None — undecidable until a deeper probe."""
    f = make_facts(plugins={"cliconf": ["ios"]}, module_options={})
    pred = {"all_of": [{"plugin": "cliconf"},
                       {"module_option": {"suffix": "_config", "option": "backup"}}]}
    assert galaxy.eval_pred(pred, f) is None      # True + None, no False -> None


def test_none_of(make_facts):
    """`none_of` is True when no listed signal is present (the bespoke/raw_ssh case); a single
    present signal flips it to False."""
    bespoke = make_facts(modules=["thing"])        # no plugins, no _config
    pred = {"none_of": [{"plugin": "cliconf"}, {"plugin": "httpapi"},
                        {"plugin": "netconf"}, {"module_suffix": "_config"}]}
    assert galaxy.eval_pred(pred, bespoke) is True
    has_cli = make_facts(plugins={"cliconf": ["ios"]})
    assert galaxy.eval_pred(pred, has_cli) is False   # a present signal -> False


def test_unknown_predicate_kind_is_none(make_facts):
    """An unrecognized predicate kind evaluates to None (not a crash) — forward-compatible with
    rules a newer vectors/backends file might introduce."""
    assert galaxy.eval_pred({"made_up_rule": "x"}, make_facts()) is None


# --- eval_vector: first-True wins; unknown -> maybe; else no ------------------ #
def test_vector_backup_yes_from_cliconf(vectors, make_facts):
    """A cliconf plugin yields the backup vector = yes at high confidence (the generic
    cli_config 'get' backs the device up), the first-True-rule-wins path."""
    backup = next(v for v in vectors if v["name"] == "backup")
    f = make_facts(plugins={"cliconf": ["ios"]})
    res = galaxy.eval_vector(backup, f)
    assert res["state"] == "yes" and res["confidence"] == "high"


def test_vector_backup_maybe_when_only_unknown(vectors, make_facts):
    """cliconf absent + module_options unprobed -> the _config-backup rule is None,
    so the vector is 'maybe' (unknown at depth), not a hard 'no'."""
    backup = next(v for v in vectors if v["name"] == "backup")
    f = make_facts(modules=["thing"], module_options={})   # no _facts, no cliconf
    assert galaxy.eval_vector(backup, f)["state"] == "maybe"


def test_vector_backup_no_when_all_false(vectors, make_facts):
    """A *deep* probe that confirms a _config module WITHOUT a backup option (so the
    module_option rule is a real False, not None) and no cliconf/_facts -> 'no'."""
    backup = next(v for v in vectors if v["name"] == "backup")
    f = make_facts(modules=["x_config"], module_options={"x_config": ["lines"]})
    assert galaxy.eval_vector(backup, f)["state"] == "no"
