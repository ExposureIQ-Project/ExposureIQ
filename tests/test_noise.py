"""Tests for noise control: ignore rules and removal confirmation.

Pure data, no network. compare_scans and present_in (Marwan) are replaced by
small fakes, so these tests work before and after his code is merged.
"""

import copy
import logging
import random

import pytest

from exposureiq.diffing import noise

LOGGER = "exposureiq.diffing.noise"


def change(kind, host, **extra):
    base = {"kind": kind, "direction": "neutral", "host": host, "ip": None,
            "port": None, "before": None, "after": None, "status": "confirmed"}
    base.update(extra)
    return base


def write(tmp_path, text, name="ignore.txt", newline=None):
    path = tmp_path / name
    data = text if newline is None else text.replace("\n", newline)
    path.write_bytes(data.encode("utf-8"))
    return str(path)


# ---------------------------------------------------------------- load_ignore_rules

def test_missing_file_gives_empty_list(tmp_path):
    assert noise.load_ignore_rules(str(tmp_path / "nope.txt")) == []


def test_empty_file_gives_empty_list(tmp_path):
    assert noise.load_ignore_rules(write(tmp_path, "")) == []


def test_only_comments_and_blank_lines_give_empty_list(tmp_path):
    assert noise.load_ignore_rules(write(tmp_path, "# a\n\n   \n# ip.* *.example.com\n")) == []


def test_the_ignore_txt_in_the_repo_ignores_nothing():
    assert noise.IGNORE_FILE.name == "ignore.txt"
    assert noise.IGNORE_FILE.exists()
    assert noise.load_ignore_rules() == []


def test_rules_are_read_in_order_with_comments_and_spacing(tmp_path):
    text = (
        "# header\n"
        "ip.*   *.example.com\n"
        "\n"
        "\ttech.version_changed\tcdn.example.com   # inline comment\n"
        "port.closed old.example.com\n"
    )
    assert noise.load_ignore_rules(write(tmp_path, text)) == [
        {"kind": "ip.*", "host": "*.example.com"},
        {"kind": "tech.version_changed", "host": "cdn.example.com"},
        {"kind": "port.closed", "host": "old.example.com"},
    ]


def test_windows_line_endings_and_bom_are_accepted(tmp_path):
    text = "\ufeff# comment\nip.* *.example.com\nhost.new a.example.com\n"
    path = write(tmp_path, text, newline="\r\n")
    assert noise.load_ignore_rules(path) == [
        {"kind": "ip.*", "host": "*.example.com"},
        {"kind": "host.new", "host": "a.example.com"},
    ]


@pytest.mark.parametrize("bad", ["onlyonetoken", "too many tokens here", "ip.* a b"])
def test_bad_line_is_skipped_with_a_warning_and_good_lines_survive(tmp_path, caplog, bad):
    path = write(tmp_path, f"ip.* *.example.com\n{bad}\nport.opened db.example.com\n")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        rules = noise.load_ignore_rules(path)
    assert rules == [
        {"kind": "ip.*", "host": "*.example.com"},
        {"kind": "port.opened", "host": "db.example.com"},
    ]
    assert "line 2" in caplog.text and "skipped" in caplog.text


def test_unknown_kind_pattern_warns_but_is_kept(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        rules = noise.load_ignore_rules(write(tmp_path, "ip.neww *.example.com\n"))
    assert rules == [{"kind": "ip.neww", "host": "*.example.com"}]
    assert "matches no known kind" in caplog.text


def test_unreadable_file_gives_empty_list_with_warning(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert noise.load_ignore_rules(str(tmp_path)) == []  # a folder, not a file
    assert "unreadable" in caplog.text


def test_file_with_invalid_utf8_gives_empty_list_with_warning(tmp_path, caplog):
    path = tmp_path / "ignore.txt"
    path.write_bytes(b"ip.* \xff\xfe.example.com\n")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert noise.load_ignore_rules(str(path)) == []
    assert "unreadable" in caplog.text


def test_path_can_be_a_path_object(tmp_path):
    path = tmp_path / "ignore.txt"
    path.write_text("ip.* *.example.com\n", encoding="utf-8")
    assert noise.load_ignore_rules(path) == [{"kind": "ip.*", "host": "*.example.com"}]


# -------------------------------------------------------------- apply_ignore_rules

def test_wildcard_in_kind_and_host():
    changes = [
        change("ip.new", "a.example.com"),
        change("ip.removed", "b.example.com"),
        change("port.opened", "a.example.com"),
        change("ip.new", "other.org"),
    ]
    rules = [{"kind": "ip.*", "host": "*.example.com"}]
    kept, ignored = noise.apply_ignore_rules(changes, rules)
    assert ignored == [changes[0], changes[1]]
    assert kept == [changes[2], changes[3]]


def test_exact_kind_and_exact_host():
    changes = [change("tech.new", "cdn.example.com"), change("tech.new", "www.example.com")]
    kept, ignored = noise.apply_ignore_rules(changes, [{"kind": "tech.new", "host": "cdn.example.com"}])
    assert ignored == [changes[0]] and kept == [changes[1]]


@pytest.mark.parametrize("rule", [
    {"kind": "IP.*", "host": "*.EXAMPLE.com"},
    {"kind": "Ip.New", "host": "*.Example.COM"},
    {"kind": "ip.*", "host": "*.example.com"},
])
def test_matching_ignores_letter_case_in_rule(rule):
    _, ignored = noise.apply_ignore_rules([change("ip.new", "a.example.com")], [rule])
    assert len(ignored) == 1


def test_matching_ignores_letter_case_in_the_change():
    upper = change("IP.NEW", "A.Example.COM")
    _, ignored = noise.apply_ignore_rules([upper], [{"kind": "ip.*", "host": "*.example.com"}])
    assert ignored == [upper]


def test_both_kind_and_host_must_match():
    changes = [change("port.opened", "a.example.com"), change("ip.new", "a.other.org")]
    kept, ignored = noise.apply_ignore_rules(changes, [{"kind": "ip.*", "host": "*.example.com"}])
    assert ignored == [] and kept == changes


def test_star_host_does_not_match_the_bare_domain():
    bare = change("ip.new", "example.com")
    kept, ignored = noise.apply_ignore_rules([bare], [{"kind": "ip.*", "host": "*.example.com"}])
    assert kept == [bare] and ignored == []
    _, ignored = noise.apply_ignore_rules([bare], [{"kind": "ip.*", "host": "example.com"}])
    assert ignored == [bare]


def test_no_rules_keeps_everything():
    changes = [change("ip.new", "a.example.com"), change("host.new", "b.example.com")]
    assert noise.apply_ignore_rules(changes, []) == (changes, [])


def test_no_changes_gives_two_empty_lists():
    assert noise.apply_ignore_rules([], [{"kind": "*", "host": "*"}]) == ([], [])


def test_any_matching_rule_is_enough():
    changes = [change("ip.new", "a.example.com"), change("tech.new", "b.example.com")]
    rules = [{"kind": "tech.*", "host": "b.example.com"}, {"kind": "ip.*", "host": "a.example.com"}]
    kept, ignored = noise.apply_ignore_rules(changes, rules)
    assert kept == [] and ignored == changes


def test_input_is_never_changed_and_unmatched_changes_are_untouched():
    changes = [change("ip.new", "a.example.com", after={"ip": "203.0.113.1"}),
               change("port.opened", "a.example.com", port=3306)]
    rules = [{"kind": "ip.*", "host": "*.example.com"}]
    changes_before, rules_before = copy.deepcopy(changes), copy.deepcopy(rules)
    kept, ignored = noise.apply_ignore_rules(changes, rules)
    assert changes == changes_before and rules == rules_before
    assert kept[0] is changes[1]  # same object, not even a copy
    assert ignored[0] == changes_before[0]


def test_kept_plus_ignored_is_every_change_exactly_once_in_order():
    rng = random.Random(7)
    hosts = ["a.example.com", "b.example.com", "example.com", "x.other.org", "cdn.other.org"]
    changes = [change(rng.choice(noise.KINDS), rng.choice(hosts), port=i) for i in range(200)]
    rules = [{"kind": "ip.*", "host": "*.example.com"}, {"kind": "tech.*", "host": "*.org"}]
    kept, ignored = noise.apply_ignore_rules(changes, rules)
    assert len(kept) + len(ignored) == len(changes)
    assert sorted(c["port"] for c in kept + ignored) == list(range(200))  # each exactly once
    for part in (kept, ignored):
        assert [c["port"] for c in part] == sorted(c["port"] for c in part)  # original order
    assert ignored and kept  # the sample really exercised both sides


def test_malformed_changes_and_rules_do_not_crash_and_are_never_lost():
    weird = [None, "text", {"no": "kind"}, change("ip.new", "a.example.com")]
    rules = [None, {"kind": "ip.*"}, {"host": "*"}, {"kind": 1, "host": 2},
             {"kind": "ip.*", "host": "*.example.com"}]
    kept, ignored = noise.apply_ignore_rules(weird, rules)
    assert ignored == [weird[3]]
    assert kept == weird[:3]


# --------------------------------------------------------------- confirmed_removals
# Three tiny scans, oldest first. Each scan is just a list of hosts here; the
# fakes below stand in for Marwan's compare_scans and present_in.

def scan(*hosts):
    return {"target": "example.com", "assets": [{"host": h} for h in hosts]}


def hosts_of(s):
    return {a["host"] for a in s["assets"]}


class FakeCompare:
    def __init__(self):
        self.compare_calls = []
        self.present_calls = []

    def compare_scans(self, a, b):
        self.compare_calls.append((a, b))
        changes = []
        for h in sorted(hosts_of(a) - hosts_of(b)):
            changes.append(change("host.removed", h, status="missing", before={"host": h}))
        for h in sorted(hosts_of(b) - hosts_of(a)):
            changes.append(change("host.new", h, after={"host": h}))
        return {"changes": changes}

    def present_in(self, s, c):
        self.present_calls.append((s, c))
        return c["host"] in hosts_of(s)


@pytest.fixture
def fake(monkeypatch):
    f = FakeCompare()
    monkeypatch.setattr(noise, "compare_scans", f.compare_scans)
    monkeypatch.setattr(noise, "present_in", f.present_in)
    return f


def test_removal_missing_twice_is_confirmed(fake):
    A, B, C = scan("www.example.com", "old.example.com"), scan("www.example.com"), scan("www.example.com")
    result = noise.confirmed_removals(A, B, C)
    assert len(result) == 1
    assert result[0]["kind"] == "host.removed"
    assert result[0]["host"] == "old.example.com"
    assert result[0]["status"] == "confirmed"


def test_removal_that_came_back_is_not_confirmed(fake):
    A = scan("www.example.com", "old.example.com")
    B = scan("www.example.com")
    C = scan("www.example.com", "old.example.com")
    assert noise.confirmed_removals(A, B, C) == []


def test_only_removals_are_returned(fake):
    A = scan("a.example.com", "gone.example.com")
    B = scan("a.example.com", "new.example.com")  # one removed, one brand new
    C = scan("a.example.com", "new.example.com")
    result = noise.confirmed_removals(A, B, C)
    assert [c["host"] for c in result] == ["gone.example.com"]


def test_nothing_removed_gives_empty_list(fake):
    A = B = C = scan("a.example.com")
    assert noise.confirmed_removals(A, B, C) == []


def test_several_removals_keep_the_order_from_compare_scans(fake):
    A = scan("a.example.com", "b.example.com", "c.example.com", "d.example.com")
    B = scan("d.example.com")
    C = scan("b.example.com", "d.example.com")  # b came back
    result = noise.confirmed_removals(A, B, C)
    assert [c["host"] for c in result] == ["a.example.com", "c.example.com"]


def test_it_uses_compare_scans_on_the_first_two_and_present_in_on_the_third(fake):
    A, B, C = scan("x.example.com"), scan(), scan()
    noise.confirmed_removals(A, B, C)
    assert fake.compare_calls == [(A, B)]
    assert len(fake.present_calls) == 1 and fake.present_calls[0][0] is C


def test_scans_and_the_original_change_are_not_changed(fake, monkeypatch):
    A, B, C = scan("x.example.com"), scan(), scan()
    snapshot = copy.deepcopy((A, B, C))
    original = fake.compare_scans(A, B)["changes"][0]
    assert original["status"] == "missing"
    monkeypatch.setattr(noise, "compare_scans", lambda a, b: {"changes": [original]})
    result = noise.confirmed_removals(A, B, C)
    assert result[0]["status"] == "confirmed" and result[0] is not original
    assert original["status"] == "missing"          # the candidate keeps its own status
    assert (A, B, C) == snapshot


@pytest.mark.parametrize("kind", sorted(noise.REMOVAL_KINDS))
def test_every_removal_kind_can_be_confirmed(monkeypatch, kind):
    candidate = change(kind, "h.example.com", status="missing")
    monkeypatch.setattr(noise, "compare_scans", lambda a, b: {"changes": [candidate]})
    monkeypatch.setattr(noise, "present_in", lambda s, c: False)
    assert noise.confirmed_removals({}, {}, {})[0]["kind"] == kind


@pytest.mark.parametrize("kind", sorted(set(noise.KINDS) - noise.REMOVAL_KINDS))
def test_non_removal_kinds_are_never_returned(monkeypatch, kind):
    monkeypatch.setattr(noise, "compare_scans", lambda a, b: {"changes": [change(kind, "h.example.com")]})
    monkeypatch.setattr(noise, "present_in", lambda s, c: False)
    assert noise.confirmed_removals({}, {}, {}) == []


def test_compare_scans_may_return_a_plain_list(monkeypatch):
    candidate = change("port.closed", "h.example.com", status="missing", port=22)
    monkeypatch.setattr(noise, "compare_scans", lambda a, b: [candidate])
    monkeypatch.setattr(noise, "present_in", lambda s, c: False)
    assert noise.confirmed_removals({}, {}, {})[0]["port"] == 22


def test_clear_error_when_compare_code_is_not_available(monkeypatch):
    monkeypatch.setattr(noise, "compare_scans", None)
    monkeypatch.setattr(noise, "present_in", None)
    with pytest.raises(RuntimeError, match="not available"):
        noise.confirmed_removals({}, {}, {})


def test_ignore_rules_and_confirmation_work_together(fake):
    A = scan("www.example.com", "cdn.example.com", "old.example.com")
    B, C = scan("www.example.com"), scan("www.example.com")
    removals = noise.confirmed_removals(A, B, C)
    kept, ignored = noise.apply_ignore_rules(removals, [{"kind": "host.removed", "host": "cdn.*"}])
    assert [c["host"] for c in kept] == ["old.example.com"]
    assert [c["host"] for c in ignored] == ["cdn.example.com"]
