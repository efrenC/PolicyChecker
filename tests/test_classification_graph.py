import pytest

import classification_graph as cg
import config


def checker_returning(status, code=None, error=None):
    reachable = {"reachable": True, "not checked": None}.get(status, False)
    return lambda url: {
        "status": status,
        "reachable": reachable,
        "status_code": code,
        "error": error,
    }


# ---- max-risk rule -------------------------------------------------------


@pytest.mark.parametrize(
    "inputs, expected",
    [
        (["Public", "Internal"], "Internal"),
        (["Restricted", "Internal"], "Restricted"),
        (["Confidential", "Restricted", "Public"], "Restricted"),
        (["Internal", "Internal"], "Internal"),
        (["Public", "Public"], "Public"),
        (["Public", "Internal", "Confidential", "Public"], "Confidential"),
    ],
)
def test_max_risk_rule(make_ds, inputs, expected):
    datasets = [make_ds(f"D{i}", c) for i, c in enumerate(inputs)]
    result = cg.run_classification_graph(datasets)
    assert result["ResultingSecurityClassification"] == expected


def test_order_of_inputs_does_not_matter(make_ds):
    a = cg.run_classification_graph([make_ds("A", "Restricted"), make_ds("B", "Public")])
    b = cg.run_classification_graph([make_ds("B", "Public"), make_ds("A", "Restricted")])
    assert a["ResultingSecurityClassification"] == b["ResultingSecurityClassification"]


# ---- validation ----------------------------------------------------------


def test_requires_at_least_two_datasets(make_ds):
    with pytest.raises(cg.ClassificationRejected, match="At least 2 datasets"):
        cg.run_classification_graph([make_ds()])


def test_allows_at_most_four_datasets(make_ds):
    datasets = [make_ds(f"D{i}") for i in range(config.MAX_DATASETS + 1)]
    with pytest.raises(cg.ClassificationRejected, match="At most 4 datasets"):
        cg.run_classification_graph(datasets)


def test_rejects_unknown_classification(make_ds):
    with pytest.raises(cg.ClassificationRejected, match="Invalid SecurityClassification"):
        cg.run_classification_graph([make_ds("A", "Secret"), make_ds("B")])


def test_rejects_non_https_link(make_ds):
    bad = make_ds("A", link="http://policies.example.com/a")
    with pytest.raises(cg.ClassificationRejected, match="HTTPS"):
        cg.run_classification_graph([bad, make_ds("B")])


def test_rejects_whitespace_only_name_and_description(make_ds):
    bad = dict(make_ds("A"), Name="   ", Description="\t ")
    with pytest.raises(cg.ClassificationRejected) as exc:
        cg.run_classification_graph([bad, make_ds("B")])
    assert "Dataset[0]: Name is required." in exc.value.errors
    assert "Dataset[0]: Description is required." in exc.value.errors


def test_reports_all_errors_at_once(make_ds):
    bad = {"Name": "", "Description": "", "SecurityClassification": "X", "PolicyLink": ""}
    with pytest.raises(cg.ClassificationRejected) as exc:
        cg.run_classification_graph([bad, make_ds("B")])
    assert len(exc.value.errors) == 4


def test_rejection_is_audited(make_ds, audit_entries):
    with pytest.raises(cg.ClassificationRejected) as exc:
        cg.run_classification_graph([make_ds()])
    [entry] = audit_entries()
    assert entry["audit_log_id"] == exc.value.audit_log_id
    assert entry["outcome"] == "rejected"
    assert entry["stage"] == "pipeline"
    assert entry["received"] == [make_ds()]


# ---- policy link checks --------------------------------------------------


def test_failed_link_is_flagged_but_classification_still_computed(make_ds):
    def checker(url):
        status = "unreachable" if url.endswith("/b") else "reachable"
        return checker_returning(status, 404 if status == "unreachable" else 200)(url)

    result = cg.run_classification_graph(
        [make_ds("A", "Internal"), make_ds("B", "Restricted")], link_checker=checker
    )
    assert result["AllPolicyLinksReachable"] is False
    assert result["ResultingSecurityClassification"] == "Restricted"
    b = next(c for c in result["PolicyChecks"] if c["Name"] == "B")
    assert b["Status"] == "unreachable" and b["StatusCode"] == 404


def test_blocked_link_counts_as_not_reachable(make_ds):
    result = cg.run_classification_graph(
        [make_ds("A"), make_ds("B")], link_checker=checker_returning("blocked")
    )
    assert result["AllPolicyLinksReachable"] is False


def test_skipped_checks_are_reported_as_not_checked(make_ds, monkeypatch):
    monkeypatch.setattr(config, "SKIP_LINK_CHECK", True)
    result = cg.run_classification_graph([make_ds("A"), make_ds("B")])
    assert result["AllPolicyLinksReachable"] is None
    for check in result["PolicyChecks"]:
        assert check["Status"] == "not checked"
        assert check["Reachable"] is None


def test_check_results_keep_input_order(make_ds):
    datasets = [make_ds(f"D{i}") for i in range(4)]
    result = cg.run_classification_graph(datasets)
    assert [c["Name"] for c in result["PolicyChecks"]] == ["D0", "D1", "D2", "D3"]


# ---- audit log -----------------------------------------------------------


def test_audit_entry_is_persisted(make_ds, audit_entries):
    result = cg.run_classification_graph([make_ds("A", "Internal"), make_ds("B", "Confidential")])

    [entry] = audit_entries()
    assert entry["audit_log_id"] == result["AuditLogId"]
    assert entry["outcome"] == "classified"
    assert entry["resulting_classification"] == "Confidential"
    assert entry["validation"]["is_valid"] is True
    assert entry["timestamp"].endswith("+00:00")


def test_audit_ids_are_unique(make_ds, audit_entries):
    ids = {
        cg.run_classification_graph([make_ds("A"), make_ds("B")])["AuditLogId"] for _ in range(20)
    }
    assert len(ids) == 20
    assert len(audit_entries()) == 20


# ---- classification scheme -----------------------------------------------


def test_scheme_ranks_levels_in_declared_order():
    from classifications import SECURITY_ORDER, SecurityLevel

    assert list(SECURITY_ORDER) == [level.value for level in SecurityLevel]
    assert list(SECURITY_ORDER.values()) == list(range(1, len(SecurityLevel) + 1))
    assert SECURITY_ORDER["Public"] < SECURITY_ORDER["Restricted"]
