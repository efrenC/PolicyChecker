import json

import pytest
from fastapi.testclient import TestClient

import config
from app import app

client = TestClient(app)


def body(*datasets):
    return {"Datasets": list(datasets)}


def test_health_and_security_headers():
    r = client.get("/health")
    assert r.json() == {"status": "ok"}
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_classify_happy_path(make_ds, audit_entries):
    r = client.post("/classify", json=body(make_ds("A", "Internal"), make_ds("B", "Restricted")))
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ResultingSecurityClassification"] == "Restricted"
    assert data["AllPolicyLinksReachable"] is True
    assert [c["Status"] for c in data["PolicyChecks"]] == ["reachable", "reachable"]
    assert data["AuditLogId"].startswith("audit-")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert audit_entries()[-1]["outcome"] == "classified"


def test_four_datasets_allowed(make_ds):
    r = client.post("/classify", json=body(*[make_ds(f"D{i}") for i in range(4)]))
    assert r.status_code == 200, r.text


def test_names_are_trimmed(make_ds):
    r = client.post("/classify", json=body(dict(make_ds("A"), Name="  Sales  "), make_ds("B")))
    assert r.status_code == 200
    assert r.json()["Datasets"][0]["Name"] == "Sales"


@pytest.mark.parametrize(
    "datasets",
    [
        pytest.param(lambda m: [m("A")], id="single-dataset"),
        pytest.param(lambda m: [m(f"D{i}") for i in range(5)], id="five-datasets"),
        pytest.param(lambda m: [m("A", "Blue"), m("B")], id="bad-classification"),
        pytest.param(lambda m: [m("A", link="http://x.example.com"), m("B")], id="http-link"),
        pytest.param(lambda m: [dict(m("A"), Name=""), m("B")], id="empty-name"),
        pytest.param(lambda m: [dict(m("A"), Name="   "), m("B")], id="blank-name"),
        pytest.param(lambda m: [dict(m("A"), Description=" \t "), m("B")], id="blank-description"),
        pytest.param(lambda m: [dict(m("A"), Name="x" * 201), m("B")], id="name-too-long"),
        pytest.param(lambda m: [dict(m("A"), Owner="me"), m("B")], id="unknown-field"),
        pytest.param(lambda m: [{"Name": "A"}, m("B")], id="missing-fields"),
    ],
)
def test_invalid_requests_return_422_and_are_audited(make_ds, audit_entries, datasets):
    r = client.post("/classify", json=body(*datasets(make_ds)))
    assert r.status_code == 422, r.text
    audit_id = r.json()["AuditLogId"]
    [entry] = audit_entries()
    assert entry["audit_log_id"] == audit_id
    assert entry["outcome"] == "rejected" and entry["stage"] == "api"
    assert entry["errors"]


def test_malformed_json_is_rejected_and_audited(audit_entries):
    r = client.post("/classify", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 422
    assert audit_entries()[-1]["outcome"] == "rejected"


def test_oversized_body_is_rejected_and_audited(make_ds, audit_entries):
    padded = body(
        dict(make_ds("A"), Description="x" * (config.MAX_REQUEST_BYTES + 1)), make_ds("B")
    )
    r = client.post("/classify", json=padded)
    assert r.status_code == 413
    assert r.json()["AuditLogId"] == audit_entries()[-1]["audit_log_id"]


def test_oversized_body_without_content_length_is_rejected(make_ds):
    payload = json.dumps(
        body(dict(make_ds("A"), Description="x" * (config.MAX_REQUEST_BYTES + 1)), make_ds("B"))
    ).encode()

    def chunks():
        for i in range(0, len(payload), 1024):
            yield payload[i : i + 1024]

    r = client.post("/classify", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_error_responses_do_not_leak_internals(make_ds, monkeypatch):
    import app as app_module

    def explode(datasets):
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(app_module, "run_classification_graph", explode)
    quiet = TestClient(app, raise_server_exceptions=False)
    r = quiet.post("/classify", json=body(make_ds("A"), make_ds("B")))
    assert r.status_code == 500
    assert "hunter2" not in r.text
