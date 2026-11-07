import json

import pytest

import config
import link_checker


def make_dataset(name="A", classification="Internal", link=None):
    return {
        "Name": name,
        "Description": f"{name} description",
        "SecurityClassification": classification,
        "PolicyLink": link or f"https://policies.example.com/{name.lower()}",
    }


@pytest.fixture
def make_ds():
    return make_dataset


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    """Keep tests offline and write audit logs to a temp file."""
    audit_path = tmp_path / "audit_log.jsonl"
    monkeypatch.setattr(config, "AUDIT_LOG_PATH", audit_path)
    monkeypatch.setattr(config, "SKIP_LINK_CHECK", False)
    monkeypatch.setattr(
        link_checker,
        "http_link_checker",
        lambda url: {"status": "reachable", "reachable": True, "status_code": 200, "error": None},
    )
    return audit_path


@pytest.fixture
def audit_entries(isolate):
    def read():
        if not isolate.exists():
            return []
        return [json.loads(line) for line in isolate.read_text().splitlines()]

    return read
