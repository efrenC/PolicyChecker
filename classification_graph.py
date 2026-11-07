"""Classification pipeline.

Each step takes the shared state, adds its result, and passes it on:

    validate_datasets -> check_policy_links -> compute_max_risk
        -> write_audit_log -> return_result

The resulting classification follows the max-risk (high-water mark) rule:
combining datasets produces data at least as sensitive as the most
sensitive input. If validation fails, the rejection is audited and a
ClassificationRejected error is raised.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import config
import link_checker
from audit import append_audit_entry, audit_rejection
from classifications import SECURITY_ORDER, VALID_CLASSES

HTTPS_PATTERN = re.compile(r"^https://.+")

LinkChecker = Callable[[str], dict[str, Any]]


class ClassificationRejected(ValueError):
    """Input failed the pipeline's rules. The rejection has been audited."""

    def __init__(self, errors: list[str], audit_log_id: str):
        super().__init__(f"Validation failed: {errors}")
        self.errors = errors
        self.audit_log_id = audit_log_id


class ClassificationState(dict):
    """State passed between pipeline steps."""

    @property
    def datasets(self) -> list[dict[str, Any]]:
        return self.get("datasets", [])

    @datasets.setter
    def datasets(self, value: list[dict[str, Any]]) -> None:
        self["datasets"] = value

    @property
    def resulting_classification(self) -> str | None:
        return self.get("resulting_classification")

    @resulting_classification.setter
    def resulting_classification(self, value: str) -> None:
        self["resulting_classification"] = value


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------


def _blank(value: Any) -> bool:
    return not isinstance(value, str) or not value.strip()


def validate_datasets(state: ClassificationState) -> ClassificationState:
    """Business-rule validation.

    The API already validates through Pydantic; this repeats the checks so the
    pipeline is safe to call directly (batch jobs, other agents, tests).
    Raises ValueError listing every problem found.
    """
    errors: list[str] = []
    count = len(state.datasets)

    if count < config.MIN_DATASETS:
        errors.append(f"At least {config.MIN_DATASETS} datasets are required for comparison.")
    if count > config.MAX_DATASETS:
        errors.append(f"At most {config.MAX_DATASETS} datasets can be compared at once.")

    for idx, ds in enumerate(state.datasets):
        prefix = f"Dataset[{idx}]"

        if _blank(ds.get("Name")):
            errors.append(f"{prefix}: Name is required.")

        if _blank(ds.get("Description")):
            errors.append(f"{prefix}: Description is required.")

        sc = ds.get("SecurityClassification")
        if sc not in VALID_CLASSES:
            errors.append(
                f"{prefix}: Invalid SecurityClassification '{sc}'. Allowed: {list(SECURITY_ORDER)}"
            )

        link = ds.get("PolicyLink")
        if not isinstance(link, str) or not HTTPS_PATTERN.match(link):
            errors.append(f"{prefix}: PolicyLink must be a non-empty HTTPS URL.")

    state["validation"] = {"is_valid": not errors, "errors": errors}

    if errors:
        raise ValueError(errors)

    return state


def _overall_reachability(statuses: list[str]) -> bool | None:
    if any(s in ("unreachable", "blocked") for s in statuses):
        return False
    if any(s == "not checked" for s in statuses):
        return None
    return True


def check_policy_links(
    state: ClassificationState, checker: LinkChecker | None = None
) -> ClassificationState:
    """Record whether each policy link is reachable, checking links in parallel.

    A failed or blocked link is reported, not treated as an error: the
    classification is still computed, and the result flags the problem.
    """
    if checker is None:
        checker = (
            link_checker.skipped_link_checker
            if config.SKIP_LINK_CHECK
            else link_checker.http_link_checker
        )

    links = [ds["PolicyLink"] for ds in state.datasets]
    with ThreadPoolExecutor(max_workers=max(1, len(links))) as pool:
        outcomes = list(pool.map(checker, links))

    results = [
        {
            "Name": ds["Name"],
            "PolicyLink": ds["PolicyLink"],
            "Status": outcome["status"],
            "Reachable": outcome.get("reachable"),
            "StatusCode": outcome.get("status_code"),
            "Error": outcome.get("error"),
        }
        for ds, outcome in zip(state.datasets, outcomes, strict=True)
    ]

    state["policy_checks"] = {
        "all_reachable": _overall_reachability([r["Status"] for r in results]),
        "results": results,
    }
    return state


def compute_max_risk(state: ClassificationState) -> ClassificationState:
    """Highest classification among the inputs wins."""
    state.resulting_classification = max(
        (ds["SecurityClassification"] for ds in state.datasets),
        key=SECURITY_ORDER.__getitem__,
    )
    return state


def write_audit_log(
    state: ClassificationState, log_path: Path | None = None
) -> ClassificationState:
    """Append the completed decision to the audit log and record its ID."""
    audit_entry = {
        "outcome": "classified",
        "datasets": state.datasets,
        "resulting_classification": state.resulting_classification,
        "validation": state.get("validation"),
        "policy_checks": state.get("policy_checks"),
    }
    state["audit_log_id"] = append_audit_entry(dict(audit_entry), log_path=log_path)
    state["audit_entry"] = audit_entry
    return state


def return_result(state: ClassificationState) -> dict[str, Any]:
    return {
        "Datasets": state.datasets,
        "ResultingSecurityClassification": state.resulting_classification,
        "AllPolicyLinksReachable": state["policy_checks"]["all_reachable"],
        "PolicyChecks": state["policy_checks"]["results"],
        "AuditLogId": state["audit_log_id"],
    }


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def run_classification_graph(
    datasets: list[dict[str, Any]],
    link_checker: LinkChecker | None = None,
    audit_log_path: Path | None = None,
) -> dict[str, Any]:
    state = ClassificationState()
    state.datasets = datasets

    try:
        state = validate_datasets(state)
    except ValueError as exc:
        errors = exc.args[0] if exc.args and isinstance(exc.args[0], list) else [str(exc)]
        audit_id = audit_rejection("pipeline", errors, datasets, log_path=audit_log_path)
        raise ClassificationRejected(errors, audit_id) from exc

    state = check_policy_links(state, checker=link_checker)
    state = compute_max_risk(state)
    state = write_audit_log(state, log_path=audit_log_path)
    return return_result(state)
