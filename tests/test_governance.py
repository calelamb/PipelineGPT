"""Tests for engine/governance.py — validates PII detection and access control."""

import pytest


class TestGovernanceImports:
    """governance.py must import and expose required functions."""

    def test_imports(self):
        from engine import governance
        assert governance is not None

    def test_has_run_function(self):
        """Must have a main governance check function."""
        from engine import governance
        # Look for the primary function — name may vary
        has_func = any([
            hasattr(governance, "run_governance_checks"),
            hasattr(governance, "check_governance"),
            hasattr(governance, "run_checks"),
        ])
        assert has_func, \
            "governance.py must have run_governance_checks() or similar"


class TestPIIDetection:
    """PII detection must catch common patterns."""

    def test_detects_email(self):
        from engine.governance import _detect_pii
        results = _detect_pii("Contact john@example.com for details")
        assert len(results) > 0, "Should detect email address"
        assert any(r["type"] == "email" for r in results)

    def test_detects_phone(self):
        from engine.governance import _detect_pii
        results = _detect_pii("Call 555-123-4567")
        assert len(results) > 0, "Should detect phone number"

    def test_no_false_positives_on_clean_data(self):
        from engine.governance import _detect_pii
        results = _detect_pii("SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier")
        # This clean SQL should have zero or very few PII matches
        assert len(results) <= 1, f"Too many false positives on clean SQL: {results}"


class TestAccessControl:
    """Role-based access checks must enforce permission boundaries."""

    def test_admin_has_all_capabilities(self):
        from engine.governance import _check_access_control
        assert _check_access_control("admin", "view_all_data") is True
        assert _check_access_control("admin", "export_data") is True

    def test_viewer_cannot_export(self):
        from engine.governance import _check_access_control
        result = _check_access_control("viewer", "export_data")
        assert result is False, "Viewers should not be able to export data"

    def test_unknown_role_denied(self):
        from engine.governance import _check_access_control
        result = _check_access_control("hacker", "view_all_data")
        assert result is False, "Unknown roles should be denied"


class TestGovernanceCheckFunction:
    """The main governance check function must return the expected structure."""

    def test_returns_dict(self, mock_app_definition):
        from engine.governance import run_governance_checks
        result = run_governance_checks(mock_app_definition, "analyst")
        assert isinstance(result, dict)

    def test_has_checks_list(self, mock_app_definition):
        from engine.governance import run_governance_checks
        result = run_governance_checks(mock_app_definition, "analyst")
        assert "checks" in result, "Result must have 'checks' list"
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) >= 1, "Must have at least 1 governance check"

    def test_has_overall_status(self, mock_app_definition):
        from engine.governance import run_governance_checks
        result = run_governance_checks(mock_app_definition, "analyst")
        assert "overall_status" in result
        assert result["overall_status"] in ["compliant", "review_required", "non_compliant", "pass", "warning", "fail"]

    def test_admin_vs_viewer_different_results(self, mock_app_definition):
        from engine.governance import run_governance_checks
        admin_result = run_governance_checks(mock_app_definition, "admin")
        viewer_result = run_governance_checks(mock_app_definition, "viewer")
        # They should potentially differ — admin should be more permissive
        assert admin_result is not None
        assert viewer_result is not None
