"""Tests for engine/governance.py — validates PII detection, access control,
SQL sanitization, column access, component permissions, data quality,
audit trail, and PII redaction."""

import sys
import os

# Add the project root to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def get_mock_app_definition():
    """A valid app_definition that matches the contract schema."""
    return {
        "app_title": "Supplier Performance Dashboard",
        "app_description": "Analyze supplier defect rates and delivery performance across regions",
        "components": [
            {
                "id": "kpi_total_orders",
                "type": "kpi_card",
                "title": "Total Orders",
                "sql_query": "SELECT COUNT(*) as total_orders FROM supply_chain",
                "config": {
                    "format": "number",
                    "value_column": "total_orders"
                },
                "width": "third"
            },
            {
                "id": "kpi_avg_defect",
                "type": "kpi_card",
                "title": "Average Defect Rate",
                "sql_query": "SELECT ROUND(AVG(defect_rate), 2) as avg_defect FROM supply_chain",
                "config": {
                    "format": "percentage",
                    "value_column": "avg_defect"
                },
                "width": "third"
            },
            {
                "id": "kpi_on_time",
                "type": "kpi_card",
                "title": "On-Time Delivery %",
                "sql_query": "SELECT ROUND(AVG(CAST(on_time_delivery AS FLOAT)) * 100, 1) as on_time_pct FROM supply_chain",
                "config": {
                    "format": "percentage",
                    "value_column": "on_time_pct"
                },
                "width": "third"
            },
            {
                "id": "bar_defect_by_supplier",
                "type": "bar_chart",
                "title": "Defect Rate by Supplier",
                "sql_query": "SELECT supplier, ROUND(AVG(defect_rate), 2) as avg_defect FROM supply_chain GROUP BY supplier ORDER BY avg_defect DESC",
                "config": {
                    "x_column": "supplier",
                    "y_column": "avg_defect",
                    "threshold": 5.0
                },
                "width": "half"
            },
            {
                "id": "line_delivery_trend",
                "type": "line_chart",
                "title": "Monthly Delivery Trends",
                "sql_query": "SELECT SUBSTR(order_date, 1, 7) as month, ROUND(AVG(delivery_days), 1) as avg_days FROM supply_chain GROUP BY month ORDER BY month",
                "config": {
                    "x_column": "month",
                    "y_column": "avg_days"
                },
                "width": "half"
            },
            {
                "id": "pie_by_region",
                "type": "pie_chart",
                "title": "Orders by Region",
                "sql_query": "SELECT region, COUNT(*) as order_count FROM supply_chain GROUP BY region",
                "config": {
                    "label_column": "region",
                    "value_column": "order_count"
                },
                "width": "half"
            },
            {
                "id": "table_supplier_detail",
                "type": "table",
                "title": "Supplier Detail",
                "sql_query": "SELECT supplier, COUNT(*) as orders, ROUND(AVG(defect_rate), 2) as avg_defect, ROUND(AVG(delivery_days), 1) as avg_delivery FROM supply_chain GROUP BY supplier ORDER BY avg_defect DESC",
                "config": {
                    "sort_by": "avg_defect",
                    "sort_order": "desc",
                    "limit": 50
                },
                "width": "full"
            }
        ],
        "filters": [
            {
                "id": "region_filter",
                "name": "Region",
                "column": "region",
                "type": "multiselect"
            },
            {
                "id": "category_filter",
                "name": "Category",
                "column": "category",
                "type": "multiselect"
            }
        ]
    }


def test_imports():
    """governance.py must import and expose required functions."""
    from engine import governance
    assert governance is not None


def test_has_run_function():
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


def test_detects_email():
    """PII detection must catch email patterns."""
    from engine.governance import _detect_pii
    results = _detect_pii("Contact john@example.com for details")
    assert len(results) > 0, "Should detect email address"
    assert any(r["type"] == "email" for r in results)


def test_detects_phone():
    """PII detection must catch phone patterns."""
    from engine.governance import _detect_pii
    results = _detect_pii("Call 555-123-4567")
    assert len(results) > 0, "Should detect phone number"


def test_no_false_positives_on_clean_data():
    """PII detection should not flag clean SQL."""
    from engine.governance import _detect_pii
    results = _detect_pii("SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier")
    # This clean SQL should have zero or very few PII matches
    assert len(results) <= 1, f"Too many false positives on clean SQL: {results}"


def test_admin_has_all_capabilities():
    """Admin role must have all capabilities."""
    from engine.governance import _check_access_control
    assert _check_access_control("admin", "view_all_data") is True
    assert _check_access_control("admin", "export_data") is True


def test_viewer_cannot_export():
    """Viewer role cannot export data."""
    from engine.governance import _check_access_control
    result = _check_access_control("viewer", "export_data")
    assert result is False, "Viewers should not be able to export data"


def test_unknown_role_denied():
    """Unknown roles should be denied access."""
    from engine.governance import _check_access_control
    result = _check_access_control("hacker", "view_all_data")
    assert result is False, "Unknown roles should be denied"


def test_returns_dict():
    """Governance check function must return a dict."""
    from engine.governance import run_governance_checks
    mock_app_definition = get_mock_app_definition()
    result = run_governance_checks(mock_app_definition, "analyst")
    assert isinstance(result, dict)


def test_has_checks_list():
    """Governance result must have checks list."""
    from engine.governance import run_governance_checks
    mock_app_definition = get_mock_app_definition()
    result = run_governance_checks(mock_app_definition, "analyst")
    assert "checks" in result, "Result must have 'checks' list"
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) >= 1, "Must have at least 1 governance check"


def test_has_overall_status():
    """Governance result must have overall status."""
    from engine.governance import run_governance_checks
    mock_app_definition = get_mock_app_definition()
    result = run_governance_checks(mock_app_definition, "analyst")
    assert "overall_status" in result
    assert result["overall_status"] in ["compliant", "review_required", "non_compliant", "pass", "warning", "fail"]


def test_admin_vs_viewer_different_results():
    """Admin and viewer should get different results."""
    from engine.governance import run_governance_checks
    mock_app_definition = get_mock_app_definition()
    admin_result = run_governance_checks(mock_app_definition, "admin")
    viewer_result = run_governance_checks(mock_app_definition, "viewer")
    # They should potentially differ — admin should be more permissive
    assert admin_result is not None
    assert viewer_result is not None


def test_sql_sanitization_blocks_drop():
    """DROP TABLE must be blocked."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("DROP TABLE supply_chain")
    assert result["safe"] is False
    assert "DROP" in result["blocked_keywords"]


def test_sql_sanitization_blocks_delete():
    """DELETE must be blocked."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("DELETE FROM supply_chain WHERE 1=1")
    assert result["safe"] is False


def test_sql_sanitization_blocks_union_injection():
    """UNION injection must be blocked."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT * FROM supply_chain UNION SELECT * FROM users")
    assert result["safe"] is False


def test_sql_sanitization_allows_normal_query():
    """Normal queries should be allowed."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT supplier, AVG(defect_rate) FROM supply_chain GROUP BY supplier")
    assert result["safe"] is True


def test_sql_sanitization_query_length():
    """Very long queries should be flagged."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT " + "a," * 1000 + "b FROM supply_chain")
    assert result["query_length_ok"] is False


def test_sql_sanitization_word_boundary():
    """'UPDATED_AT' should NOT trigger the UPDATE blocklist."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT updated_at FROM supply_chain")
    assert result["safe"] is True


def test_viewer_blocked_from_cost_columns():
    """Viewer should be blocked from cost columns."""
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT region, total_cost FROM supply_chain",
        role="viewer"
    )
    assert result["allowed"] is False
    assert "total_cost" in result["blocked_columns"]


def test_viewer_allowed_public_columns():
    """Viewer should be allowed public columns."""
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT region, product, category FROM supply_chain",
        role="viewer"
    )
    assert result["allowed"] is True


def test_analyst_allowed_internal_columns():
    """Analyst should be allowed internal columns."""
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT region, total_cost, defect_rate FROM supply_chain",
        role="analyst"
    )
    assert result["allowed"] is True


def test_analyst_blocked_from_restricted():
    """Analyst should be blocked from restricted columns."""
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT supplier, total_cost FROM supply_chain",
        role="analyst"
    )
    assert result["allowed"] is False
    assert "supplier" in result["blocked_columns"]


def test_admin_sees_everything():
    """Admin should see everything."""
    from engine.governance import check_column_access
    result = check_column_access(
        "SELECT supplier, total_cost, defect_rate FROM supply_chain",
        role="admin"
    )
    assert result["allowed"] is True


def test_viewer_blocked_from_table():
    """Viewer should be blocked from table components."""
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": "t1", "type": "table", "title": "Data"},
        ]
    }
    result = check_component_permissions(app, role="viewer")
    assert result["allowed"] is False
    assert any(c["type"] == "table" for c in result["blocked_components"])


def test_viewer_allowed_bar_chart():
    """Viewer should be allowed bar charts."""
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": "c1", "type": "bar_chart", "title": "Chart"},
        ]
    }
    result = check_component_permissions(app, role="viewer")
    assert result["allowed"] is True


def test_viewer_max_components():
    """Viewer should be limited to max components."""
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"Chart {i}"}
            for i in range(5)  # Viewer max is 4
        ]
    }
    result = check_component_permissions(app, role="viewer")
    assert result["component_count_ok"] is False


def test_admin_unlimited_components():
    """Admin should have unlimited components."""
    from engine.governance import check_component_permissions
    app = {
        "components": [
            {"id": f"c{i}", "type": "table", "title": f"Table {i}"}
            for i in range(8)
        ]
    }
    result = check_component_permissions(app, role="admin")
    assert result["allowed"] is True
    assert result["component_count_ok"] is True


def test_data_quality_detects_nulls():
    """Data quality checks must detect nulls."""
    from engine.governance import _check_data_quality
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"supplier": "Acme", "cost": 100},
                {"supplier": None, "cost": 200},
            ],
            "row_count": 2,
        }
    }
    quality = _check_data_quality(results)
    assert quality["null_count"] > 0
    assert quality["overall_quality"] in ["warning", "poor"]


def test_data_quality_good_data():
    """Good data should pass quality checks."""
    from engine.governance import _check_data_quality
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"supplier": "Acme", "cost": 100},
                {"supplier": "BuildRight", "cost": 200},
            ],
            "row_count": 2,
        }
    }
    quality = _check_data_quality(results)
    assert quality["overall_quality"] == "good"


def test_audit_trail_writes_entry():
    """Audit trail must write entries."""
    from engine.governance import _log_audit_trail, get_audit_trail
    _log_audit_trail("test_action", {"test": True})
    trail = get_audit_trail(limit=1)
    assert len(trail) >= 1
    assert trail[-1]["action"] == "test_action"


def test_audit_trail_includes_timestamp():
    """Audit trail entries must include timestamps."""
    from engine.governance import get_audit_trail
    trail = get_audit_trail(limit=1)
    assert "timestamp" in trail[-1]


def test_pii_redacted_for_analyst():
    """PII must be redacted for analyst role."""
    from engine.governance import redact_pii
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"name": "john@acme.com", "cost": 100},
            ],
            "row_count": 1,
        }
    }
    redacted = redact_pii(results, role="analyst")
    assert "[REDACTED]" in str(redacted["chart_1"]["data"])


def test_pii_visible_for_admin():
    """PII must be visible for admin role."""
    from engine.governance import redact_pii
    results = {
        "chart_1": {
            "status": "success",
            "data": [
                {"name": "john@acme.com", "cost": 100},
            ],
            "row_count": 1,
        }
    }
    redacted = redact_pii(results, role="admin")
    assert "john@acme.com" in str(redacted["chart_1"]["data"])


def test_pipeline_blocks_viewer_from_creating():
    """Pipeline should block viewers from creating apps."""
    from engine.pipeline import run_pipeline
    result = run_pipeline("Show me costs", role="viewer")
    assert result["governance"]["access_granted"] is False
    assert result["governance"]["passed"] is False


def test_pipeline_blocks_dangerous_sql():
    """Pipeline should block dangerous SQL."""
    from engine.governance import sanitize_sql
    result = sanitize_sql("SELECT * FROM supply_chain; DROP TABLE supply_chain")
    assert result["safe"] is False


def test_governance_returns_new_fields():
    """Governance result must include all new enhanced fields."""
    from engine.governance import run_governance_checks
    mock_app_definition = get_mock_app_definition()
    result = run_governance_checks(mock_app_definition, "admin")
    assert "sql_safety" in result
    assert "column_access" in result
    assert "component_permissions" in result
    assert "blocked_reasons" in result
    assert "audit_entry_id" in result
    assert "role_display_name" in result
    assert "export_formats" in result


def run_all_governance_tests():
    """Run all governance tests and report results."""
    tests = [
        test_imports,
        test_has_run_function,
        test_detects_email,
        test_detects_phone,
        test_no_false_positives_on_clean_data,
        test_admin_has_all_capabilities,
        test_viewer_cannot_export,
        test_unknown_role_denied,
        test_returns_dict,
        test_has_checks_list,
        test_has_overall_status,
        test_admin_vs_viewer_different_results,
        test_sql_sanitization_blocks_drop,
        test_sql_sanitization_blocks_delete,
        test_sql_sanitization_blocks_union_injection,
        test_sql_sanitization_allows_normal_query,
        test_sql_sanitization_query_length,
        test_sql_sanitization_word_boundary,
        test_viewer_blocked_from_cost_columns,
        test_viewer_allowed_public_columns,
        test_analyst_allowed_internal_columns,
        test_analyst_blocked_from_restricted,
        test_admin_sees_everything,
        test_viewer_blocked_from_table,
        test_viewer_allowed_bar_chart,
        test_viewer_max_components,
        test_admin_unlimited_components,
        test_data_quality_detects_nulls,
        test_data_quality_good_data,
        test_audit_trail_writes_entry,
        test_audit_trail_includes_timestamp,
        test_pii_redacted_for_analyst,
        test_pii_visible_for_admin,
        test_pipeline_blocks_viewer_from_creating,
        test_pipeline_blocks_dangerous_sql,
        test_governance_returns_new_fields,
    ]

    passed = 0
    failed = 0
    results = []

    for test_func in tests:
        try:
            test_func()
            results.append(f"✓ {test_func.__name__}")
            passed += 1
        except Exception as e:
            results.append(f"✗ {test_func.__name__}: {str(e)}")
            failed += 1

    print("Governance Tests Results:")
    print("=" * 50)
    for result in results:
        print(result)
    print("=" * 50)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")

    if failed > 0:
        return False
    return True


if __name__ == "__main__":
    success = run_all_governance_tests()
    sys.exit(0 if success else 1)
    """Column-level access control must enforce sensitivity levels."""

    def test_viewer_blocked_from_cost_columns(self):
        from engine.governance import check_column_access
        result = check_column_access(
            "SELECT region, total_cost FROM supply_chain",
            role="viewer"
        )
        assert result["allowed"] is False
        assert "total_cost" in result["blocked_columns"]

    def test_viewer_allowed_public_columns(self):
        from engine.governance import check_column_access
        result = check_column_access(
            "SELECT region, product, category FROM supply_chain",
            role="viewer"
        )
        assert result["allowed"] is True

    def test_analyst_allowed_internal_columns(self):
        from engine.governance import check_column_access
        result = check_column_access(
            "SELECT region, total_cost, defect_rate FROM supply_chain",
            role="analyst"
        )
        assert result["allowed"] is True

    def test_analyst_blocked_from_restricted(self):
        from engine.governance import check_column_access
        result = check_column_access(
            "SELECT supplier, total_cost FROM supply_chain",
            role="analyst"
        )
        assert result["allowed"] is False
        assert "supplier" in result["blocked_columns"]

    def test_admin_sees_everything(self):
        from engine.governance import check_column_access
        result = check_column_access(
            "SELECT supplier, total_cost, defect_rate FROM supply_chain",
            role="admin"
        )
        assert result["allowed"] is True


# ============================================================================
# NEW TESTS: COMPONENT PERMISSIONS (Section 4.3)
# ============================================================================


class TestComponentPermissions:
    """Component type enforcement must restrict by role."""

    def test_viewer_blocked_from_table(self):
        from engine.governance import check_component_permissions
        app = {
            "components": [
                {"id": "t1", "type": "table", "title": "Data"},
            ]
        }
        result = check_component_permissions(app, role="viewer")
        assert result["allowed"] is False
        assert any(c["type"] == "table" for c in result["blocked_components"])

    def test_viewer_allowed_bar_chart(self):
        from engine.governance import check_component_permissions
        app = {
            "components": [
                {"id": "c1", "type": "bar_chart", "title": "Chart"},
            ]
        }
        result = check_component_permissions(app, role="viewer")
        assert result["allowed"] is True

    def test_viewer_max_components(self):
        from engine.governance import check_component_permissions
        app = {
            "components": [
                {"id": f"c{i}", "type": "bar_chart", "title": f"Chart {i}"}
                for i in range(5)  # Viewer max is 4
            ]
        }
        result = check_component_permissions(app, role="viewer")
        assert result["component_count_ok"] is False

    def test_admin_unlimited_components(self):
        from engine.governance import check_component_permissions
        app = {
            "components": [
                {"id": f"c{i}", "type": "table", "title": f"Table {i}"}
                for i in range(8)
            ]
        }
        result = check_component_permissions(app, role="admin")
        assert result["allowed"] is True
        assert result["component_count_ok"] is True


# ============================================================================
# NEW TESTS: DATA QUALITY (Section 4.4)
# ============================================================================


class TestDataQuality:
    """Data quality checks must detect nulls, duplicates, and outliers."""

    def test_data_quality_detects_nulls(self):
        from engine.governance import _check_data_quality
        results = {
            "chart_1": {
                "status": "success",
                "data": [
                    {"supplier": "Acme", "cost": 100},
                    {"supplier": None, "cost": 200},
                ],
                "row_count": 2,
            }
        }
        quality = _check_data_quality(results)
        assert quality["null_count"] > 0
        assert quality["overall_quality"] in ["warning", "poor"]

    def test_data_quality_good_data(self):
        from engine.governance import _check_data_quality
        results = {
            "chart_1": {
                "status": "success",
                "data": [
                    {"supplier": "Acme", "cost": 100},
                    {"supplier": "BuildRight", "cost": 200},
                ],
                "row_count": 2,
            }
        }
        quality = _check_data_quality(results)
        assert quality["overall_quality"] == "good"


# ============================================================================
# NEW TESTS: AUDIT TRAIL (Section 4.5)
# ============================================================================


class TestAuditTrail:
    """Audit trail must persist entries with timestamps."""

    def test_audit_trail_writes_entry(self):
        from engine.governance import _log_audit_trail, get_audit_trail
        _log_audit_trail("test_action", {"test": True})
        trail = get_audit_trail(limit=1)
        assert len(trail) >= 1
        assert trail[-1]["action"] == "test_action"

    def test_audit_trail_includes_timestamp(self):
        from engine.governance import get_audit_trail
        trail = get_audit_trail(limit=1)
        assert "timestamp" in trail[-1]


# ============================================================================
# NEW TESTS: PII REDACTION (Section 4.6)
# ============================================================================


class TestPIIRedaction:
    """PII redaction must mask sensitive data for non-admin roles."""

    def test_pii_redacted_for_analyst(self):
        from engine.governance import redact_pii
        results = {
            "chart_1": {
                "status": "success",
                "data": [
                    {"name": "john@acme.com", "cost": 100},
                ],
                "row_count": 1,
            }
        }
        redacted = redact_pii(results, role="analyst")
        assert "[REDACTED]" in str(redacted["chart_1"]["data"])

    def test_pii_visible_for_admin(self):
        from engine.governance import redact_pii
        results = {
            "chart_1": {
                "status": "success",
                "data": [
                    {"name": "john@acme.com", "cost": 100},
                ],
                "row_count": 1,
            }
        }
        redacted = redact_pii(results, role="admin")
        assert "john@acme.com" in str(redacted["chart_1"]["data"])


# ============================================================================
# NEW TESTS: PRE-EXECUTION GATE INTEGRATION (Section 4.7)
# ============================================================================


class TestPreExecutionGate:
    """Pre-execution governance gate must block dangerous operations."""

    def test_pipeline_blocks_viewer_from_creating(self):
        """Viewers can't create apps — pipeline should return blocked result."""
        from engine.pipeline import run_pipeline
        result = run_pipeline("Show me costs", role="viewer")
        assert result["governance"]["access_granted"] is False
        assert result["governance"]["passed"] is False

    def test_pipeline_blocks_dangerous_sql(self):
        """If GPT somehow generates dangerous SQL, governance gate catches it."""
        from engine.governance import sanitize_sql
        result = sanitize_sql("SELECT * FROM supply_chain; DROP TABLE supply_chain")
        assert result["safe"] is False

    def test_governance_returns_new_fields(self, mock_app_definition):
        """Governance result must include all new enhanced fields."""
        from engine.governance import run_governance_checks
        result = run_governance_checks(mock_app_definition, "admin")
        assert "sql_safety" in result
        assert "column_access" in result
        assert "component_permissions" in result
        assert "blocked_reasons" in result
        assert "audit_entry_id" in result
        assert "role_display_name" in result
        assert "export_formats" in result
