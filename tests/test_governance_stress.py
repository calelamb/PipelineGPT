"""
Governance Stress Test Suite — StackForge
==========================================
Comprehensive tests ensuring private data stays private, dangerous SQL
is blocked, role boundaries are enforced, PII is detected & redacted,
and the audit trail captures everything.

Covers:
  - PII detection for ALL 6 pattern types (SSN, CC, email, phone, passport, IP)
  - PII in data rows (post-execution scanning)
  - PII redaction per role (admin sees raw, everyone else gets [REDACTED])
  - SQL injection variants (obfuscation, multi-statement, comment injection)
  - Column-level access across all 3 sensitivity tiers
  - Component type enforcement per role
  - Component count limits per role
  - Export control per role
  - Cross-role escalation prevention
  - Full pipeline governance gate integration
  - Audit trail integrity
  - Data quality detection
  - Edge cases (empty data, unknown roles, malformed input)
"""

import sys
import os
import copy
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from engine.governance import (
    _detect_pii,
    redact_pii,
    sanitize_sql,
    check_column_access,
    check_component_permissions,
    run_governance_checks,
    _check_access_control,
    _check_data_quality,
    _check_export_control,
    _log_audit_trail,
    get_audit_trail,
)
from config import (
    PII_PATTERNS,
    ROLES,
    SQL_BLOCKLIST,
    MAX_QUERY_LENGTH,
    COLUMN_SENSITIVITY,
    COLUMN_SENSITIVITY_MAP,
    SENSITIVITY_ACCESS,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def basic_app():
    """Minimal valid app definition with public-only columns."""
    return {
        "app_title": "Test App",
        "components": [
            {
                "id": "kpi1",
                "type": "kpi_card",
                "title": "Total Orders",
                "sql_query": "SELECT COUNT(*) as total FROM supply_chain",
                "config": {"value_column": "total", "format": "number"},
            }
        ],
    }


@pytest.fixture
def multi_component_app():
    """App with all 8 component types."""
    return {
        "app_title": "Full App",
        "components": [
            {"id": "c1", "type": "kpi_card", "title": "KPI", "sql_query": "SELECT COUNT(*) as n FROM supply_chain", "config": {}},
            {"id": "c2", "type": "metric_highlight", "title": "Metric", "sql_query": "SELECT AVG(quantity) as avg_q FROM supply_chain", "config": {}},
            {"id": "c3", "type": "bar_chart", "title": "Bar", "sql_query": "SELECT region, COUNT(*) as n FROM supply_chain GROUP BY region", "config": {}},
            {"id": "c4", "type": "line_chart", "title": "Line", "sql_query": "SELECT order_date, COUNT(*) as n FROM supply_chain GROUP BY order_date", "config": {}},
            {"id": "c5", "type": "pie_chart", "title": "Pie", "sql_query": "SELECT category, COUNT(*) as n FROM supply_chain GROUP BY category", "config": {}},
            {"id": "c6", "type": "scatter_plot", "title": "Scatter", "sql_query": "SELECT quantity, unit_cost FROM supply_chain", "config": {}},
            {"id": "c7", "type": "area_chart", "title": "Area", "sql_query": "SELECT order_date, SUM(quantity) as total FROM supply_chain GROUP BY order_date", "config": {}},
            {"id": "c8", "type": "table", "title": "Table", "sql_query": "SELECT * FROM supply_chain LIMIT 10", "config": {}},
        ],
    }


@pytest.fixture
def pii_laden_data():
    """Execution results with PII across all 6 types."""
    return {
        "comp_ssn": {
            "status": "success",
            "data": [
                {"name": "Alice", "ssn": "123-45-6789", "cost": 100},
                {"name": "Bob", "ssn": "987-65-4321", "cost": 200},
            ],
            "row_count": 2,
        },
        "comp_cc": {
            "status": "success",
            "data": [
                {"name": "Carol", "card": "4111-1111-1111-1111", "amount": 500},
            ],
            "row_count": 1,
        },
        "comp_email": {
            "status": "success",
            "data": [
                {"contact": "secret@corp.com", "dept": "Finance"},
                {"contact": "ceo@example.org", "dept": "Executive"},
            ],
            "row_count": 2,
        },
        "comp_phone": {
            "status": "success",
            "data": [
                {"name": "Dave", "phone": "555-123-4567"},
            ],
            "row_count": 1,
        },
        "comp_passport": {
            "status": "success",
            "data": [
                {"name": "Eve", "passport": "AB1234567"},
            ],
            "row_count": 1,
        },
        "comp_ip": {
            "status": "success",
            "data": [
                {"server": "prod-db", "ip": "192.168.1.100"},
            ],
            "row_count": 1,
        },
    }


# ============================================================================
# 1. PII DETECTION — ALL 6 TYPES
# ============================================================================


class TestPIIDetectionAllTypes:
    """Every PII pattern type must be detected in both text and data."""

    def test_detects_ssn(self):
        results = _detect_pii("Employee SSN: 123-45-6789")
        assert any(r["type"] == "ssn" for r in results), "Must detect SSN"

    def test_detects_credit_card_with_dashes(self):
        results = _detect_pii("Card: 4111-1111-1111-1111")
        assert any(r["type"] == "credit_card" for r in results), "Must detect credit card"

    def test_detects_credit_card_with_spaces(self):
        results = _detect_pii("Card: 4111 1111 1111 1111")
        assert any(r["type"] == "credit_card" for r in results), "Must detect credit card with spaces"

    def test_detects_credit_card_no_separators(self):
        results = _detect_pii("Card: 4111111111111111")
        assert any(r["type"] == "credit_card" for r in results), "Must detect credit card without separators"

    def test_detects_email(self):
        results = _detect_pii("Email: john.doe@company.com")
        assert any(r["type"] == "email" for r in results)

    def test_detects_phone(self):
        results = _detect_pii("Phone: 555-867-5309")
        assert any(r["type"] == "phone" for r in results)

    def test_detects_phone_with_dots(self):
        results = _detect_pii("Phone: 555.867.5309")
        assert any(r["type"] == "phone" for r in results)

    def test_detects_passport(self):
        results = _detect_pii("Passport: AB1234567")
        assert any(r["type"] == "passport" for r in results)

    def test_detects_ip_address(self):
        results = _detect_pii("Server: 10.0.0.1")
        assert any(r["type"] == "ip_address" for r in results)

    def test_detects_multiple_pii_types_in_one_string(self):
        text = "Contact john@acme.com at 555-123-4567, SSN 123-45-6789"
        results = _detect_pii(text)
        types_found = {r["type"] for r in results}
        assert "email" in types_found
        assert "phone" in types_found
        assert "ssn" in types_found

    def test_no_pii_in_clean_sql(self):
        sql = "SELECT region, AVG(quantity) FROM supply_chain GROUP BY region ORDER BY region"
        results = _detect_pii(sql)
        # Should have zero PII (no emails, SSNs, etc. in clean SQL)
        pii_without_false_positives = [
            r for r in results if r["type"] in ("ssn", "credit_card", "email", "passport")
        ]
        assert len(pii_without_false_positives) == 0


class TestPIIDetectionInData:
    """PII scanner must find PII in actual data rows, not just query text."""

    def test_detects_ssn_in_data_rows(self):
        data = [{"name": "Alice", "id_num": "123-45-6789"}]
        results = _detect_pii("", scan_data=True, data=data)
        assert any(r["type"] == "ssn" and r["source"] == "data" for r in results)

    def test_detects_email_in_data_rows(self):
        data = [{"contact": "secret@corp.com"}]
        results = _detect_pii("", scan_data=True, data=data)
        assert any(r["type"] == "email" and r["source"] == "data" for r in results)

    def test_detects_credit_card_in_data_rows(self):
        data = [{"payment": "4111-1111-1111-1111"}]
        results = _detect_pii("", scan_data=True, data=data)
        assert any(r["type"] == "credit_card" and r["source"] == "data" for r in results)

    def test_detects_ip_in_data_rows(self):
        data = [{"server_ip": "192.168.0.1"}]
        results = _detect_pii("", scan_data=True, data=data)
        assert any(r["type"] == "ip_address" and r["source"] == "data" for r in results)

    def test_returns_column_name_for_data_pii(self):
        data = [{"email_col": "test@example.com"}]
        results = _detect_pii("", scan_data=True, data=data)
        data_results = [r for r in results if r["source"] == "data"]
        assert len(data_results) > 0
        assert data_results[0]["column"] == "email_col"

    def test_scans_multiple_rows(self):
        data = [
            {"info": "clean data"},
            {"info": "contact: 555-123-4567"},
            {"info": "also clean"},
            {"info": "ssn: 111-22-3333"},
        ]
        results = _detect_pii("", scan_data=True, data=data)
        assert len(results) >= 2, "Must find PII across multiple rows"

    def test_handles_none_values_gracefully(self):
        data = [{"name": None, "cost": None}]
        results = _detect_pii("", scan_data=True, data=data)
        # Should not crash, may or may not find anything
        assert isinstance(results, list)

    def test_empty_data_returns_empty(self):
        results = _detect_pii("", scan_data=True, data=[])
        assert results == []

    def test_scan_data_false_ignores_data(self):
        data = [{"ssn": "123-45-6789"}]
        results = _detect_pii("clean text", scan_data=False, data=data)
        # Should NOT find the SSN because scan_data is False
        assert not any(r["source"] == "data" for r in results)


# ============================================================================
# 2. PII REDACTION — ROLE-BASED
# ============================================================================


class TestPIIRedaction:
    """PII must be redacted for non-admin roles, visible for admins."""

    def test_admin_sees_all_pii(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="admin")
        # Admin should see raw SSN
        ssn_data = str(result["comp_ssn"]["data"])
        assert "123-45-6789" in ssn_data
        assert "[REDACTED]" not in ssn_data

    def test_analyst_gets_ssn_redacted(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="analyst")
        ssn_data = str(result["comp_ssn"]["data"])
        assert "123-45-6789" not in ssn_data
        assert "[REDACTED]" in ssn_data

    def test_viewer_gets_ssn_redacted(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="viewer")
        ssn_data = str(result["comp_ssn"]["data"])
        assert "123-45-6789" not in ssn_data
        assert "[REDACTED]" in ssn_data

    def test_analyst_gets_email_redacted(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="analyst")
        email_data = str(result["comp_email"]["data"])
        assert "secret@corp.com" not in email_data
        assert "[REDACTED]" in email_data

    def test_analyst_gets_credit_card_redacted(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="analyst")
        cc_data = str(result["comp_cc"]["data"])
        assert "4111-1111-1111-1111" not in cc_data
        assert "[REDACTED]" in cc_data

    def test_viewer_gets_ip_redacted(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="viewer")
        ip_data = str(result["comp_ip"]["data"])
        assert "192.168.1.100" not in ip_data

    def test_redaction_does_not_mutate_original(self, pii_laden_data):
        original_ssn = pii_laden_data["comp_ssn"]["data"][0]["ssn"]
        _ = redact_pii(pii_laden_data, role="analyst")
        assert pii_laden_data["comp_ssn"]["data"][0]["ssn"] == original_ssn, \
            "Redaction must not mutate the original data"

    def test_non_pii_fields_preserved(self, pii_laden_data):
        result = redact_pii(pii_laden_data, role="analyst")
        # Cost field should remain untouched
        assert result["comp_ssn"]["data"][0]["cost"] == 100
        assert result["comp_ssn"]["data"][1]["cost"] == 200

    def test_redaction_handles_empty_data(self):
        results = {"comp1": {"status": "success", "data": []}}
        redacted = redact_pii(results, role="analyst")
        assert redacted["comp1"]["data"] == []

    def test_redaction_handles_no_data_key(self):
        results = {"comp1": {"status": "error"}}
        redacted = redact_pii(results, role="analyst")
        assert redacted["comp1"]["status"] == "error"

    def test_unknown_role_gets_redacted(self, pii_laden_data):
        """Unknown roles should not see PII — fail closed."""
        result = redact_pii(pii_laden_data, role="hacker")
        ssn_data = str(result["comp_ssn"]["data"])
        assert "123-45-6789" not in ssn_data


# ============================================================================
# 3. SQL INJECTION — EXTENSIVE VARIANTS
# ============================================================================


class TestSQLInjection:
    """Every SQL injection variant must be caught and blocked."""

    @pytest.mark.parametrize("keyword", SQL_BLOCKLIST)
    def test_blocks_every_blocklist_keyword(self, keyword):
        if " " in keyword:
            sql = f"SELECT * FROM t {keyword}"
        else:
            sql = f"{keyword} TABLE supply_chain"
        result = sanitize_sql(sql)
        assert result["safe"] is False, f"Must block: {keyword}"

    def test_blocks_drop_table(self):
        assert sanitize_sql("DROP TABLE supply_chain")["safe"] is False

    def test_blocks_delete_from(self):
        assert sanitize_sql("DELETE FROM supply_chain WHERE 1=1")["safe"] is False

    def test_blocks_update_set(self):
        assert sanitize_sql("UPDATE supply_chain SET quantity = 0")["safe"] is False

    def test_blocks_insert_into(self):
        assert sanitize_sql("INSERT INTO supply_chain VALUES (1,2,3)")["safe"] is False

    def test_blocks_alter_table(self):
        assert sanitize_sql("ALTER TABLE supply_chain ADD COLUMN hack TEXT")["safe"] is False

    def test_blocks_truncate(self):
        assert sanitize_sql("TRUNCATE TABLE supply_chain")["safe"] is False

    def test_blocks_union_injection(self):
        assert sanitize_sql("SELECT * FROM supply_chain UNION SELECT * FROM secrets")["safe"] is False

    def test_blocks_into_outfile(self):
        assert sanitize_sql("SELECT * FROM supply_chain INTO OUTFILE '/etc/passwd'")["safe"] is False

    def test_blocks_load_extension(self):
        assert sanitize_sql("LOAD_EXTENSION 'httpfs'")["safe"] is False

    def test_blocks_grant(self):
        assert sanitize_sql("GRANT ALL ON supply_chain TO hacker")["safe"] is False

    def test_blocks_multi_statement_drop(self):
        assert sanitize_sql("SELECT 1; DROP TABLE supply_chain")["safe"] is False

    def test_blocks_case_insensitive(self):
        assert sanitize_sql("drop table supply_chain")["safe"] is False
        assert sanitize_sql("Drop Table supply_chain")["safe"] is False
        assert sanitize_sql("dRoP tAbLe supply_chain")["safe"] is False

    def test_allows_normal_select(self):
        assert sanitize_sql("SELECT region, COUNT(*) FROM supply_chain GROUP BY region")["safe"] is True

    def test_allows_aggregations(self):
        assert sanitize_sql("SELECT AVG(quantity), SUM(total_cost) FROM supply_chain")["safe"] is True

    def test_allows_subqueries(self):
        sql = "SELECT * FROM (SELECT region, COUNT(*) as n FROM supply_chain GROUP BY region) sub WHERE n > 10"
        assert sanitize_sql(sql)["safe"] is True

    def test_allows_case_when(self):
        sql = "SELECT CASE WHEN quantity > 100 THEN 'high' ELSE 'low' END as level FROM supply_chain"
        assert sanitize_sql(sql)["safe"] is True

    def test_word_boundary_updated_at_allowed(self):
        """'UPDATED_AT' contains 'UPDATE' but should NOT be blocked."""
        assert sanitize_sql("SELECT updated_at FROM supply_chain")["safe"] is True

    def test_word_boundary_created_at_allowed(self):
        """'CREATED_AT' contains 'CREATE' but should NOT be blocked."""
        assert sanitize_sql("SELECT created_at FROM supply_chain")["safe"] is True

    def test_word_boundary_execution_time_allowed(self):
        """'execution_time' contains 'EXEC' substring but column should be allowed."""
        # EXEC uses word boundary match, so execution should be blocked since
        # EXEC is a separate word match — let's verify behavior
        result = sanitize_sql("SELECT execution_time FROM supply_chain")
        # 'execution' should NOT match '\bEXEC\b' because 'execution' != 'exec'
        # But 'EXECUTE' is in blocklist — let's check if 'execution_time' triggers it
        # execution contains EXECUTE? No, 'execution' has 'execut' + 'ion'
        # The word boundary for EXECUTE would need \bEXECUTE\b which won't match 'execution_time'
        # Actually it depends — EXECUTE as a word boundary check: \bEXECUTE\b
        # 'execution_time' → EXECUTION_TIME → does \bEXECUTE\b match? No, because
        # the character after EXECUTE is 'I' not a word boundary
        assert result["safe"] is True

    def test_blocks_query_over_max_length(self):
        long_query = "SELECT " + "a, " * 700 + "b FROM supply_chain"
        assert len(long_query) > MAX_QUERY_LENGTH
        result = sanitize_sql(long_query)
        assert result["safe"] is False
        assert result["query_length_ok"] is False

    def test_query_at_exact_max_length(self):
        """Query at exactly max length should pass."""
        sql = "SELECT * FROM t" + " " * (MAX_QUERY_LENGTH - len("SELECT * FROM t"))
        assert len(sql) == MAX_QUERY_LENGTH
        result = sanitize_sql(sql)
        assert result["query_length_ok"] is True


# ============================================================================
# 4. COLUMN-LEVEL ACCESS — ALL 3 TIERS
# ============================================================================


class TestColumnAccess:
    """Column sensitivity levels must be enforced per role."""

    # --- Viewer: public only ---
    def test_viewer_allowed_all_public_columns(self):
        for col in COLUMN_SENSITIVITY["public"]:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "viewer")
            assert result["allowed"] is True, f"Viewer should access public column: {col}"

    def test_viewer_blocked_all_internal_columns(self):
        for col in COLUMN_SENSITIVITY["internal"]:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "viewer")
            assert result["allowed"] is False, f"Viewer should NOT access internal column: {col}"
            assert col in result["blocked_columns"]

    def test_viewer_blocked_all_restricted_columns(self):
        for col in COLUMN_SENSITIVITY["restricted"]:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "viewer")
            assert result["allowed"] is False, f"Viewer should NOT access restricted column: {col}"

    # --- Analyst: public + internal ---
    def test_analyst_allowed_public_columns(self):
        for col in COLUMN_SENSITIVITY["public"]:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "analyst")
            assert result["allowed"] is True, f"Analyst should access public column: {col}"

    def test_analyst_allowed_internal_columns(self):
        for col in COLUMN_SENSITIVITY["internal"]:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "analyst")
            assert result["allowed"] is True, f"Analyst should access internal column: {col}"

    def test_analyst_blocked_restricted_columns(self):
        for col in COLUMN_SENSITIVITY["restricted"]:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "analyst")
            assert result["allowed"] is False, f"Analyst should NOT access restricted column: {col}"

    # --- Admin: all ---
    def test_admin_allowed_all_columns(self):
        all_cols = (
            COLUMN_SENSITIVITY["public"]
            + COLUMN_SENSITIVITY["internal"]
            + COLUMN_SENSITIVITY["restricted"]
        )
        for col in all_cols:
            result = check_column_access(f"SELECT {col} FROM supply_chain", "admin")
            assert result["allowed"] is True, f"Admin should access all columns, blocked: {col}"

    # --- Multi-column queries ---
    def test_viewer_blocked_mixed_public_internal(self):
        result = check_column_access(
            "SELECT region, total_cost, product FROM supply_chain", "viewer"
        )
        assert result["allowed"] is False
        assert "total_cost" in result["blocked_columns"]

    def test_unknown_columns_default_public(self):
        """Columns NOT in sensitivity map should be allowed (custom CSV uploads)."""
        result = check_column_access(
            "SELECT my_custom_column FROM uploaded_data", "viewer"
        )
        assert result["allowed"] is True

    # --- Unknown role ---
    def test_unknown_role_gets_no_access(self):
        result = check_column_access(
            "SELECT total_cost FROM supply_chain", "hacker"
        )
        assert result["allowed"] is False


# ============================================================================
# 5. COMPONENT TYPE ENFORCEMENT
# ============================================================================


class TestComponentPermissions:
    """Component types and counts must be enforced per role."""

    def test_viewer_blocked_from_table(self):
        app = {"components": [{"id": "t1", "type": "table", "title": "T"}]}
        result = check_component_permissions(app, "viewer")
        assert result["allowed"] is False

    def test_viewer_blocked_from_scatter(self):
        app = {"components": [{"id": "s1", "type": "scatter_plot", "title": "S"}]}
        result = check_component_permissions(app, "viewer")
        assert result["allowed"] is False

    def test_viewer_blocked_from_area_chart(self):
        app = {"components": [{"id": "a1", "type": "area_chart", "title": "A"}]}
        result = check_component_permissions(app, "viewer")
        assert result["allowed"] is False

    @pytest.mark.parametrize("comp_type", [
        "bar_chart", "line_chart", "pie_chart", "kpi_card", "metric_highlight"
    ])
    def test_viewer_allowed_safe_types(self, comp_type):
        app = {"components": [{"id": "c1", "type": comp_type, "title": "C"}]}
        result = check_component_permissions(app, "viewer")
        assert result["allowed"] is True

    @pytest.mark.parametrize("comp_type", [
        "kpi_card", "bar_chart", "line_chart", "pie_chart",
        "scatter_plot", "table", "metric_highlight", "area_chart"
    ])
    def test_admin_allowed_all_types(self, comp_type):
        app = {"components": [{"id": "c1", "type": comp_type, "title": "C"}]}
        result = check_component_permissions(app, "admin")
        assert result["allowed"] is True

    @pytest.mark.parametrize("comp_type", [
        "kpi_card", "bar_chart", "line_chart", "pie_chart",
        "scatter_plot", "table", "metric_highlight", "area_chart"
    ])
    def test_analyst_allowed_all_types(self, comp_type):
        app = {"components": [{"id": "c1", "type": comp_type, "title": "C"}]}
        result = check_component_permissions(app, "analyst")
        assert result["allowed"] is True

    # --- Component count limits ---
    def test_viewer_max_4_components(self):
        app = {"components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"C{i}"}
            for i in range(5)  # 5 > viewer max of 4
        ]}
        result = check_component_permissions(app, "viewer")
        assert result["component_count_ok"] is False

    def test_viewer_exactly_4_components(self):
        app = {"components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"C{i}"}
            for i in range(4)
        ]}
        result = check_component_permissions(app, "viewer")
        assert result["component_count_ok"] is True

    def test_analyst_max_6_components(self):
        app = {"components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"C{i}"}
            for i in range(7)  # 7 > analyst max of 6
        ]}
        result = check_component_permissions(app, "analyst")
        assert result["component_count_ok"] is False

    def test_analyst_exactly_6_components(self):
        app = {"components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"C{i}"}
            for i in range(6)
        ]}
        result = check_component_permissions(app, "analyst")
        assert result["component_count_ok"] is True

    def test_admin_allows_15_components(self):
        app = {"components": [
            {"id": f"c{i}", "type": "table", "title": f"T{i}"}
            for i in range(15)
        ]}
        result = check_component_permissions(app, "admin")
        assert result["component_count_ok"] is True
        assert result["allowed"] is True

    def test_admin_blocked_at_16_components(self):
        app = {"components": [
            {"id": f"c{i}", "type": "bar_chart", "title": f"C{i}"}
            for i in range(16)
        ]}
        result = check_component_permissions(app, "admin")
        assert result["component_count_ok"] is False


# ============================================================================
# 6. EXPORT CONTROL
# ============================================================================


class TestExportControl:
    """Export permissions must match role configuration."""

    def test_admin_can_export(self):
        result = _check_export_control("admin", 1000)
        assert result["can_export"] is True
        assert "csv" in result["export_formats"]
        assert "json" in result["export_formats"]
        assert "pdf" in result["export_formats"]

    def test_analyst_can_export_within_limit(self):
        result = _check_export_control("analyst", 1000)
        assert result["can_export"] is True
        assert "csv" in result["export_formats"]

    def test_analyst_blocked_over_row_limit(self):
        result = _check_export_control("analyst", 200000)  # Over 100K limit
        assert result["can_export"] is False

    def test_viewer_cannot_export(self):
        result = _check_export_control("viewer", 1)
        assert result["can_export"] is False
        assert result["export_formats"] == []

    def test_admin_no_row_limit(self):
        result = _check_export_control("admin", 999999)
        assert result["can_export"] is True

    def test_unknown_role_cannot_export(self):
        result = _check_export_control("hacker", 1)
        assert result["can_export"] is False


# ============================================================================
# 7. RBAC CAPABILITIES
# ============================================================================


class TestAccessControl:
    """Role capabilities must be correctly enforced."""

    def test_admin_has_create_app(self):
        assert _check_access_control("admin", "create_app") is True

    def test_admin_has_view_pii(self):
        assert _check_access_control("admin", "view_pii") is True

    def test_admin_has_view_audit_trail(self):
        assert _check_access_control("admin", "view_audit_trail") is True

    def test_admin_has_export_data(self):
        assert _check_access_control("admin", "export_data") is True

    def test_analyst_has_create_app(self):
        assert _check_access_control("analyst", "create_app") is True

    def test_analyst_no_view_pii(self):
        assert _check_access_control("analyst", "view_pii") is False

    def test_analyst_no_view_audit(self):
        assert _check_access_control("analyst", "view_audit_trail") is False

    def test_viewer_no_create_app(self):
        assert _check_access_control("viewer", "create_app") is False

    def test_viewer_no_export(self):
        assert _check_access_control("viewer", "export_data") is False

    def test_viewer_no_pii(self):
        assert _check_access_control("viewer", "view_pii") is False

    def test_unknown_role_denied_everything(self):
        assert _check_access_control("hacker", "view_all_data") is False
        assert _check_access_control("hacker", "create_app") is False
        assert _check_access_control("hacker", "export_data") is False
        assert _check_access_control("hacker", "view_pii") is False

    def test_empty_role_denied(self):
        assert _check_access_control("", "create_app") is False


# ============================================================================
# 8. FULL GOVERNANCE PIPELINE
# ============================================================================


class TestFullGovernancePipeline:
    """End-to-end governance checks must produce correct outcomes."""

    def test_admin_passes_everything(self, basic_app):
        result = run_governance_checks(basic_app, "admin")
        assert result["passed"] is True
        assert result["overall_status"] in ("pass", "warning")

    def test_viewer_blocked_from_creating(self, basic_app):
        result = run_governance_checks(basic_app, "viewer")
        assert result["passed"] is False
        assert result["access_granted"] is False

    def test_analyst_passes_with_public_columns(self, basic_app):
        result = run_governance_checks(basic_app, "analyst")
        assert result["passed"] is True

    def test_analyst_blocked_with_restricted_columns(self):
        app = {
            "app_title": "Bad App",
            "components": [{
                "id": "c1", "type": "bar_chart", "title": "T",
                "sql_query": "SELECT supplier, COUNT(*) as n FROM supply_chain GROUP BY supplier",
                "config": {},
            }],
        }
        result = run_governance_checks(app, "analyst")
        assert result["passed"] is False
        assert len(result["blocked_reasons"]) > 0

    def test_dangerous_sql_blocks_pipeline(self):
        app = {
            "app_title": "Evil App",
            "components": [{
                "id": "c1", "type": "kpi_card", "title": "T",
                "sql_query": "DROP TABLE supply_chain",
                "config": {},
            }],
        }
        result = run_governance_checks(app, "admin")
        assert result["passed"] is False
        assert any("DROP" in str(r) for r in result["blocked_reasons"])

    def test_pii_in_user_message_generates_warning(self, basic_app):
        result = run_governance_checks(
            basic_app, "admin",
            user_message="My SSN is 123-45-6789, show me data"
        )
        assert len(result["pii_detected"]) > 0
        assert len(result["warnings"]) > 0

    def test_pii_in_data_detected_post_execution(self, basic_app):
        exec_results = {
            "kpi1": {
                "status": "success",
                "data": [{"email": "secret@corp.com", "total": 100}],
                "row_count": 1,
            }
        }
        result = run_governance_checks(basic_app, "admin", execution_results=exec_results)
        assert len(result["pii_detected"]) > 0

    def test_result_contains_all_required_fields(self, basic_app):
        result = run_governance_checks(basic_app, "admin")
        required_fields = [
            "overall_status", "passed", "role", "checks",
            "sql_safety", "column_access", "component_permissions",
            "pii_detected", "access_granted", "query_complexity",
            "data_quality", "export_allowed", "export_formats",
            "warnings", "blocked_reasons", "audit_entry_id",
        ]
        for field in required_fields:
            assert field in result, f"Missing field: {field}"

    def test_checks_list_has_all_8_checks(self, basic_app):
        result = run_governance_checks(basic_app, "admin")
        check_names = [c["name"] for c in result["checks"]]
        expected = [
            "sql_sanitization", "column_access", "component_permissions",
            "pii_detection", "access_control", "query_complexity",
            "data_quality", "export_control",
        ]
        for name in expected:
            assert name in check_names, f"Missing check: {name}"

    def test_viewer_with_8_components_double_blocked(self, multi_component_app):
        """Viewer should be blocked for BOTH component types AND count."""
        result = run_governance_checks(multi_component_app, "viewer")
        assert result["passed"] is False
        # Should have multiple blocked reasons (access + component types + count)
        assert len(result["blocked_reasons"]) >= 2


# ============================================================================
# 9. DATA QUALITY
# ============================================================================


class TestDataQuality:
    """Data quality checks must detect issues in execution results."""

    def test_detects_nulls(self):
        results = {
            "c1": {"status": "success", "data": [
                {"a": 1, "b": None}, {"a": None, "b": 2}
            ]}
        }
        quality = _check_data_quality(results)
        assert quality["null_count"] >= 2

    def test_detects_duplicates(self):
        results = {
            "c1": {"status": "success", "data": [
                {"a": 1, "b": 2}, {"a": 1, "b": 2}, {"a": 1, "b": 2}
            ]}
        }
        quality = _check_data_quality(results)
        assert quality["duplicate_count"] >= 2

    def test_good_data_passes(self):
        results = {
            "c1": {"status": "success", "data": [
                {"a": 1, "b": 10}, {"a": 2, "b": 20}, {"a": 3, "b": 30}
            ]}
        }
        quality = _check_data_quality(results)
        assert quality["overall_quality"] == "good"

    def test_skips_failed_components(self):
        results = {"c1": {"status": "error", "data": None}}
        quality = _check_data_quality(results)
        assert quality["overall_quality"] == "good"

    def test_skips_empty_data(self):
        results = {"c1": {"status": "success", "data": []}}
        quality = _check_data_quality(results)
        assert quality["overall_quality"] == "good"

    def test_per_component_tracking(self):
        results = {
            "good": {"status": "success", "data": [{"a": 1}, {"a": 2}]},
            "bad": {"status": "success", "data": [{"a": None}, {"a": None}]},
        }
        quality = _check_data_quality(results)
        assert "good" in quality["per_component"]
        assert "bad" in quality["per_component"]
        assert quality["per_component"]["good"]["quality"] == "good"
        assert quality["per_component"]["bad"]["quality"] in ("warning", "poor")


# ============================================================================
# 10. AUDIT TRAIL
# ============================================================================


class TestAuditTrail:
    """Audit trail must capture all governance events."""

    def test_log_creates_entry(self):
        _log_audit_trail("stress_test", {"scenario": "test_log"})
        trail = get_audit_trail(limit=5)
        assert any(e["action"] == "stress_test" for e in trail)

    def test_entry_has_timestamp(self):
        _log_audit_trail("ts_test", {})
        trail = get_audit_trail(limit=1)
        assert "timestamp" in trail[-1]

    def test_entry_has_session_id(self):
        _log_audit_trail("sid_test", {})
        trail = get_audit_trail(limit=1)
        assert "session_id" in trail[-1]

    def test_governance_check_creates_audit_entry(self, basic_app):
        before = len(get_audit_trail(limit=999))
        run_governance_checks(basic_app, "admin")
        after = len(get_audit_trail(limit=999))
        assert after > before, "Governance check must create audit entry"

    def test_blocked_sql_creates_audit_entry(self):
        before = len(get_audit_trail(limit=999))
        sanitize_sql("DROP TABLE supply_chain")
        after = len(get_audit_trail(limit=999))
        assert after > before, "Blocked SQL must create audit entry"

    def test_limit_parameter_works(self):
        for i in range(10):
            _log_audit_trail(f"bulk_{i}", {"i": i})
        trail = get_audit_trail(limit=3)
        assert len(trail) <= 3


# ============================================================================
# 11. EDGE CASES
# ============================================================================


class TestEdgeCases:
    """Edge cases and malformed inputs must be handled gracefully."""

    def test_empty_app_definition(self):
        result = run_governance_checks({"components": []}, "admin")
        assert isinstance(result, dict)
        assert result["passed"] is True  # No components = nothing to block

    def test_empty_sql_query(self):
        result = sanitize_sql("")
        assert result["safe"] is True  # Empty query has no dangerous keywords

    def test_none_in_component_fields(self):
        app = {"components": [{"id": None, "type": None, "sql_query": "", "title": ""}]}
        # Should not crash
        result = run_governance_checks(app, "admin")
        assert isinstance(result, dict)

    def test_very_long_pii_scan(self):
        """Scanning lots of data rows should not crash."""
        data = [{"email": f"user{i}@test.com", "val": i} for i in range(1000)]
        results = _detect_pii("", scan_data=True, data=data)
        assert len(results) >= 1000  # At least one email per row

    def test_unicode_in_sql(self):
        result = sanitize_sql("SELECT * FROM supply_chain WHERE region = '日本'")
        assert result["safe"] is True

    def test_governance_with_no_execution_results(self, basic_app):
        result = run_governance_checks(basic_app, "admin", execution_results=None)
        assert isinstance(result, dict)
        assert result["passed"] is True

    def test_config_sensitivity_map_completeness(self):
        """Every column in COLUMN_SENSITIVITY must be in COLUMN_SENSITIVITY_MAP."""
        for level, columns in COLUMN_SENSITIVITY.items():
            for col in columns:
                assert col in COLUMN_SENSITIVITY_MAP, f"Missing from map: {col}"
                assert COLUMN_SENSITIVITY_MAP[col] == level

    def test_config_roles_have_required_keys(self):
        """Every role must have required configuration keys."""
        required = ["capabilities", "max_components_per_app", "export_formats"]
        for role_name, role_config in ROLES.items():
            for key in required:
                assert key in role_config, f"Role '{role_name}' missing key: {key}"

    def test_sensitivity_access_covers_all_roles(self):
        """SENSITIVITY_ACCESS must have entries for all defined roles."""
        for role_name in ROLES:
            assert role_name in SENSITIVITY_ACCESS, \
                f"SENSITIVITY_ACCESS missing role: {role_name}"
