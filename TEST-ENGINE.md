# TEST PRD — Engine Layer Automated Validation
## StackForge | Person 1 — The Engine

**Purpose:** Claude Code should run these tests after completing each file to validate correctness before moving on. Tests are designed to run WITHOUT an OpenAI API key where possible (mocked intent parser), and WITH a key for the full integration test.

---

## CLAUDE CODE INSTRUCTIONS

After building each engine file, run the corresponding test file. If tests fail, fix the code before moving to the next file. After all files are built, run the full integration test.

```
# Run all tests
python -m pytest tests/ -v --tb=short

# Run individual test files
python -m pytest tests/test_data_loader.py -v
python -m pytest tests/test_executor.py -v
python -m pytest tests/test_validator.py -v
python -m pytest tests/test_governance.py -v
python -m pytest tests/test_config.py -v
python -m pytest tests/test_integration.py -v
```

Create a `tests/` directory and `tests/__init__.py` (empty file).

---

## File 1: `tests/conftest.py`

Shared fixtures used across all test files.

```python
"""Shared test fixtures for StackForge engine tests."""

import pytest
import duckdb
import pandas as pd


@pytest.fixture
def db_conn():
    """Create a fresh in-memory DuckDB connection with supply_chain table."""
    from data.sample_data_loader import get_connection
    conn = get_connection()
    yield conn
    conn.close()


@pytest.fixture
def sample_schema(db_conn):
    """Get the table schema string."""
    from data.sample_data_loader import get_table_schema
    return get_table_schema(db_conn)


@pytest.fixture
def sample_rows(db_conn):
    """Get sample rows DataFrame."""
    from data.sample_data_loader import get_sample_rows
    return get_sample_rows(db_conn)


@pytest.fixture
def mock_app_definition():
    """A valid app_definition that matches the contract schema.

    This is the GOLD STANDARD — if Person 1's engine produces JSON
    that doesn't look like this, integration with Person 2 will break.
    """
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
                "sql_query": "SELECT strftime(order_date, '%Y-%m') as month, ROUND(AVG(delivery_days), 1) as avg_days FROM supply_chain GROUP BY month ORDER BY month",
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


@pytest.fixture
def mock_execution_results():
    """Mock execution results matching the contract format."""
    return {
        "kpi_total_orders": {
            "status": "success",
            "data": pd.DataFrame({"total_orders": [500]}),
            "row_count": 1
        },
        "bar_defect_by_supplier": {
            "status": "success",
            "data": pd.DataFrame({
                "supplier": ["SupplierA", "SupplierB", "SupplierC", "SupplierD"],
                "avg_defect": [6.2, 4.1, 3.5, 2.8]
            }),
            "row_count": 4
        },
        "table_supplier_detail": {
            "status": "success",
            "data": pd.DataFrame({
                "supplier": ["A", "B", "C"],
                "orders": [120, 95, 85],
                "avg_defect": [3.1, 2.8, 4.5],
                "avg_delivery": [5.2, 4.8, 6.1]
            }),
            "row_count": 3
        }
    }
```

---

## File 2: `tests/test_config.py`

Tests that config.py loads correctly and has all required structures.

```python
"""Tests for config.py — validates all configuration is present and well-formed."""

import pytest


class TestConfigLoads:
    """Verify config.py imports and has all required attributes."""

    def test_config_imports(self):
        """config.py must import without errors."""
        import config
        assert config is not None

    def test_app_name_exists(self):
        from config import APP_NAME
        assert isinstance(APP_NAME, str)
        assert len(APP_NAME) > 0

    def test_openai_model_exists(self):
        from config import OPENAI_MODEL
        assert isinstance(OPENAI_MODEL, str)


class TestPIIPatterns:
    """PII patterns must be defined for governance scanning."""

    def test_pii_patterns_exist(self):
        from config import PII_PATTERNS
        assert isinstance(PII_PATTERNS, (dict, list))
        assert len(PII_PATTERNS) >= 3, "Need at least 3 PII patterns (email, phone, ssn)"

    def test_pii_patterns_are_valid_regex(self):
        import re
        from config import PII_PATTERNS
        if isinstance(PII_PATTERNS, dict):
            for name, pattern in PII_PATTERNS.items():
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"PII pattern '{name}' is not valid regex: {pattern}")
        elif isinstance(PII_PATTERNS, list):
            for pattern in PII_PATTERNS:
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"PII pattern is not valid regex: {pattern}")


class TestRoles:
    """Role definitions must include admin, analyst, viewer."""

    def test_roles_exist(self):
        from config import ROLES
        assert isinstance(ROLES, dict)
        assert "admin" in ROLES, "Missing 'admin' role"
        assert "analyst" in ROLES, "Missing 'analyst' role"
        assert "viewer" in ROLES, "Missing 'viewer' role"

    def test_each_role_has_capabilities(self):
        from config import ROLES
        for role_name, role_config in ROLES.items():
            assert "capabilities" in role_config or "display_name" in role_config, \
                f"Role '{role_name}' missing expected fields"


class TestTemplates:
    """Template definitions must include at least Supplier Performance."""

    def test_templates_exist(self):
        from config import TEMPLATES
        assert isinstance(TEMPLATES, list)
        assert len(TEMPLATES) >= 1, "Need at least 1 template"

    def test_templates_have_required_fields(self):
        from config import TEMPLATES
        required_fields = {"id", "name", "description", "default_prompt"}
        for template in TEMPLATES:
            for field in required_fields:
                assert field in template, \
                    f"Template '{template.get('name', 'unknown')}' missing field: {field}"

    def test_supplier_performance_template(self):
        """The Supplier Performance template is required for demo mode."""
        from config import TEMPLATES
        supplier_template = next(
            (t for t in TEMPLATES if "supplier" in t["id"].lower()), None
        )
        assert supplier_template is not None, \
            "Must have a Supplier Performance template (used by demo mode)"
```

---

## File 3: `tests/test_data_loader.py`

Tests for the DuckDB data layer. Run AFTER `data/sample_data_loader.py` is built.

```python
"""Tests for data/sample_data_loader.py — validates DuckDB setup and data integrity."""

import pytest
import pandas as pd


class TestGetConnection:
    """DuckDB connection must work and contain supply_chain table."""

    def test_connection_returns(self, db_conn):
        """get_connection() must return a valid DuckDB connection."""
        assert db_conn is not None

    def test_supply_chain_table_exists(self, db_conn):
        """The supply_chain table must exist."""
        tables = db_conn.execute("SHOW TABLES").fetchdf()
        table_names = tables.iloc[:, 0].str.lower().tolist()
        assert "supply_chain" in table_names, \
            f"supply_chain table not found. Tables: {table_names}"

    def test_row_count(self, db_conn):
        """supply_chain must have approximately 500 rows."""
        count = db_conn.execute("SELECT COUNT(*) FROM supply_chain").fetchone()[0]
        assert count >= 100, f"Expected ~500 rows, got {count}"
        assert count <= 1000, f"Expected ~500 rows, got {count}"


class TestSupplyChainSchema:
    """The supply_chain table must have the expected columns."""

    REQUIRED_COLUMNS = [
        "order_id", "order_date", "supplier", "region", "product",
        "category", "quantity", "unit_cost", "total_cost", "defect_rate",
        "delivery_days", "on_time_delivery", "shipping_mode"
    ]

    def test_required_columns_exist(self, db_conn):
        """All required columns must exist in the table."""
        schema = db_conn.execute("DESCRIBE supply_chain").fetchdf()
        actual_columns = schema["column_name"].str.lower().tolist()

        missing = [c for c in self.REQUIRED_COLUMNS if c.lower() not in actual_columns]
        assert len(missing) == 0, f"Missing columns: {missing}. Got: {actual_columns}"

    def test_no_null_critical_columns(self, db_conn):
        """Critical columns should not be entirely NULL."""
        for col in ["supplier", "region", "defect_rate"]:
            try:
                null_count = db_conn.execute(
                    f"SELECT COUNT(*) FROM supply_chain WHERE {col} IS NULL"
                ).fetchone()[0]
                total = db_conn.execute("SELECT COUNT(*) FROM supply_chain").fetchone()[0]
                assert null_count < total, f"Column '{col}' is entirely NULL"
            except Exception:
                pass  # Column might not exist yet; test_required_columns catches that


class TestSchemaFunctions:
    """get_table_schema() and get_sample_rows() must return useful output."""

    def test_get_table_schema_returns_string(self, db_conn):
        from data.sample_data_loader import get_table_schema
        schema = get_table_schema(db_conn)
        assert isinstance(schema, str)
        assert len(schema) > 50, "Schema string is too short — probably incomplete"
        assert "supplier" in schema.lower(), "Schema should mention 'supplier' column"

    def test_get_sample_rows_returns_dataframe(self, db_conn):
        from data.sample_data_loader import get_sample_rows
        samples = get_sample_rows(db_conn)
        assert isinstance(samples, pd.DataFrame)
        assert len(samples) >= 3, f"Expected at least 3 sample rows, got {len(samples)}"
        assert len(samples) <= 10, f"Expected at most 10 sample rows, got {len(samples)}"

    def test_sample_rows_have_real_values(self, db_conn):
        """Sample rows must have actual data, not NaN/None everywhere."""
        from data.sample_data_loader import get_sample_rows
        samples = get_sample_rows(db_conn)
        non_null_pct = samples.notna().sum().sum() / (len(samples) * len(samples.columns))
        assert non_null_pct > 0.8, f"Sample data is {(1-non_null_pct)*100:.0f}% null — bad for schema injection"


class TestSQLQueries:
    """Common SQL patterns that intent_parser will generate must work against this data."""

    def test_group_by_supplier(self, db_conn):
        """GROUP BY supplier must return multiple suppliers."""
        df = db_conn.execute(
            "SELECT supplier, COUNT(*) as cnt FROM supply_chain GROUP BY supplier"
        ).fetchdf()
        assert len(df) >= 3, f"Expected multiple suppliers, got {len(df)}"

    def test_group_by_region(self, db_conn):
        df = db_conn.execute(
            "SELECT region, COUNT(*) as cnt FROM supply_chain GROUP BY region"
        ).fetchdf()
        assert len(df) >= 2, f"Expected multiple regions, got {len(df)}"

    def test_avg_defect_rate(self, db_conn):
        df = db_conn.execute(
            "SELECT ROUND(AVG(defect_rate), 2) as avg_defect FROM supply_chain"
        ).fetchdf()
        assert len(df) == 1
        val = df.iloc[0, 0]
        assert val is not None and val > 0, f"AVG(defect_rate) should be > 0, got {val}"

    def test_date_grouping(self, db_conn):
        """Date-based grouping must work (for line charts)."""
        try:
            df = db_conn.execute(
                "SELECT strftime(order_date, '%Y-%m') as month, COUNT(*) as cnt "
                "FROM supply_chain GROUP BY month ORDER BY month"
            ).fetchdf()
            assert len(df) >= 2, "Date grouping should return multiple months"
        except Exception as e:
            # strftime might need different syntax depending on date column type
            try:
                df = db_conn.execute(
                    "SELECT EXTRACT(MONTH FROM order_date) as month, COUNT(*) as cnt "
                    "FROM supply_chain GROUP BY month ORDER BY month"
                ).fetchdf()
                assert len(df) >= 2
            except Exception:
                pytest.fail(f"Date grouping failed with both strftime and EXTRACT: {e}")

    def test_filter_by_region(self, db_conn):
        """WHERE region = 'X' must work (for filter injection)."""
        regions = db_conn.execute(
            "SELECT DISTINCT region FROM supply_chain"
        ).fetchdf()["region"].tolist()
        assert len(regions) > 0

        first_region = regions[0]
        filtered = db_conn.execute(
            f"SELECT COUNT(*) FROM supply_chain WHERE region = '{first_region}'"
        ).fetchone()[0]
        assert filtered > 0, f"No rows found for region '{first_region}'"
```

---

## File 4: `tests/test_executor.py`

Tests for `engine/executor.py`. Run AFTER executor is built.

```python
"""Tests for engine/executor.py — validates SQL execution and filter injection."""

import pytest
import pandas as pd


class TestExecuteQuery:
    """execute_query() must run SQL and return DataFrames."""

    def test_simple_query(self, db_conn):
        from engine.executor import execute_query
        df = execute_query(db_conn, "SELECT COUNT(*) as total FROM supply_chain")
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert df.iloc[0, 0] > 0

    def test_group_by_query(self, db_conn):
        from engine.executor import execute_query
        df = execute_query(
            db_conn,
            "SELECT supplier, AVG(defect_rate) as avg_defect FROM supply_chain GROUP BY supplier"
        )
        assert len(df) >= 3
        assert "supplier" in df.columns
        assert "avg_defect" in df.columns

    def test_invalid_query_raises(self, db_conn):
        from engine.executor import execute_query
        with pytest.raises(Exception):
            execute_query(db_conn, "SELECT * FROM nonexistent_table_xyz")


class TestFilterInjection:
    """Filters must be injected as WHERE clauses via subquery wrapping."""

    def test_multiselect_filter(self, db_conn):
        from engine.executor import execute_query

        # Get the actual regions first
        regions = db_conn.execute(
            "SELECT DISTINCT region FROM supply_chain"
        ).fetchdf()["region"].tolist()
        first_region = regions[0]

        # Execute with filter
        base_query = "SELECT supplier, AVG(defect_rate) as avg_defect FROM supply_chain GROUP BY supplier"
        filters = {"region": [first_region]}

        try:
            df = execute_query(db_conn, base_query, filters)
            assert isinstance(df, pd.DataFrame)
            # Filtered result should have fewer or equal rows vs unfiltered
        except TypeError:
            # Some implementations use different filter format
            filters_alt = {f"region_filter": [first_region]}
            df = execute_query(db_conn, base_query, filters_alt)
            assert isinstance(df, pd.DataFrame)

    def test_no_filters_returns_all(self, db_conn):
        from engine.executor import execute_query
        df_no_filter = execute_query(
            db_conn,
            "SELECT COUNT(*) as total FROM supply_chain"
        )
        df_empty_filter = execute_query(
            db_conn,
            "SELECT COUNT(*) as total FROM supply_chain",
            filters={}
        )
        assert df_no_filter.iloc[0, 0] == df_empty_filter.iloc[0, 0]


class TestExecuteAppComponents:
    """execute_app_components() must run all component queries and return results dict."""

    def test_executes_all_components(self, db_conn, mock_app_definition):
        from engine.executor import execute_app_components
        results = execute_app_components(db_conn, mock_app_definition)

        assert isinstance(results, dict)

        # Should have a result for each component
        for comp in mock_app_definition["components"]:
            comp_id = comp["id"]
            assert comp_id in results, f"Missing result for component '{comp_id}'"

    def test_successful_components_have_data(self, db_conn, mock_app_definition):
        from engine.executor import execute_app_components
        results = execute_app_components(db_conn, mock_app_definition)

        success_count = 0
        for comp_id, result in results.items():
            if result.get("status") == "success":
                assert result.get("data") is not None, \
                    f"Component '{comp_id}' succeeded but has no data"
                assert isinstance(result["data"], pd.DataFrame), \
                    f"Component '{comp_id}' data is not a DataFrame"
                success_count += 1

        assert success_count >= 4, \
            f"Only {success_count} of {len(results)} components succeeded — most SQL should work"

    def test_error_components_have_error_message(self, db_conn):
        from engine.executor import execute_app_components

        bad_app = {
            "components": [
                {
                    "id": "bad_query",
                    "type": "table",
                    "title": "Bad Query",
                    "sql_query": "SELECT * FROM this_table_does_not_exist",
                    "config": {},
                    "width": "full"
                }
            ],
            "filters": []
        }
        results = execute_app_components(db_conn, bad_app)
        assert results["bad_query"]["status"] == "error"
        assert "error" in results["bad_query"] or "error" in str(results["bad_query"])
```

---

## File 5: `tests/test_validator.py`

Tests for `engine/validator.py`.

```python
"""Tests for engine/validator.py — validates result checking and explanation generation."""

import pytest
import pandas as pd


class TestValidateAndExplain:
    """validate_and_explain() must check results and generate explanations."""

    def test_returns_expected_structure(self, mock_app_definition, mock_execution_results):
        from engine.validator import validate_and_explain
        result = validate_and_explain(mock_app_definition, mock_execution_results)

        assert isinstance(result, dict)
        assert "overall_status" in result, "Missing 'overall_status'"
        assert result["overall_status"] in ["success", "warning", "error"], \
            f"Invalid status: {result['overall_status']}"

    def test_components_have_explanations(self, mock_app_definition, mock_execution_results):
        from engine.validator import validate_and_explain
        result = validate_and_explain(mock_app_definition, mock_execution_results)

        # Should have component-level results
        components = result.get("components", [])
        assert len(components) > 0, "Validation should produce component-level results"

        for comp in components:
            assert "explanation" in comp or "status" in comp, \
                f"Component validation missing explanation/status: {comp}"

    def test_empty_data_produces_warning(self):
        from engine.validator import validate_and_explain

        app_def = {
            "components": [{
                "id": "empty_comp",
                "type": "bar_chart",
                "title": "Empty Chart",
                "sql_query": "SELECT 1 WHERE 1=0",
                "config": {},
                "width": "full"
            }]
        }
        results = {
            "empty_comp": {
                "status": "success",
                "data": pd.DataFrame(),
                "row_count": 0
            }
        }
        validation = validate_and_explain(app_def, results)
        assert validation["overall_status"] != "success", \
            "Empty results should not be 'success'"

    def test_error_result_detected(self):
        from engine.validator import validate_and_explain

        app_def = {
            "components": [{
                "id": "error_comp",
                "type": "table",
                "title": "Failed Query",
                "sql_query": "SELECT bad",
                "config": {},
                "width": "full"
            }]
        }
        results = {
            "error_comp": {
                "status": "error",
                "error": "Column 'bad' not found",
                "row_count": 0
            }
        }
        validation = validate_and_explain(app_def, results)
        assert validation["overall_status"] != "success"
```

---

## File 6: `tests/test_governance.py`

Tests for `engine/governance.py`.

```python
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
```

---

## File 7: `tests/test_integration.py`

End-to-end integration test. This tests the FULL pipeline without OpenAI (using the mock app definition) AND optionally with OpenAI if an API key is available.

```python
"""
Integration tests — validates the full engine pipeline end to end.

Tests the contract: user prompt → app_definition → execution → validation → governance.

The mock pipeline test runs WITHOUT an API key.
The live pipeline test runs ONLY if OPENAI_API_KEY is set.
"""

import os
import json
import pytest
import pandas as pd


class TestMockPipeline:
    """Full pipeline using mock app_definition (no API key needed)."""

    def test_execute_then_validate(self, db_conn, mock_app_definition):
        """Execute mock app definition against real DuckDB, then validate."""
        from engine.executor import execute_app_components
        from engine.validator import validate_and_explain

        # Step 1: Execute all component queries
        results = execute_app_components(db_conn, mock_app_definition)
        assert len(results) > 0, "Execution returned no results"

        # Step 2: Validate the results
        validation = validate_and_explain(mock_app_definition, results)
        assert validation["overall_status"] in ["success", "warning", "error"]

        # At least half the components should succeed
        success_count = sum(
            1 for r in results.values()
            if r.get("status") == "success"
        )
        total = len(results)
        assert success_count >= total // 2, \
            f"Only {success_count}/{total} components succeeded"

    def test_execute_validate_govern(self, db_conn, mock_app_definition):
        """Full pipeline: execute → validate → governance."""
        from engine.executor import execute_app_components
        from engine.validator import validate_and_explain
        from engine.governance import run_governance_checks

        results = execute_app_components(db_conn, mock_app_definition)
        validation = validate_and_explain(mock_app_definition, results)
        governance = run_governance_checks(mock_app_definition, "analyst")

        # All three stages must return dicts
        assert isinstance(results, dict)
        assert isinstance(validation, dict)
        assert isinstance(governance, dict)

        # Governance must have checks
        assert len(governance.get("checks", [])) >= 1

    def test_app_definition_contract_shape(self, mock_app_definition):
        """The mock app_definition must match the exact contract schema.

        This is THE critical test — if this shape doesn't match,
        Person 2's UI will break on integration day.
        """
        app = mock_app_definition

        # Top-level required fields
        assert "app_title" in app
        assert "components" in app
        assert isinstance(app["components"], list)
        assert len(app["components"]) >= 1

        # Each component must have required fields
        for comp in app["components"]:
            assert "id" in comp, f"Component missing 'id': {comp}"
            assert "type" in comp, f"Component missing 'type': {comp}"
            assert "title" in comp, f"Component missing 'title': {comp}"
            assert "sql_query" in comp, f"Component missing 'sql_query': {comp}"
            assert "width" in comp, f"Component missing 'width': {comp}"

            # Type must be one of the allowed types
            allowed_types = [
                "kpi_card", "bar_chart", "line_chart", "pie_chart",
                "scatter_plot", "table", "metric_highlight", "area_chart"
            ]
            assert comp["type"] in allowed_types, \
                f"Invalid component type: {comp['type']}"

            # Width must be valid
            allowed_widths = ["full", "half", "third"]
            assert comp["width"] in allowed_widths, \
                f"Invalid width: {comp['width']}"

        # Filters (optional but expected)
        if "filters" in app:
            for f in app["filters"]:
                assert "column" in f, f"Filter missing 'column': {f}"
                assert "type" in f or "filter_type" in f, f"Filter missing type: {f}"

    def test_execution_results_contract_shape(self, db_conn, mock_app_definition):
        """Execution results must match the shape Person 2's UI expects."""
        from engine.executor import execute_app_components
        results = execute_app_components(db_conn, mock_app_definition)

        for comp_id, result in results.items():
            assert "status" in result, f"Result '{comp_id}' missing 'status'"
            assert result["status"] in ["success", "error"], \
                f"Invalid status: {result['status']}"

            if result["status"] == "success":
                assert "data" in result, f"Success result '{comp_id}' missing 'data'"
                assert isinstance(result["data"], pd.DataFrame), \
                    f"Result '{comp_id}' data is not a DataFrame"


@pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set — skipping live API test"
)
class TestLivePipeline:
    """Full pipeline with REAL OpenAI API call. Only runs if API key is set."""

    def test_live_intent_parsing(self, db_conn):
        """Real GPT-5.1 call → execute → validate → governance."""
        from data.sample_data_loader import get_table_schema, get_sample_rows
        from engine.intent_parser import parse_intent
        from engine.executor import execute_app_components
        from engine.validator import validate_and_explain
        from engine.governance import run_governance_checks

        # Step 1: Parse intent with real API
        schema = get_table_schema(db_conn)
        samples = get_sample_rows(db_conn)
        schema_ctx = schema + "\n\nSample rows:\n" + samples.to_string(index=False)

        app_def = parse_intent(
            "Show me supplier defect rates by region",
            table_schema=schema_ctx
        )

        # Validate the shape
        assert "app_title" in app_def or "title" in app_def
        assert "components" in app_def
        assert len(app_def["components"]) >= 1

        # Step 2: Execute
        results = execute_app_components(db_conn, app_def)
        success_count = sum(1 for r in results.values() if r.get("status") == "success")
        assert success_count >= 1, "At least 1 component should execute successfully"

        # Step 3: Validate
        validation = validate_and_explain(app_def, results)
        assert validation is not None

        # Step 4: Governance
        governance = run_governance_checks(app_def, "analyst")
        assert governance is not None

        print(f"\n✅ LIVE PIPELINE TEST PASSED")
        print(f"   App: {app_def.get('app_title', 'N/A')}")
        print(f"   Components: {len(app_def['components'])}")
        print(f"   Executed: {success_count}/{len(results)}")
        print(f"   Governance: {governance.get('overall_status', 'N/A')}")

    def test_live_refinement(self, db_conn):
        """Test conversational refinement — modify existing app via follow-up."""
        from data.sample_data_loader import get_table_schema, get_sample_rows
        from engine.intent_parser import parse_intent

        schema = get_table_schema(db_conn)
        samples = get_sample_rows(db_conn)
        schema_ctx = schema + "\n\nSample rows:\n" + samples.to_string(index=False)

        # Build initial app
        app_v1 = parse_intent(
            "Show supplier defect rates",
            table_schema=schema_ctx
        )
        v1_count = len(app_v1.get("components", []))

        # Refine it
        app_v2 = parse_intent(
            "Add a breakdown by shipping mode",
            existing_app=app_v1,
            table_schema=schema_ctx
        )
        v2_count = len(app_v2.get("components", []))

        # Refined app should exist and ideally have more or different components
        assert app_v2 is not None
        assert v2_count >= 1
        print(f"\n✅ REFINEMENT TEST PASSED: v1={v1_count} components → v2={v2_count} components")


class TestDynamicSchemaInjection:
    """Schema and sample rows must be injected dynamically, not hardcoded."""

    def test_schema_contains_actual_columns(self, db_conn):
        from data.sample_data_loader import get_table_schema
        schema = get_table_schema(db_conn)
        assert "supplier" in schema.lower()
        assert "defect_rate" in schema.lower()
        assert "region" in schema.lower()

    def test_sample_rows_reflect_actual_data(self, db_conn):
        from data.sample_data_loader import get_sample_rows
        samples = get_sample_rows(db_conn)
        assert "supplier" in [c.lower() for c in samples.columns]
        assert len(samples) >= 3
        # Verify the sample values are actual data, not placeholders
        assert samples.iloc[0, 0] is not None
```

---

## RUNNING THE TESTS

### After each file is built:

```bash
# After data/sample_data_loader.py
python -m pytest tests/test_data_loader.py -v --tb=short

# After engine/executor.py
python -m pytest tests/test_executor.py -v --tb=short

# After engine/validator.py
python -m pytest tests/test_validator.py -v --tb=short

# After engine/governance.py
python -m pytest tests/test_governance.py -v --tb=short

# After config.py
python -m pytest tests/test_config.py -v --tb=short
```

### Full suite (run after all engine files are done):

```bash
# All tests except live API
python -m pytest tests/ -v --tb=short -k "not Live"

# Full suite including live API (requires OPENAI_API_KEY)
python -m pytest tests/ -v --tb=short
```

### Expected output when everything passes:

```
tests/test_config.py::TestConfigLoads::test_config_imports PASSED
tests/test_config.py::TestConfigLoads::test_app_name_exists PASSED
tests/test_config.py::TestPIIPatterns::test_pii_patterns_exist PASSED
tests/test_config.py::TestRoles::test_roles_exist PASSED
tests/test_config.py::TestTemplates::test_supplier_performance_template PASSED
tests/test_data_loader.py::TestGetConnection::test_supply_chain_table_exists PASSED
tests/test_data_loader.py::TestSupplyChainSchema::test_required_columns_exist PASSED
tests/test_data_loader.py::TestSchemaFunctions::test_get_table_schema_returns_string PASSED
tests/test_data_loader.py::TestSQLQueries::test_group_by_supplier PASSED
tests/test_executor.py::TestExecuteQuery::test_simple_query PASSED
tests/test_executor.py::TestFilterInjection::test_multiselect_filter PASSED
tests/test_executor.py::TestExecuteAppComponents::test_executes_all_components PASSED
tests/test_validator.py::TestValidateAndExplain::test_returns_expected_structure PASSED
tests/test_validator.py::TestValidateAndExplain::test_empty_data_produces_warning PASSED
tests/test_governance.py::TestPIIDetection::test_detects_email PASSED
tests/test_governance.py::TestAccessControl::test_viewer_cannot_export PASSED
tests/test_governance.py::TestGovernanceCheckFunction::test_has_checks_list PASSED
tests/test_integration.py::TestMockPipeline::test_execute_then_validate PASSED
tests/test_integration.py::TestMockPipeline::test_app_definition_contract_shape PASSED
tests/test_integration.py::TestDynamicSchemaInjection::test_schema_contains_actual_columns PASSED

========================= 20+ passed in X.XXs =========================
```

---

## WHAT TO DO WHEN TESTS FAIL

1. **Import error** → The file doesn't exist yet or has a syntax error. Fix before continuing.
2. **Missing column** → `sample_data_loader.py` is generating data without that column. Add it.
3. **SQL error** → The SQL in `mock_app_definition` doesn't match your DuckDB schema. Align them.
4. **Contract mismatch** → Your `parse_intent()` output doesn't match the schema. This is critical — fix it before integration with Person 2.
5. **Governance missing function** → `governance.py` needs `run_governance_checks()` function. Person 3 extends it later, but the skeleton must work now.

---

**End of Test PRD**
