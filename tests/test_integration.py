"""
Integration tests — validates the full engine pipeline end to end.

Tests the contract: user prompt → app_definition → execution → validation → governance.

USAGE:
    python tests/test_integration.py    # Run all tests + integration demonstration

The mock pipeline test runs WITHOUT an API key.
The live pipeline test runs ONLY if OPENAI_API_KEY is set.
The demonstration shows real system components working together with mock data.
"""

import sys
import os
import json
import pandas as pd

# Add the project root to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data.sample_data_loader import get_connection


def get_db_connection():
    """Get a database connection for testing."""
    return get_connection()


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


def test_execute_then_validate():
    """Execute mock app definition against real DuckDB, then validate."""
    from engine.executor import execute_app_components
    from engine.validator import validate_and_explain

    db_conn = get_db_connection()
    mock_app_definition = get_mock_app_definition()

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


def test_execute_validate_govern():
    """Full pipeline: execute → validate → governance."""
    from engine.executor import execute_app_components
    from engine.validator import validate_and_explain
    from engine.governance import run_governance_checks

    db_conn = get_db_connection()
    mock_app_definition = get_mock_app_definition()

    results = execute_app_components(db_conn, mock_app_definition)
    validation = validate_and_explain(mock_app_definition, results)
    governance = run_governance_checks(mock_app_definition, "analyst")

    # All three stages must return dicts
    assert isinstance(results, dict)
    assert isinstance(validation, dict)
    assert isinstance(governance, dict)

    # Governance must have checks
    assert len(governance.get("checks", [])) >= 1


def test_app_definition_contract_shape():
    """The mock app_definition must match the exact contract schema."""
    mock_app_definition = get_mock_app_definition()
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


def test_execution_results_contract_shape():
    """Execution results must match the shape Person 2's UI expects."""
    from engine.executor import execute_app_components
    db_conn = get_db_connection()
    mock_app_definition = get_mock_app_definition()
    results = execute_app_components(db_conn, mock_app_definition)

    for comp_id, result in results.items():
        assert "status" in result, f"Result '{comp_id}' missing 'status'"
        assert result["status"] in ["success", "error"], \
            f"Invalid status: {result['status']}"

        if result["status"] == "success":
            assert "data" in result, f"Success result '{comp_id}' missing 'data'"
            assert isinstance(result["data"], pd.DataFrame), \
                f"Result '{comp_id}' data is not a DataFrame"


def test_live_intent_parsing():
    """Real GPT-5.1 call → execute → validate → governance."""
    if not os.getenv("OPENAI_API_KEY"):
        print("Skipping live intent parsing test - OPENAI_API_KEY not set")
        return

    from data.sample_data_loader import get_table_schema, get_all_sample_data
    from engine.intent_parser import parse_intent
    from engine.executor import execute_app_components
    from engine.validator import validate_and_explain
    from engine.governance import run_governance_checks

    db_conn = get_db_connection()

    # Step 1: Parse intent with real API
    schema = get_table_schema(db_conn)
    samples = get_all_sample_data(db_conn)
    schema_ctx = schema + "\n\nSample data:\n" + samples

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


def test_live_refinement():
    """Test conversational refinement — modify existing app via follow-up."""
    if not os.getenv("OPENAI_API_KEY"):
        print("Skipping live refinement test - OPENAI_API_KEY not set")
        return

    from data.sample_data_loader import get_table_schema, get_all_sample_data
    from engine.intent_parser import parse_intent

    db_conn = get_db_connection()

    schema = get_table_schema(db_conn)
    samples = get_all_sample_data(db_conn)
    schema_ctx = schema + "\n\nSample data:\n" + samples

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


def test_schema_contains_actual_columns():
    """Schema must contain actual columns."""
    from data.sample_data_loader import get_table_schema
    db_conn = get_db_connection()
    schema = get_table_schema(db_conn)
    assert "supplier" in schema.lower()
    assert "defect_rate" in schema.lower()
    assert "region" in schema.lower()


def test_sample_rows_reflect_actual_data():
    """Sample data must reflect actual data."""
    from data.sample_data_loader import get_all_sample_data
    db_conn = get_db_connection()
    samples = get_all_sample_data(db_conn)
    # Check that we have sample data
    assert len(samples) > 0, "Sample data should not be empty"
    assert "SUPPLY_CHAIN TABLE" in samples, "Should include supply_chain table"
    assert "CUSTOMERS TABLE" in samples, "Should include customers table"
    # Verify the sample values contain actual data, not placeholders
    assert "order_id" in samples, "Should contain order data"
    assert "customer_id" in samples, "Should contain customer data"


def demonstrate_user_example():
    """
    Integration demonstration: Shows how real system components work together.

    This demonstrates the integration of:
    - App definition structure
    - SQL execution against real database
    - Data validation
    - Governance checks

    Uses mock app definition (pre-defined components) to ensure consistent testing.
    """

    print("🔬 INTEGRATION DEMONSTRATION")
    print("="*50)
    print("Testing real system components with mock app definition")
    print()

    # Get the mock app definition (this is our "input")
    mock_app = get_mock_app_definition()

    print("📋 MOCK APP DEFINITION:")
    print(f"   Title: {mock_app['app_title']}")
    print(f"   Description: {mock_app['app_description']}")
    print(f"   Components: {len(mock_app['components'])}")
    print()

    # Show what components are defined
    print("🧩 COMPONENT DEFINITIONS:")
    for i, comp in enumerate(mock_app['components'], 1):
        print(f"   {i}. {comp['type'].upper()}: {comp['title']}")
        print(f"      SQL: {comp['sql_query']}")
        if 'config' in comp and 'value_column' in comp['config']:
            print(f"      Metric: {comp['config']['value_column']}")
        print()

    # Execute the components against real database
    print("⚙️  EXECUTING COMPONENTS (Real Database):")
    from engine.executor import execute_app_components
    db_conn = get_db_connection()
    execution_results = execute_app_components(db_conn, mock_app)

    success_count = 0
    for comp_id, result in execution_results.items():
        comp = next(c for c in mock_app['components'] if c['id'] == comp_id)
        status = result['status']
        emoji = "✅" if status == "success" else "❌"
        print(f"   {emoji} {comp['title']}: {status}")

        if status == "success":
            success_count += 1
            df = result['data']
            print(f"      → {len(df)} rows returned")
            if len(df) > 0 and len(df.columns) > 0:
                # Show actual data sample
                sample_data = df.head(1).to_dict('records')[0]
                print(f"      → Data: {sample_data}")
        else:
            print(f"      → Error: {result.get('error', 'Unknown error')}")
        print()

    # Validate the results
    print("🔍 VALIDATING RESULTS (Real Validation):")
    from engine.validator import validate_and_explain
    validation = validate_and_explain(mock_app, execution_results)
    print(f"   Overall Status: {validation.get('overall_status', 'unknown')}")
    print(f"   Components Validated: {len(validation.get('components', []))}")
    print()

    # Run governance checks
    print("🛡️  GOVERNANCE CHECKS (Real Security):")
    from engine.governance import run_governance_checks
    governance = run_governance_checks(mock_app, "analyst")
    print(f"   Overall Status: {governance.get('overall_status', 'unknown')}")
    print(f"   Checks Run: {len(governance.get('checks', []))}")

    passed_checks = [c for c in governance.get('checks', []) if c.get('status') == 'pass']
    failed_checks = [c for c in governance.get('checks', []) if c.get('status') == 'fail']
    print(f"   Checks Passed: {len(passed_checks)}")
    print(f"   Checks Failed: {len(failed_checks)}")

    if failed_checks:
        print("   Failed checks:")
        for check in failed_checks[:3]:  # Show first 3 failures
            print(f"      - {check.get('name', 'Unknown')}: {check.get('message', 'No details')}")

    print()
    print("📊 SUMMARY:")
    print(f"   Components: {len(mock_app['components'])}")
    print(f"   Successful Executions: {success_count}/{len(mock_app['components'])}")
    print(f"   Validation: {validation.get('overall_status', 'unknown')}")
    print(f"   Governance: {governance.get('overall_status', 'unknown')}")
    print()
    print("✅ Integration test demonstrates real system components working together!")


def run_all_integration_tests():
    """Run all integration tests and report results."""
    tests = [
        test_execute_then_validate,
        test_execute_validate_govern,
        test_app_definition_contract_shape,
        test_execution_results_contract_shape,
        test_live_intent_parsing,
        test_live_refinement,
        test_schema_contains_actual_columns,
        test_sample_rows_reflect_actual_data,
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

    print("Integration Tests Results:")
    print("=" * 50)
    for result in results:
        print(result)
    print("=" * 50)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")

    if failed > 0:
        return False

    # Always run demonstration after tests
    print("\n" + "="*60)
    print("🎯 RUNNING USER DEMONSTRATION")
    print("="*60)
    try:
        demonstrate_user_example()
        print("\n✅ Demonstration completed successfully!")
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")

    return True


if __name__ == "__main__":
    success = run_all_integration_tests()
    sys.exit(0 if success else 1)
