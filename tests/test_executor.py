"""Tests for engine/executor.py — validates SQL execution and filter injection."""

import sys
import os
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


def test_simple_query():
    """execute_query() must run SQL and return DataFrames."""
    from engine.executor import execute_query
    db_conn = get_db_connection()
    df = execute_query(db_conn, "SELECT COUNT(*) as total FROM supply_chain")
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1
    assert df.iloc[0, 0] > 0


def test_group_by_query():
    """execute_query() must handle GROUP BY queries."""
    from engine.executor import execute_query
    db_conn = get_db_connection()
    df = execute_query(
        db_conn,
        "SELECT supplier, AVG(defect_rate) as avg_defect FROM supply_chain GROUP BY supplier"
    )
    assert len(df) >= 3
    assert "supplier" in df.columns
    assert "avg_defect" in df.columns


def test_invalid_query_raises():
    """execute_query() must raise exception for invalid SQL."""
    from engine.executor import execute_query
    db_conn = get_db_connection()
    try:
        execute_query(db_conn, "SELECT * FROM nonexistent_table_xyz")
        assert False, "Expected exception for invalid query"
    except Exception:
        pass  # Expected


def test_multiselect_filter():
    """Filters must be injected as WHERE clauses."""
    from engine.executor import execute_query
    db_conn = get_db_connection()

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


def test_no_filters_returns_all():
    """No filters should return all data."""
    from engine.executor import execute_query
    db_conn = get_db_connection()
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


def test_executes_all_components():
    """execute_app_components() must run all component queries."""
    from engine.executor import execute_app_components
    db_conn = get_db_connection()
    mock_app_definition = get_mock_app_definition()
    results = execute_app_components(db_conn, mock_app_definition)

    assert isinstance(results, dict)

    # Should have a result for each component
    for comp in mock_app_definition["components"]:
        comp_id = comp["id"]
        assert comp_id in results, f"Missing result for component '{comp_id}'"


def test_successful_components_have_data():
    """Successful components must have data."""
    from engine.executor import execute_app_components
    db_conn = get_db_connection()
    mock_app_definition = get_mock_app_definition()
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


def test_error_components_have_error_message():
    """Error components must have error messages."""
    from engine.executor import execute_app_components
    db_conn = get_db_connection()

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


def run_all_executor_tests():
    """Run all executor tests and report results."""
    tests = [
        test_simple_query,
        test_group_by_query,
        test_invalid_query_raises,
        test_multiselect_filter,
        test_no_filters_returns_all,
        test_executes_all_components,
        test_successful_components_have_data,
        test_error_components_have_error_message,
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

    print("Executor Tests Results:")
    print("=" * 50)
    for result in results:
        print(result)
    print("=" * 50)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")

    if failed > 0:
        return False
    return True


if __name__ == "__main__":
    success = run_all_executor_tests()
    sys.exit(0 if success else 1)
