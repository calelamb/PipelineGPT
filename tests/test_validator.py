"""Tests for engine/validator.py — validates result checking and explanation generation."""

import sys
import os
import pandas as pd

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


def get_mock_execution_results():
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


def test_returns_expected_structure():
    """validate_and_explain() must return expected structure."""
    from engine.validator import validate_and_explain
    mock_app_definition = get_mock_app_definition()
    mock_execution_results = get_mock_execution_results()
    result = validate_and_explain(mock_app_definition, mock_execution_results)

    assert isinstance(result, dict)
    assert "overall_status" in result, "Missing 'overall_status'"
    assert result["overall_status"] in ["success", "warning", "error"], \
        f"Invalid status: {result['overall_status']}"


def test_components_have_explanations():
    """Validation must produce component-level results."""
    from engine.validator import validate_and_explain
    mock_app_definition = get_mock_app_definition()
    mock_execution_results = get_mock_execution_results()
    result = validate_and_explain(mock_app_definition, mock_execution_results)

    # Should have component-level results
    components = result.get("components", [])
    assert len(components) > 0, "Validation should produce component-level results"

    for comp in components:
        assert "explanation" in comp or "status" in comp, \
            f"Component validation missing explanation/status: {comp}"


def test_empty_data_produces_warning():
    """Empty data should produce warning."""
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


def test_error_result_detected():
    """Error results must be detected."""
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


def run_all_validator_tests():
    """Run all validator tests and report results."""
    tests = [
        test_returns_expected_structure,
        test_components_have_explanations,
        test_empty_data_produces_warning,
        test_error_result_detected,
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

    print("Validator Tests Results:")
    print("=" * 50)
    for result in results:
        print(result)
    print("=" * 50)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")

    if failed > 0:
        return False
    return True


if __name__ == "__main__":
    success = run_all_validator_tests()
    sys.exit(0 if success else 1)
