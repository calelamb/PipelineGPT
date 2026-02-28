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
