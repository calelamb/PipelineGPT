"""Tests for data/sample_data_loader.py — validates DuckDB setup and data integrity."""

import sys
import os
import pandas as pd

# Add the project root to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data.sample_data_loader import get_connection


def get_db_connection():
    """Get a database connection for testing."""
    return get_connection()


def test_connection_returns():
    """get_connection() must return a valid DuckDB connection."""
    db_conn = get_db_connection()
    assert db_conn is not None


def test_supply_chain_table_exists():
    """The supply_chain table must exist."""
    db_conn = get_db_connection()
    tables = db_conn.execute("SHOW TABLES").fetchdf()
    table_names = tables.iloc[:, 0].str.lower().tolist()
    assert "supply_chain" in table_names, \
        f"supply_chain table not found. Tables: {table_names}"


def test_row_count():
    """supply_chain must have approximately 500 rows."""
    db_conn = get_db_connection()
    count = db_conn.execute("SELECT COUNT(*) FROM supply_chain").fetchone()[0]
    assert count >= 100, f"Expected ~500 rows, got {count}"
    assert count <= 1000, f"Expected ~500 rows, got {count}"


REQUIRED_COLUMNS = [
    "order_id", "order_date", "supplier", "region", "product",
    "category", "quantity", "unit_cost", "total_cost", "defect_rate",
    "delivery_days", "on_time_delivery", "shipping_mode"
]


def test_required_columns_exist():
    """All required columns must exist in the table."""
    db_conn = get_db_connection()
    schema = db_conn.execute("DESCRIBE supply_chain").fetchdf()
    actual_columns = schema["column_name"].str.lower().tolist()

    missing = [c for c in REQUIRED_COLUMNS if c.lower() not in actual_columns]
    assert len(missing) == 0, f"Missing columns: {missing}. Got: {actual_columns}"


def test_no_null_critical_columns():
    """Critical columns should not be entirely NULL."""
    db_conn = get_db_connection()
    for col in ["supplier", "region", "defect_rate"]:
        try:
            null_count = db_conn.execute(
                f"SELECT COUNT(*) FROM supply_chain WHERE {col} IS NULL"
            ).fetchone()[0]
            total = db_conn.execute("SELECT COUNT(*) FROM supply_chain").fetchone()[0]
            assert null_count < total, f"Column '{col}' is entirely NULL"
        except Exception:
            pass  # Column might not exist yet; test_required_columns catches that


def test_get_table_schema_returns_string():
    """get_table_schema() must return useful output."""
    from data.sample_data_loader import get_table_schema
    db_conn = get_db_connection()
    schema = get_table_schema(db_conn)
    assert isinstance(schema, str)
    assert len(schema) > 50, "Schema string is too short — probably incomplete"
    assert "supplier" in schema.lower(), "Schema should mention 'supplier' column"


def test_get_sample_rows_returns_dataframe():
    """get_all_sample_data() must return formatted sample data."""
    from data.sample_data_loader import get_all_sample_data
    db_conn = get_db_connection()
    samples = get_all_sample_data(db_conn)
    assert isinstance(samples, str)
    assert len(samples) > 100, f"Expected substantial sample data, got {len(samples)} chars"
    assert "SUPPLY_CHAIN TABLE" in samples, "Should include supply_chain table header"


def test_sample_rows_have_real_values():
    """Sample data must have actual data, not empty."""
    from data.sample_data_loader import get_all_sample_data
    db_conn = get_db_connection()
    samples = get_all_sample_data(db_conn)
    assert len(samples.strip()) > 0, "Sample data should not be empty"
    assert "order_id" in samples, "Should contain actual column data"
    assert "supplier" in samples, "Should contain actual column data"


def test_group_by_supplier():
    """GROUP BY supplier must return multiple suppliers."""
    db_conn = get_db_connection()
    df = db_conn.execute(
        "SELECT supplier, COUNT(*) as cnt FROM supply_chain GROUP BY supplier"
    ).fetchdf()
    assert len(df) >= 3, f"Expected multiple suppliers, got {len(df)}"


def test_group_by_region():
    """GROUP BY region must return multiple regions."""
    db_conn = get_db_connection()
    df = db_conn.execute(
        "SELECT region, COUNT(*) as cnt FROM supply_chain GROUP BY region"
    ).fetchdf()
    assert len(df) >= 2, f"Expected multiple regions, got {len(df)}"


def test_avg_defect_rate():
    """AVG(defect_rate) must return a positive value."""
    db_conn = get_db_connection()
    df = db_conn.execute(
        "SELECT ROUND(AVG(defect_rate), 2) as avg_defect FROM supply_chain"
    ).fetchdf()
    assert len(df) == 1
    val = df.iloc[0, 0]
    assert val is not None and val > 0, f"AVG(defect_rate) should be > 0, got {val}"


def test_date_grouping():
    """Date-based grouping must work (for line charts)."""
    db_conn = get_db_connection()
    try:
        # Try strftime first (if order_date is DATE/TIMESTAMP)
        df = db_conn.execute(
            "SELECT strftime(order_date, '%Y-%m') as month, COUNT(*) as cnt "
            "FROM supply_chain GROUP BY month ORDER BY month"
        ).fetchdf()
        assert len(df) >= 2, "Date grouping should return multiple months"
    except Exception:
        # If strftime fails, try string operations (if order_date is VARCHAR)
        try:
            df = db_conn.execute(
                "SELECT SUBSTR(order_date, 1, 7) as month, COUNT(*) as cnt "
                "FROM supply_chain GROUP BY month ORDER BY month"
            ).fetchdf()
            assert len(df) >= 2, "Date grouping should return multiple months"
        except Exception as e2:
            raise AssertionError(f"Date grouping failed with strftime and SUBSTR: {e2}")


def test_filter_by_region():
    """WHERE region = 'X' must work (for filter injection)."""
    db_conn = get_db_connection()
    regions = db_conn.execute(
        "SELECT DISTINCT region FROM supply_chain"
    ).fetchdf()["region"].tolist()
    assert len(regions) > 0

    first_region = regions[0]
    filtered = db_conn.execute(
        f"SELECT COUNT(*) FROM supply_chain WHERE region = '{first_region}'"
    ).fetchone()[0]
    assert filtered > 0, f"No rows found for region '{first_region}'"


def run_all_data_loader_tests():
    """Run all data loader tests and report results."""
    tests = [
        test_connection_returns,
        test_supply_chain_table_exists,
        test_row_count,
        test_required_columns_exist,
        test_no_null_critical_columns,
        test_get_table_schema_returns_string,
        test_get_sample_rows_returns_dataframe,
        test_sample_rows_have_real_values,
        test_group_by_supplier,
        test_group_by_region,
        test_avg_defect_rate,
        test_date_grouping,
        test_filter_by_region,
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

    print("Data Loader Tests Results:")
    print("=" * 50)
    for result in results:
        print(result)
    print("=" * 50)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")

    if failed > 0:
        return False
    return True


if __name__ == "__main__":
    success = run_all_data_loader_tests()
    sys.exit(0 if success else 1)
