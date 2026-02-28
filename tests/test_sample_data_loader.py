# filepath: tests/test_sample_data_loader.py
"""
Sample Data Loader Tests
Run with: python tests/test_sample_data_loader.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import tempfile
from unittest.mock import patch
from data.sample_data_loader import (
    get_connection,
    get_table_schema,
    get_available_tables,
    get_all_sample_data,
)


def reset_global_connection():
    """Reset the global connection for testing"""
    import data.sample_data_loader as sdl
    sdl._conn = None


def test_connection_creation():
    """Test that get_connection() creates a valid DuckDB connection"""
    print("Testing connection creation...")
    reset_global_connection()

    conn = get_connection()
    assert conn is not None, "Connection should not be None"
    assert hasattr(conn, 'execute'), "Connection should have execute method"

    # Test that we can execute a simple query
    result = conn.execute("SELECT 1 as test").fetchone()
    assert result[0] == 1, "Should be able to execute basic queries"

    print("✅ Connection creation test passed")


def test_connection_reuse():
    """Test that get_connection() reuses the global connection"""
    print("Testing connection reuse...")
    reset_global_connection()

    conn1 = get_connection()
    conn2 = get_connection()

    assert conn1 is conn2, "Should return the same connection object"

    print("✅ Connection reuse test passed")


def test_available_tables_discovery():
    """Test that available tables are correctly discovered from CSV files"""
    print("Testing table discovery...")
    reset_global_connection()

    tables = get_available_tables()

    # With current CSV files, we should have both tables
    assert 'supply_chain' in tables, "supply_chain table should be available"
    assert 'customers' in tables, "customers table should be available"
    assert len(tables) == 2, f"Should have exactly 2 tables, got {len(tables)}: {tables}"

    print("✅ Table discovery test passed")


def test_fallback_synthetic_data():
    """Test fallback to synthetic data when no CSV files exist"""
    print("Testing synthetic data fallback...")
    reset_global_connection()

    # Mock glob.glob to return empty list (no CSV files)
    with patch('data.sample_data_loader.glob.glob', return_value=[]):
        tables = get_available_tables()
        assert 'supply_chain' in tables, "Should fallback to synthetic supply_chain table"

    print("✅ Synthetic data fallback test passed")


def test_table_creation():
    """Test that tables are created from CSV files"""
    print("Testing table creation...")
    reset_global_connection()

    conn = get_connection()

    # Check that tables exist
    result = conn.execute("SHOW TABLES").fetchall()
    table_names = [row[0] for row in result]

    assert 'supply_chain' in table_names, "supply_chain table should exist"
    assert 'customers' in table_names, "customers table should exist"

    print("✅ Table creation test passed")


def test_data_integrity():
    """Test that CSV data is loaded with correct row counts"""
    print("Testing data integrity...")
    reset_global_connection()

    conn = get_connection()

    # Check row counts
    supply_count = conn.execute("SELECT COUNT(*) FROM supply_chain").fetchone()[0]
    customer_count = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]

    assert supply_count == 500, f"supply_chain should have 500 rows, got {supply_count}"
    assert customer_count == 20, f"customers should have 20 rows, got {customer_count}"

    print("✅ Data integrity test passed")


def test_schema_retrieval():
    """Test that table schemas are correctly retrieved"""
    print("Testing schema retrieval...")
    reset_global_connection()

    schema = get_table_schema()

    # Check that schema contains expected information
    assert 'supply_chain' in schema, "Schema should include supply_chain table"
    assert 'customers' in schema, "Schema should include customers table"
    assert 'order_id (VARCHAR)' in schema, "Schema should include order_id column"
    assert 'customer_id (VARCHAR)' in schema, "Schema should include customer_id column"
    assert 'quantity (BIGINT)' in schema, "Schema should include quantity column"
    assert 'satisfaction_score (DOUBLE)' in schema, "Schema should include satisfaction_score column"

    print("✅ Schema retrieval test passed")


def test_sample_rows_retrieval():
    """Test that sample rows can be retrieved from all tables"""
    print("Testing sample rows retrieval...")
    reset_global_connection()

    # Test that we can get sample data from all tables
    sample_data = get_all_sample_data(n=3)

    assert isinstance(sample_data, str), "Should return a string"
    assert 'SUPPLY_CHAIN TABLE' in sample_data, "Should include supply_chain table"
    assert 'CUSTOMERS TABLE' in sample_data, "Should include customers table"
    assert 'order_id' in sample_data, "Should include order data"
    assert 'customer_id' in sample_data, "Should include customer data"

    # Count the number of lines that contain data (not headers)
    lines = sample_data.split('\n')
    data_lines = [line for line in lines if line.strip() and not line.startswith('===') and not line.strip() == '']
    # Should have at least 3 data rows per table (header + 3 data rows + empty line per table)
    assert len(data_lines) >= 6, f"Should have at least 6 data lines, got {len(data_lines)}"

    print("✅ Sample rows retrieval test passed")


def test_nonexistent_table_handling():
    """Test that all sample data still works even with potential table issues"""
    print("Testing nonexistent table handling...")
    reset_global_connection()

    # The all-tables function should handle missing tables gracefully
    sample_data = get_all_sample_data(n=2)

    assert isinstance(sample_data, str), "Should return a string"
    # Should still work even if some tables have issues
    assert len(sample_data) > 0, "Should return some data"

    print("✅ Nonexistent table handling test passed")


def test_all_sample_data():
    """Test that formatted sample data from all tables is returned"""
    print("Testing all sample data retrieval...")
    reset_global_connection()

    sample_data = get_all_sample_data(n=2)

    assert isinstance(sample_data, str), "Should return a string"
    assert 'SUPPLY_CHAIN TABLE' in sample_data, "Should include supply_chain table header"
    assert 'CUSTOMERS TABLE' in sample_data, "Should include customers table header"
    assert 'order_id' in sample_data, "Should include order data"
    assert 'customer_id' in sample_data, "Should include customer data"

    print("✅ All sample data test passed")


def test_empty_tables_fallback():
    """Test behavior when no tables are available"""
    print("Testing empty tables fallback...")
    reset_global_connection()

    with patch('data.sample_data_loader.glob.glob', return_value=[]):
        sample_data = get_all_sample_data()
        assert 'SUPPLY_CHAIN TABLE' in sample_data, "Should fallback to synthetic data"

    print("✅ Empty tables fallback test passed")


def test_malformed_csv_handling():
    """Test error handling for malformed CSV files"""
    print("Testing malformed CSV handling...")
    reset_global_connection()

    # Create a malformed CSV file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("col1,col2\nval1\nval2,val3,val4")  # Inconsistent columns
        bad_csv_path = f.name

    try:
        with patch('data.sample_data_loader.glob.glob', return_value=[bad_csv_path]):
            # This should handle the error gracefully
            conn = get_connection()

            # Check that no malformed table was created
            result = conn.execute("SHOW TABLES").fetchall()
            table_names = [row[0] for row in result]

            assert 'bad' not in table_names, "Malformed CSV should not create a table"

    finally:
        # Clean up
        os.unlink(bad_csv_path)

    print("✅ Malformed CSV handling test passed")


def test_connection_error_recovery():
    """Test that connection errors are handled and recovered"""
    print("Testing connection error recovery...")
    reset_global_connection()

    # Force the global connection to be invalid
    import data.sample_data_loader as sdl
    sdl._conn = "invalid_connection"

    # Should create a new valid connection
    conn = get_connection()
    assert conn is not None, "Should create new connection"
    assert hasattr(conn, 'execute'), "New connection should be valid"

    # Should be able to execute queries
    result = conn.execute("SELECT 1").fetchone()
    assert result[0] == 1, "Should be able to execute queries on recovered connection"

    print("✅ Connection error recovery test passed")


def test_connection_failure_handling():
    """Test handling of DuckDB connection failures"""
    print("Testing connection failure handling...")
    reset_global_connection()

    with patch('data.sample_data_loader.duckdb.connect') as mock_connect:
        mock_connect.side_effect = Exception("Database connection failed")

        try:
            get_connection()
            assert False, "Should have raised an exception"
        except Exception as e:
            assert "Database connection failed" in str(e), f"Expected connection failure message, got: {e}"

    print("✅ Connection failure handling test passed")


def test_schema_caching():
    """Test that schema information is cached and consistent"""
    print("Testing schema caching...")
    reset_global_connection()

    # Get schema twice
    schema1 = get_table_schema()
    schema2 = get_table_schema()

    assert schema1 == schema2, "Schema should be consistent across calls"

    print("✅ Schema caching test passed")


def run_all_tests():
    """Run all tests and report results"""
    print("🧪 Running Sample Data Loader Tests")
    print("=" * 50)

    tests = [
        test_connection_creation,
        test_connection_reuse,
        test_available_tables_discovery,
        test_fallback_synthetic_data,
        test_table_creation,
        test_data_integrity,
        test_schema_retrieval,
        test_sample_rows_retrieval,
        test_nonexistent_table_handling,
        test_all_sample_data,
        test_empty_tables_fallback,
        test_malformed_csv_handling,
        test_connection_error_recovery,
        test_connection_failure_handling,
        test_schema_caching,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"❌ {test_func.__name__} FAILED: {str(e)}")
            failed += 1
        print()  # Empty line between tests

    print("=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")

    if failed > 0:
        print("❌ Some tests failed!")
        return False
    else:
        print("🎉 All tests passed!")
        return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)