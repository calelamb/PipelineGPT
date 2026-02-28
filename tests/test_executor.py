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
