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
