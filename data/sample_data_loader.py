import duckdb
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Optional, Tuple

# ============================================================================
# GLOBAL CONNECTION (singleton pattern)
# ============================================================================

_conn: Optional[duckdb.DuckDBPyConnection] = None


def get_connection() -> duckdb.DuckDBPyConnection:
    """
    Returns a DuckDB connection. Creates and initializes tables on first call.
    Uses in-memory database (:memory:) for the hackathon.
    Re-creates connection if previously closed.
    """
    global _conn
    if _conn is not None:
        try:
            _conn.execute("SELECT 1")
        except Exception:
            _conn = None
    if _conn is None:
        _conn = duckdb.connect(":memory:")
        _initialize_tables(_conn)
    return _conn


def _initialize_tables(conn: duckdb.DuckDBPyConnection) -> None:
    """Initialize sample data tables in DuckDB."""
    df = _generate_sample_data()
    conn.register("supply_chain", df)
    print(f"✓ Loaded {len(df)} rows into supply_chain table")


def _generate_sample_data() -> pd.DataFrame:
    """
    Generate 500 rows of synthetic supply chain data.

    Columns:
    - order_id: unique identifier
    - order_date: date of order
    - supplier: supplier name
    - region: geographic region
    - product: product name
    - category: product category
    - quantity: order quantity
    - unit_cost: cost per unit
    - total_cost: quantity * unit_cost
    - defect_rate: percentage (0-5%)
    - delivery_days: days to deliver
    - on_time_delivery: 1 if on-time, 0 if late
    - shipping_mode: air, sea, truck, rail
    - shipping_cost: cost of shipping
    - warehouse_cost: storage cost
    """
    np.random.seed(42)
    n_rows = 500

    suppliers = [
        "Acme Corp",
        "BuildRight Inc",
        "Global Parts Ltd",
        "Superior Materials",
        "Reliable Suppliers Co",
    ]

    regions = ["North America", "Europe", "Asia Pacific", "Latin America", "Africa"]

    products = [
        "Steel Fasteners",
        "Aluminum Extrusions",
        "Plastic Components",
        "Rubber Seals",
        "Electronic Sensors",
        "Hydraulic Cylinders",
        "Control Systems",
        "Drive Belts",
    ]

    categories = [
        "Hardware",
        "Materials",
        "Electronics",
        "Mechanical",
        "Assembly",
    ]

    shipping_modes = ["air", "sea", "truck", "rail"]

    data = {
        "order_id": [f"ORD-{i:05d}" for i in range(1, n_rows + 1)],
        "order_date": pd.to_datetime([
            (datetime(2024, 1, 1) + timedelta(days=int(i * 365 / n_rows)))
            for i in range(n_rows)
        ]),
        "supplier": np.random.choice(suppliers, n_rows),
        "region": np.random.choice(regions, n_rows),
        "product": np.random.choice(products, n_rows),
        "category": np.random.choice(categories, n_rows),
        "quantity": np.random.randint(10, 500, n_rows),
        "unit_cost": np.round(np.random.uniform(5, 100, n_rows), 2),
        "defect_rate": np.round(np.random.uniform(0, 5, n_rows), 2),
        "delivery_days": np.random.randint(5, 45, n_rows),
        "on_time_delivery": np.random.choice([0, 1], n_rows, p=[0.2, 0.8]),
        "shipping_mode": np.random.choice(shipping_modes, n_rows),
        "shipping_cost": np.round(np.random.uniform(100, 5000, n_rows), 2),
        "warehouse_cost": np.round(np.random.uniform(50, 2000, n_rows), 2),
    }

    df = pd.DataFrame(data)

    # Calculate total_cost
    df["total_cost"] = (df["quantity"] * df["unit_cost"]).round(2)

    return df


def get_table_schema(conn: Optional[duckdb.DuckDBPyConnection] = None) -> str:
    """
    Returns a formatted schema string describing the supply_chain table.
    Used by intent_parser to inject schema into GPT-5.1 prompt.

    Args:
        conn: Optional DuckDB connection. Uses singleton if not provided.

    Returns:
        str: Human-readable schema description
    """
    if conn is None:
        conn = get_connection()
    result = conn.execute("DESCRIBE supply_chain").fetchall()

    schema_lines = ["Table: supply_chain", ""]
    for col_name, col_type, *_ in result:
        schema_lines.append(f"  - {col_name} ({col_type})")

    return "\n".join(schema_lines)


def get_sample_rows(conn: Optional[duckdb.DuckDBPyConnection] = None, n: int = 5) -> pd.DataFrame:
    """
    Returns first N rows of supply_chain table as DataFrame.
    CRITICAL: Used by intent_parser to inject sample data into GPT-5.1 prompt.
    This helps the AI understand data distribution and available values.

    Args:
        conn: Optional DuckDB connection. Uses singleton if not provided.
        n: Number of rows to return (default 5)

    Returns:
        pd.DataFrame: Sample rows from supply_chain table
    """
    if conn is None:
        conn = get_connection()
    df = conn.execute(f"SELECT * FROM supply_chain LIMIT {n}").df()
    return df


if __name__ == "__main__":
    # Quick test
    conn = get_connection()
    schema = get_table_schema()
    print(schema)
    print("\nSample rows:")
    print(get_sample_rows(3))
