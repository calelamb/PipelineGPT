import duckdb
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any
import os
import glob

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
    """Initialize tables from all CSV files in the data directory."""
    # Get the directory where this file is located
    data_dir = os.path.dirname(os.path.abspath(__file__))

    # Find all CSV files in the data directory
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))

    if not csv_files:
        print("⚠️  No CSV files found in data directory. Using synthetic data as fallback.")
        # Fallback to synthetic data if no CSVs found
        df = _generate_sample_data()
        conn.register("supply_chain", df)
        print(f"✓ Loaded {len(df)} rows into supply_chain table (synthetic)")
        return

    # Load each CSV file as a table
    for csv_file in csv_files:
        table_name = os.path.splitext(os.path.basename(csv_file))[0]  # Remove .csv extension
        try:
            df = pd.read_csv(csv_file)
            conn.register(table_name, df)
            print(f"✓ Loaded {len(df)} rows into {table_name} table from {os.path.basename(csv_file)}")
        except Exception as e:
            print(f"❌ Failed to load {csv_file}: {e}")


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
    Returns a formatted schema string describing all available tables.
    Used by intent_parser to inject schema into GPT-5.1 prompt.

    Args:
        conn: Optional DuckDB connection. Uses singleton if not provided.

    Returns:
        str: Human-readable schema description for all tables
    """
    if conn is None:
        conn = get_connection()

    # Get all table names
    try:
        tables_result = conn.execute("SHOW TABLES").fetchall()
        table_names = [row[0] for row in tables_result]
    except Exception:
        # Fallback for older DuckDB versions
        table_names = ["supply_chain"]  # Assume default table exists

    schema_lines = []

    for table_name in table_names:
        try:
            result = conn.execute(f"DESCRIBE {table_name}").fetchall()
            schema_lines.append(f"Table: {table_name}")
            schema_lines.append("")
            for col_name, col_type, *_ in result:
                schema_lines.append(f"  - {col_name} ({col_type})")
            schema_lines.append("")
        except Exception as e:
            schema_lines.append(f"Table: {table_name} (Error reading schema: {e})")
            schema_lines.append("")

    return "\n".join(schema_lines).strip()


def get_sample_rows_from_all_tables(conn: Optional[duckdb.DuckDBPyConnection] = None, n: int = 3) -> Dict[str, pd.DataFrame]:
    """
    Returns sample rows from all available tables.
    Useful for providing comprehensive sample data to LLMs.

    Args:
        conn: Optional DuckDB connection. Uses singleton if not provided.
        n: Number of rows to return per table (default 3)

    Returns:
        Dict[str, pd.DataFrame]: Dictionary mapping table names to sample DataFrames
    """
    if conn is None:
        conn = get_connection()

    samples = {}

    try:
        tables_result = conn.execute("SHOW TABLES").fetchall()
        table_names = [row[0] for row in tables_result]
    except Exception:
        # Fallback
        table_names = ["supply_chain"]

    for table_name in table_names:
        try:
            df = conn.execute(f"SELECT * FROM {table_name} LIMIT {n}").df()
            samples[table_name] = df
        except Exception as e:
            print(f"Warning: Could not get samples from {table_name}: {e}")

    return samples


def get_all_sample_data(conn: Optional[duckdb.DuckDBPyConnection] = None, n: int = 3) -> str:
    """
    Returns sample rows from all tables as a formatted string.
    Useful for providing comprehensive sample data to LLMs.

    Args:
        conn: Optional DuckDB connection. Uses singleton if not provided.
        n: Number of rows to return per table (default 3)

    Returns:
        str: Formatted sample data string for all tables
    """
    samples = get_sample_rows_from_all_tables(conn=conn, n=n)

    output_lines = []
    for table_name, df in samples.items():
        output_lines.append(f"=== {table_name.upper()} TABLE ===")
        output_lines.append(df.to_string())
        output_lines.append("")

    return "\n".join(output_lines).strip()


def get_available_tables(conn: Optional[duckdb.DuckDBPyConnection] = None) -> List[str]:
    """
    Returns a list of all available table names.

    Args:
        conn: Optional DuckDB connection. Uses singleton if not provided.

    Returns:
        List[str]: List of table names
    """
    if conn is None:
        conn = get_connection()

    try:
        tables_result = conn.execute("SHOW TABLES").fetchall()
        return [row[0] for row in tables_result]
    except Exception:
        return ["supply_chain"]  # Fallback


if __name__ == "__main__":
    # Quick test
    conn = get_connection()

    print("=== AVAILABLE TABLES ===")
    tables = get_available_tables(conn)
    print(f"Found tables: {tables}")
    print()

    print("=== SCHEMA INFORMATION ===")
    schema = get_table_schema(conn)
    print(schema)
    print()

    print("=== SAMPLE DATA FROM ALL TABLES ===")
    all_samples = get_all_sample_data(conn, n=3)
    print(all_samples)
