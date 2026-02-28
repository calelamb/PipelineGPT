import duckdb
from typing import Optional, List, Dict, Any
import pandas as pd
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# FILTER APPLICATION & SUBQUERY WRAPPING
# ============================================================================


def _build_filter_where_clause(filters: Optional[Dict[str, Any]]) -> str:
    """
    Build a WHERE clause from user-applied filters.

    Supports:
    - multiselect: column IN (val1, val2, ...)
    - date_range: column BETWEEN date1 AND date2
    - numeric_range: column BETWEEN num1 AND num2

    Args:
        filters: Dict mapping filter_id to selected values
                 Example: {"region_filter": ["North America", "Europe"]}

    Returns:
        str: WHERE clause (e.g., "WHERE region IN ('North America', 'Europe')")
             Returns empty string if no filters
    """
    if not filters:
        return ""

    where_conditions = []

    for filter_id, filter_value in filters.items():
        # For simplicity, assume filter_id maps to column name
        # In production, look up the column from app_definition.filters
        column_name = filter_id.replace("_filter", "")

        if isinstance(filter_value, list):
            # Multiselect: IN clause
            quoted_values = [f"'{v}'" for v in filter_value]
            where_conditions.append(f"{column_name} IN ({','.join(quoted_values)})")
        elif isinstance(filter_value, dict) and "start" in filter_value:
            # Date/numeric range: BETWEEN clause
            start = filter_value["start"]
            end = filter_value.get("end", start)
            where_conditions.append(f"{column_name} BETWEEN '{start}' AND '{end}'")

    if where_conditions:
        return "WHERE " + " AND ".join(where_conditions)
    return ""


def execute_query(
    conn: duckdb.DuckDBPyConnection,
    sql_query: str,
    filters: Optional[Dict[str, Any]] = None,
) -> pd.DataFrame:
    """
    Execute a SQL query with optional filter injection.

    For safety and flexibility, wraps the query as a subquery and applies
    filters via WHERE clause (if provided).

    Args:
        conn: DuckDB connection
        sql_query: SQL query to execute
        filters: Optional dict of filters to apply

    Returns:
        pd.DataFrame: Query results

    Raises:
        Exception: If query fails
    """
    where_clause = _build_filter_where_clause(filters)

    if where_clause:
        # Inject filters into the FROM supply_chain clause directly
        # This handles cases where the filter column isn't in the SELECT
        upper_query = sql_query.upper()
        if "WHERE" in upper_query:
            # Append to existing WHERE clause
            where_conditions = where_clause.replace("WHERE ", "")
            wrapped_query = sql_query + " AND " + where_conditions
        elif "FROM SUPPLY_CHAIN" in upper_query:
            # Insert WHERE clause after FROM supply_chain
            idx = upper_query.index("FROM SUPPLY_CHAIN") + len("FROM SUPPLY_CHAIN")
            wrapped_query = sql_query[:idx] + " " + where_clause + " " + sql_query[idx:]
        else:
            # Fallback: wrap as subquery
            wrapped_query = f"SELECT * FROM ({sql_query}) AS filtered_data {where_clause}"
        logger.info(f"Applied filters. Query: {wrapped_query[:100]}...")
    else:
        wrapped_query = sql_query

    try:
        df = conn.execute(wrapped_query).df()
        logger.info(f"✓ Query executed: {len(df)} rows returned")
        return df
    except Exception as e:
        logger.error(f"Query execution failed: {e}\nQuery: {wrapped_query}")
        raise


def execute_app_components(
    conn: duckdb.DuckDBPyConnection,
    app_definition: Dict[str, Any],
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute all components in an app_definition and return aggregated results.

    This function:
    1. Iterates through each component in app_definition
    2. Executes the component's SQL query (with filters applied)
    3. Returns results keyed by component_id

    The returned dict is passed to validator.validate_and_explain() for
    validation and explanation generation.

    Args:
        conn: DuckDB connection
        app_definition: App definition dict with components list
        filters: Optional user-applied filters

    Returns:
        Dict[str, Any]:
            {
                "component_id_1": pd.DataFrame (results),
                "component_id_2": pd.DataFrame (results),
                ...
            }
    """
    execution_results = {}

    components = app_definition.get("components", [])
    logger.info(f"Executing {len(components)} components...")

    for component in components:
        component_id = component.get("id")
        sql_query = component.get("sql_query")

        try:
            df = execute_query(conn, sql_query, filters)
            execution_results[component_id] = {
                "status": "success",
                "data": df,
                "row_count": len(df),
            }
        except Exception as e:
            logger.error(f"Component {component_id} failed: {e}")
            execution_results[component_id] = {
                "status": "error",
                "error": str(e),
                "row_count": 0,
            }

    return execution_results


if __name__ == "__main__":
    # Quick test
    from data.sample_data_loader import get_connection

    logging.basicConfig(level=logging.INFO)

    conn = get_connection()

    # Test query
    test_query = "SELECT supplier, AVG(defect_rate) as avg_defect FROM supply_chain GROUP BY supplier"
    result = execute_query(conn, test_query)
    print(result)

    # Test with filters
    test_filters = {"region_filter": ["North America", "Europe"]}
    result_filtered = execute_query(conn, test_query, test_filters)
    print("\nFiltered result:")
    print(result_filtered)
