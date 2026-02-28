import json
import os
from typing import Optional, Dict, Any
from openai import OpenAI
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# GPT-5.1 FUNCTION SCHEMA FOR DATA APP CREATION
# ============================================================================

APP_INTENT_FUNCTION = {
    "type": "function",
    "function": {
        "name": "create_data_app",
        "description": "Create an interactive data app definition with visualizations and filters",
        "parameters": {
            "type": "object",
            "properties": {
                "app_title": {
                    "type": "string",
                    "description": "Title of the data app (e.g., 'Supplier Performance Dashboard')",
                },
                "app_description": {
                    "type": "string",
                    "description": "Brief description of what the app does",
                },
                "components": {
                    "type": "array",
                    "description": "List of visualization components",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Unique component ID (e.g., 'chart_1')",
                            },
                            "type": {
                                "type": "string",
                                "enum": [
                                    "kpi_card",
                                    "bar_chart",
                                    "line_chart",
                                    "pie_chart",
                                    "scatter_plot",
                                    "table",
                                    "metric_highlight",
                                    "area_chart",
                                ],
                                "description": "Type of visualization",
                            },
                            "title": {
                                "type": "string",
                                "description": "Component title",
                            },
                            "sql_query": {
                                "type": "string",
                                "description": "SQL query to fetch data (SELECT from supply_chain table)",
                            },
                            "config": {
                                "type": "object",
                                "description": "Component-specific configuration",
                                "properties": {
                                    "x_axis": {
                                        "type": "string",
                                        "description": "Column name for X-axis (charts)",
                                    },
                                    "y_axis": {
                                        "type": "string",
                                        "description": "Column name for Y-axis (charts)",
                                    },
                                    "value_column": {
                                        "type": "string",
                                        "description": "Column to display as value (KPI cards, metrics)",
                                    },
                                    "metric_name": {
                                        "type": "string",
                                        "description": "Name of metric being displayed",
                                    },
                                    "format": {
                                        "type": "string",
                                        "enum": ["number", "currency", "percentage", "date"],
                                        "description": "Format for value display",
                                    },
                                    "columns": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Columns to display in table",
                                    },
                                    "sort_column": {
                                        "type": "string",
                                        "description": "Column to sort by",
                                    },
                                    "sort_order": {
                                        "type": "string",
                                        "enum": ["asc", "desc"],
                                        "description": "Sort order",
                                    },
                                },
                            },
                        },
                        "required": [
                            "id",
                            "type",
                            "title",
                            "sql_query",
                            "config",
                        ],
                    },
                },
                "filters": {
                    "type": "array",
                    "description": "List of filters users can apply",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Unique filter ID",
                            },
                            "name": {
                                "type": "string",
                                "description": "Filter display name",
                            },
                            "column": {
                                "type": "string",
                                "description": "Column to filter on",
                            },
                            "type": {
                                "type": "string",
                                "enum": [
                                    "multiselect",
                                    "date_range",
                                    "numeric_range",
                                ],
                                "description": "Type of filter",
                            },
                            "default_values": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Default selected values",
                            },
                        },
                        "required": [
                            "id",
                            "name",
                            "column",
                            "type",
                        ],
                    },
                },
            },
            "required": [
                "app_title",
                "app_description",
                "components",
                "filters",
            ],
        },
    },
}

# ============================================================================
# SYSTEM PROMPT (DYNAMIC — NOT HARDCODED SCHEMA)
# ============================================================================

SYSTEM_PROMPT_TEMPLATE = """You are an expert data engineer helping users create interactive data dashboards.

The user has a supply chain dataset with the following structure:

{schema}

Sample data (first 5 rows):
{sample_data}

Based on the user's request, create an app definition that:
1. Uses SQL queries to fetch the right data
2. Includes appropriate visualizations (charts, tables, KPIs)
3. Provides useful filters for exploration
4. Follows the app_definition schema exactly

IMPORTANT:
- All SQL queries must be valid DuckDB syntax
- All SQL queries must SELECT FROM the 'supply_chain' table
- Only use columns that exist in the schema above
- Keep queries efficient (avoid SELECT *)
- For aggregations, use GROUP BY appropriately
- For filters, the column name must match exactly what's in the schema

Return the app definition as a JSON object via the create_data_app function.
"""


def parse_intent(
    user_message: str,
    existing_app: Optional[Dict[str, Any]] = None,
    table_schema: Optional[str] = None,
    sample_data: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parse user intent and return an app_definition JSON structure.

    This function:
    1. Injects dynamic schema and sample data into the system prompt
    2. Sends user message + schema to GPT-5.1 with function calling
    3. Forces tool_choice to create_data_app to ensure structured output
    4. Returns the parsed app_definition

    Supports two modes:
    - NEW BUILD: Create a new app from scratch (existing_app=None)
    - CONVERSATIONAL REFINEMENT: Modify existing app based on user feedback

    Args:
        user_message: User's natural language request
        existing_app: Current app definition (if refining). None for new apps.
        table_schema: Formatted schema string (from sample_data_loader.get_table_schema())
        sample_data: Sample rows as string (from sample_data_loader.get_sample_rows())

    Returns:
        Dict[str, Any]: app_definition JSON matching the schema

    Raises:
        ValueError: If GPT-5.1 response is invalid or missing function call
    """
    from data.sample_data_loader import get_table_schema, get_sample_rows

    # Load schema and sample data if not provided
    if table_schema is None:
        table_schema = get_table_schema()

    if sample_data is None:
        sample_df = get_sample_rows(n=5)
        sample_data = sample_df.to_string()

    # Inject schema into system prompt
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        schema=table_schema,
        sample_data=sample_data,
    )

    # For refinement mode, include existing app in context
    if existing_app:
        system_prompt += f"\n\nCurrent app definition:\n{json.dumps(existing_app, indent=2)}\n\nUser is asking to refine this app."

    # Initialize OpenAI client
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    # Call GPT-5.1 with tool calling
    try:
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-5.1"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            tools=[APP_INTENT_FUNCTION],
            tool_choice={"type": "function", "function": {"name": "create_data_app"}},
            temperature=0.3,
            max_completion_tokens=4096,
        )
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        raise ValueError(f"Failed to parse intent: {e}")

    # Extract tool call from response
    tool_calls = response.choices[0].message.tool_calls
    if not tool_calls:
        raise ValueError(
            "GPT-5.1 did not return a tool call. "
            "Ensure the prompt and schema are clear."
        )

    tool_call = tool_calls[0]
    if tool_call.function.name != "create_data_app":
        raise ValueError(f"Unexpected function call: {tool_call.function.name}")

    # Parse the app_definition from function arguments
    try:
        app_definition = json.loads(tool_call.function.arguments)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse function arguments: {e}")
        raise ValueError(f"Invalid JSON in function call: {e}")

    logger.info(f"✓ Parsed intent into app with {len(app_definition.get('components', []))} components")

    return app_definition


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)

    test_message = "Show me supplier defect rates by region with on-time delivery percentage"
    result = parse_intent(test_message)
    print(json.dumps(result, indent=2))
