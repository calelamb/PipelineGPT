import os
from typing import Dict, List, Any
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# API & MODEL CONFIGURATION
# ============================================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.1")
APP_NAME = os.getenv("APP_NAME", "StackForge")
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

DATABASE_TYPE = os.getenv("DATABASE_TYPE", "duckdb")
DATABASE_PATH = os.getenv("DATABASE_PATH", ":memory:")
DATA_SOURCE = os.getenv("DATA_SOURCE", "synthetic")

# ============================================================================
# PII PATTERNS (for governance scanning)
# ============================================================================

PII_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "passport": r"\b[A-Z]{2}\d{6,8}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# ============================================================================
# ROLE-BASED ACCESS CONTROL (ENHANCED)
# ============================================================================

ROLES = {
    "admin": {
        "display_name": "Administrator",
        "capabilities": [
            "view_all_data",
            "view_sensitive_data",
            "view_pii",
            "export_data",
            "export_sensitive",
            "create_app",
            "modify_app",
            "delete_app",
            "view_audit_trail",
            "manage_roles",
            "bypass_row_limit",
        ],
        "max_rows_per_query": None,         # No limit
        "max_components_per_app": 15,       # Generous limit for admins
        "allowed_component_types": None,    # All types
        "can_use_templates": True,
        "session_timeout_minutes": 480,     # 8 hours
        "export_formats": ["csv", "json", "pdf"],
    },
    "analyst": {
        "display_name": "Data Analyst",
        "capabilities": [
            "view_all_data",
            "view_sensitive_data",
            "export_data",
            "create_app",
            "modify_app",
        ],
        "max_rows_per_query": 100000,
        "max_components_per_app": 6,
        "allowed_component_types": None,    # All types
        "can_use_templates": True,
        "session_timeout_minutes": 240,     # 4 hours
        "export_formats": ["csv", "json"],
    },
    "viewer": {
        "display_name": "Viewer",
        "capabilities": [
            "view_all_data",
        ],
        "max_rows_per_query": 10000,
        "max_components_per_app": 4,
        "allowed_component_types": [
            "bar_chart", "line_chart", "pie_chart",
            "kpi_card", "metric_highlight",
        ],  # No table or scatter_plot (can't see raw data)
        "can_use_templates": False,
        "session_timeout_minutes": 60,      # 1 hour
        "export_formats": [],               # No export
    },
}

# ============================================================================
# DATA SENSITIVITY CLASSIFICATION
# ============================================================================

COLUMN_SENSITIVITY = {
    # Public — all roles can see
    "public": [
        "order_id", "order_date", "region", "product", "category",
        "shipping_mode", "quantity",
    ],
    # Internal — analyst and admin only
    "internal": [
        "unit_cost", "total_cost", "shipping_cost", "warehouse_cost",
        "defect_rate",
    ],
    # Restricted — admin only
    "restricted": [
        "supplier",  # Supplier names are business-sensitive
    ],
}

# Reverse lookup: column → sensitivity level
COLUMN_SENSITIVITY_MAP = {}
for level, columns in COLUMN_SENSITIVITY.items():
    for col in columns:
        COLUMN_SENSITIVITY_MAP[col] = level

# Which roles can access which sensitivity levels
SENSITIVITY_ACCESS = {
    "admin": ["public", "internal", "restricted"],
    "analyst": ["public", "internal"],
    "viewer": ["public"],
}

# ============================================================================
# SQL SECURITY
# ============================================================================

# SQL keywords that should NEVER appear in generated queries
SQL_BLOCKLIST = [
    "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE",
    "TRUNCATE", "EXEC", "EXECUTE", "GRANT", "REVOKE",
    "UNION",  # Prevent UNION injection
    "INTO OUTFILE", "INTO DUMPFILE",  # File write attempts
    "LOAD_EXTENSION",  # DuckDB-specific: prevent loading extensions
]

# Max query length (characters) — prevents prompt injection via massive queries
MAX_QUERY_LENGTH = 2000

# ============================================================================
# APPLICATION TEMPLATES
# ============================================================================

TEMPLATES = [
    {
        "id": "supplier_performance",
        "name": "Supplier Performance",
        "description": "Analyze supplier defect rates and delivery performance",
        "default_prompt": "Create a dashboard showing supplier defect rates by region with on-time delivery percentage",
        "template_components": [
            "bar_chart",
            "metric_highlight",
            "line_chart",
        ],
    },
    {
        "id": "regional_analysis",
        "name": "Regional Analysis",
        "description": "Compare regional supply chain metrics",
        "default_prompt": "Show me cost breakdown and order volumes by region with a heat map",
        "template_components": [
            "pie_chart",
            "bar_chart",
            "metric_highlight",
        ],
    },
    {
        "id": "product_profitability",
        "name": "Product Profitability",
        "description": "Analyze product margins and costs",
        "default_prompt": "Display product margins, unit costs, and order volumes by category",
        "template_components": [
            "scatter_plot",
            "bar_chart",
            "table",
        ],
    },
    {
        "id": "shipping_optimization",
        "name": "Shipping Optimization",
        "description": "Optimize shipping costs and delivery performance",
        "default_prompt": "Compare shipping modes by cost, delivery time, and on-time performance",
        "template_components": [
            "bar_chart",
            "line_chart",
            "metric_highlight",
        ],
    },
    {
        "id": "inventory_health",
        "name": "Inventory Health",
        "description": "Monitor inventory levels and turnover",
        "default_prompt": "Show inventory turnover, warehouse costs, and stock levels by category",
        "template_components": [
            "area_chart",
            "bar_chart",
            "table",
        ],
    },
    {
        "id": "quality_assurance",
        "name": "Quality Assurance",
        "description": "Monitor product quality and defect trends",
        "default_prompt": "Display defect rates by supplier and product with trend analysis",
        "template_components": [
            "line_chart",
            "bar_chart",
            "metric_highlight",
        ],
    },
]

# ============================================================================
# COMPONENT TYPES & CONFIGURATION OPTIONS
# ============================================================================

COMPONENT_TYPES = [
    "kpi_card",
    "bar_chart",
    "line_chart",
    "pie_chart",
    "scatter_plot",
    "table",
    "metric_highlight",
    "area_chart",
]

# ============================================================================
# QUERY LIMITS & CONSTRAINTS
# ============================================================================

MAX_QUERY_COMPLEXITY = 5  # Max number of joins
MAX_RESULT_ROWS = 10000
MAX_COMPONENTS_PER_APP = 8
MIN_CHART_DATA_POINTS = 2
MAX_CHART_CATEGORIES = 50

# ============================================================================
# EXPORT SETTINGS
# ============================================================================

EXPORT_FORMATS = ["csv", "json", "pdf"]
EXPORT_ROW_LIMIT = 50000

# ============================================================================
# VALIDATION RULES
# ============================================================================

VALIDATION_RULES = {
    "table": {
        "min_rows": 1,
        "max_rows": 1000,
        "max_columns": 20,
    },
    "bar_chart": {
        "min_categories": 2,
        "max_categories": 50,
        "min_values": 1,
    },
    "line_chart": {
        "min_points": 3,
        "max_points": 500,
    },
    "pie_chart": {
        "min_slices": 2,
        "max_slices": 12,
    },
    "scatter_plot": {
        "min_points": 3,
        "max_points": 1000,
    },
    "area_chart": {
        "min_points": 3,
        "max_points": 500,
    },
    "kpi_card": {
        "expected_rows": 1,
    },
    "metric_highlight": {
        "expected_rows": 1,
    },
}
