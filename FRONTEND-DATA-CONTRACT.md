# FRONTEND DATA CONTRACT

> Auto-generated from live GPT-5.1 pipeline runs. This shows the **exact JSON** your Streamlit frontend receives.

---

## How to Call the Engine

```python
from engine.pipeline import run_pipeline

result = run_pipeline(
    user_message="Show me supplier defect rates by region",
    existing_app=None,      # Pass previous app_definition for conversational refinement
    filters=None,           # Dict of filter_id -> selected values from sidebar
    role="analyst",         # "admin", "analyst", or "viewer"
)

# result keys:
# result["app_definition"]      -> app layout (components + filters)
# result["execution_results"]   -> actual data rows per component
# result["validation"]          -> validation status + explanations
# result["governance"]          -> PII, access, export checks
```

---

## Prompt 1: "Show me supplier defect rates by region"

**Input:**
```python
result = run_pipeline(
    user_message="Show me supplier defect rates by region",
    filters=None,
    role="analyst",
)
```

### result["app_definition"]

```json
{
  "app_title": "Supplier Defect Rates by Region",
  "app_description": "Analyze average defect rates for each supplier across regions to identify quality issues and improvement opportunities.",
  "components": [
    {
      "id": "bar_1",
      "type": "bar_chart",
      "title": "Average Defect Rate by Supplier and Region",
      "sql_query": "SELECT supplier, region, AVG(defect_rate) AS avg_defect_rate\nFROM supply_chain\nGROUP BY supplier, region\nORDER BY avg_defect_rate DESC;",
      "config": {
        "x_axis": "region",
        "y_axis": "avg_defect_rate",
        "format": "percentage"
      }
    },
    {
      "id": "table_1",
      "type": "table",
      "title": "Supplier Defect Rate Details by Region",
      "sql_query": "SELECT supplier, region, COUNT(DISTINCT order_id) AS orders_count, SUM(quantity) AS total_quantity, AVG(defect_rate) AS avg_defect_rate\nFROM supply_chain\nGROUP BY supplier, region\nORDER BY avg_defect_rate DESC;",
      "config": {
        "columns": [
          "supplier",
          "region",
          "orders_count",
          "total_quantity",
          "avg_defect_rate"
        ],
        "sort_column": "avg_defect_rate",
        "sort_order": "desc",
        "format": "number"
      }
    },
    {
      "id": "kpi_1",
      "type": "kpi_card",
      "title": "Overall Average Defect Rate",
      "sql_query": "SELECT AVG(defect_rate) AS overall_defect_rate\nFROM supply_chain;",
      "config": {
        "value_column": "overall_defect_rate",
        "metric_name": "Overall Defect Rate",
        "format": "percentage"
      }
    }
  ],
  "filters": [
    {
      "id": "f_region",
      "name": "Region",
      "column": "region",
      "type": "multiselect"
    },
    {
      "id": "f_supplier",
      "name": "Supplier",
      "column": "supplier",
      "type": "multiselect"
    },
    {
      "id": "f_category",
      "name": "Category",
      "column": "category",
      "type": "multiselect"
    }
  ]
}
```

### result["execution_results"]

> Data trimmed to first 3 rows per component for readability. Actual results may have more rows.

```json
{
  "bar_1": {
    "status": "success",
    "data": [
      {
        "supplier": "Acme Corp",
        "region": "Europe",
        "avg_defect_rate": 3.183846153846154
      },
      {
        "supplier": "Superior Materials",
        "region": "Africa",
        "avg_defect_rate": 2.794285714285714
      },
      {
        "supplier": "Global Parts Ltd",
        "region": "Asia Pacific",
        "avg_defect_rate": 2.7895833333333333
      }
    ],
    "row_count": 25,
    "_total_rows": 25,
    "_showing": 3
  },
  "table_1": {
    "status": "success",
    "data": [
      {
        "supplier": "Acme Corp",
        "region": "Europe",
        "orders_count": 26,
        "total_quantity": 7076.0,
        "avg_defect_rate": 3.183846153846154
      },
      {
        "supplier": "Superior Materials",
        "region": "Africa",
        "orders_count": 14,
        "total_quantity": 4494.0,
        "avg_defect_rate": 2.794285714285714
      },
      {
        "supplier": "Global Parts Ltd",
        "region": "Asia Pacific",
        "orders_count": 24,
        "total_quantity": 5996.0,
        "avg_defect_rate": 2.7895833333333333
      }
    ],
    "row_count": 25,
    "_total_rows": 25,
    "_showing": 3
  },
  "kpi_1": {
    "status": "success",
    "data": [
      {
        "overall_defect_rate": 2.5294000000000025
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  }
}
```

### result["validation"]

```json
{
  "overall_status": "success",
  "components": [
    {
      "id": "bar_1",
      "title": "Average Defect Rate by Supplier and Region",
      "type": "bar_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Average Defect Rate by Supplier and Region: Compares 25 categories"
    },
    {
      "id": "table_1",
      "title": "Supplier Defect Rate Details by Region",
      "type": "table",
      "status": "success",
      "warnings": [],
      "explanation": "Supplier Defect Rate Details by Region: Shows 25 rows across 5 columns"
    },
    {
      "id": "kpi_1",
      "title": "Overall Average Defect Rate",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "Overall Average Defect Rate: Displays a single metric value (1 data point)"
    }
  ],
  "total_warnings": 0
}
```

### result["governance"]

```json
{
  "overall_status": "pass",
  "passed": true,
  "role": "analyst",
  "checks": [
    {
      "name": "pii_detection",
      "status": "pass",
      "details": "No PII detected"
    },
    {
      "name": "access_control",
      "status": "pass",
      "details": "Role 'analyst' granted create_app"
    },
    {
      "name": "query_complexity",
      "status": "pass",
      "details": "Analyzed 3 queries"
    },
    {
      "name": "data_quality",
      "status": "pass",
      "details": "good"
    },
    {
      "name": "export_control",
      "status": "pass",
      "details": "51 rows (limit: 100000)"
    }
  ],
  "pii_detected": [],
  "access_granted": true,
  "query_complexity": {
    "bar_1": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "table_1": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "kpi_1": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    }
  },
  "data_quality": {
    "has_null_values": false,
    "has_duplicates": false,
    "overall_quality": "good"
  },
  "export_allowed": true,
  "warnings": []
}
```

---

## Prompt 2: "Compare shipping costs by mode with delivery performance trends"

**Input:**
```python
result = run_pipeline(
    user_message="Compare shipping costs by mode with delivery performance trends",
    filters=None,
    role="analyst",
)
```

### result["app_definition"]

```json
{
  "app_title": "Shipping Cost & Delivery Performance Dashboard",
  "app_description": "Analyze and compare shipping costs by mode alongside delivery performance trends over time.",
  "components": [
    {
      "id": "kpi_avg_shipping_cost",
      "type": "kpi_card",
      "title": "Average Shipping Cost per Order",
      "sql_query": "SELECT AVG(shipping_cost) AS avg_shipping_cost FROM supply_chain;",
      "config": {
        "value_column": "avg_shipping_cost",
        "metric_name": "Avg Shipping Cost",
        "format": "currency"
      }
    },
    {
      "id": "kpi_on_time_rate",
      "type": "kpi_card",
      "title": "Overall On-Time Delivery Rate",
      "sql_query": "SELECT CASE WHEN COUNT(*) = 0 THEN 0 ELSE CAST(SUM(on_time_delivery) AS DOUBLE) / COUNT(*) END AS on_time_rate FROM supply_chain;",
      "config": {
        "value_column": "on_time_rate",
        "metric_name": "On-Time Delivery Rate",
        "format": "percentage"
      }
    },
    {
      "id": "bar_shipping_cost_by_mode",
      "type": "bar_chart",
      "title": "Average Shipping Cost by Shipping Mode",
      "sql_query": "SELECT shipping_mode, AVG(shipping_cost) AS avg_shipping_cost FROM supply_chain GROUP BY shipping_mode ORDER BY avg_shipping_cost DESC;",
      "config": {
        "x_axis": "shipping_mode",
        "y_axis": "avg_shipping_cost",
        "format": "currency"
      }
    },
    {
      "id": "bar_ontime_by_mode",
      "type": "bar_chart",
      "title": "On-Time Delivery Rate by Shipping Mode",
      "sql_query": "SELECT shipping_mode, CASE WHEN COUNT(*) = 0 THEN 0 ELSE CAST(SUM(on_time_delivery) AS DOUBLE) / COUNT(*) END AS on_time_rate FROM supply_chain GROUP BY shipping_mode ORDER BY on_time_rate DESC;",
      "config": {
        "x_axis": "shipping_mode",
        "y_axis": "on_time_rate",
        "format": "percentage"
      }
    },
    {
      "id": "line_shipping_cost_trend",
      "type": "line_chart",
      "title": "Shipping Cost Trend Over Time",
      "sql_query": "SELECT strftime(order_date, '%Y-%m-%d') AS order_day, AVG(shipping_cost) AS avg_shipping_cost FROM supply_chain GROUP BY order_day ORDER BY order_day;",
      "config": {
        "x_axis": "order_day",
        "y_axis": "avg_shipping_cost",
        "format": "currency"
      }
    },
    {
      "id": "line_delivery_performance_trend",
      "type": "line_chart",
      "title": "On-Time Delivery Trend Over Time",
      "sql_query": "SELECT strftime(order_date, '%Y-%m-%d') AS order_day, CASE WHEN COUNT(*) = 0 THEN 0 ELSE CAST(SUM(on_time_delivery) AS DOUBLE) / COUNT(*) END AS on_time_rate FROM supply_chain GROUP BY order_day ORDER BY order_day;",
      "config": {
        "x_axis": "order_day",
        "y_axis": "on_time_rate",
        "format": "percentage"
      }
    },
    {
      "id": "scatter_cost_vs_delivery_days",
      "type": "scatter_plot",
      "title": "Shipping Cost vs Delivery Days by Mode",
      "sql_query": "SELECT shipping_mode, delivery_days, shipping_cost FROM supply_chain;",
      "config": {
        "x_axis": "delivery_days",
        "y_axis": "shipping_cost",
        "format": "currency"
      }
    },
    {
      "id": "table_mode_summary",
      "type": "table",
      "title": "Shipping Mode Performance Summary",
      "sql_query": "SELECT shipping_mode, COUNT(*) AS total_orders, AVG(shipping_cost) AS avg_shipping_cost, AVG(delivery_days) AS avg_delivery_days, CASE WHEN COUNT(*) = 0 THEN 0 ELSE CAST(SUM(on_time_delivery) AS DOUBLE) / COUNT(*) END AS on_time_rate FROM supply_chain GROUP BY shipping_mode ORDER BY total_orders DESC;",
      "config": {
        "columns": [
          "shipping_mode",
          "total_orders",
          "avg_shipping_cost",
          "avg_delivery_days",
          "on_time_rate"
        ],
        "sort_column": "total_orders",
        "sort_order": "desc",
        "format": "number"
      }
    }
  ],
  "filters": [
    {
      "id": "filter_date_range",
      "name": "Order Date",
      "column": "order_date",
      "type": "date_range"
    },
    {
      "id": "filter_region",
      "name": "Region",
      "column": "region",
      "type": "multiselect"
    },
    {
      "id": "filter_supplier",
      "name": "Supplier",
      "column": "supplier",
      "type": "multiselect"
    },
    {
      "id": "filter_shipping_mode",
      "name": "Shipping Mode",
      "column": "shipping_mode",
      "type": "multiselect"
    },
    {
      "id": "filter_category",
      "name": "Category",
      "column": "category",
      "type": "multiselect"
    }
  ]
}
```

### result["execution_results"]

> Data trimmed to first 3 rows per component for readability. Actual results may have more rows.

```json
{
  "kpi_avg_shipping_cost": {
    "status": "success",
    "data": [
      {
        "avg_shipping_cost": 2451.762320000001
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  },
  "kpi_on_time_rate": {
    "status": "success",
    "data": [
      {
        "on_time_rate": 0.842
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  },
  "bar_shipping_cost_by_mode": {
    "status": "success",
    "data": [
      {
        "shipping_mode": "sea",
        "avg_shipping_cost": 2498.3345161290326
      },
      {
        "shipping_mode": "rail",
        "avg_shipping_cost": 2494.874206349206
      },
      {
        "shipping_mode": "air",
        "avg_shipping_cost": 2453.3712403100776
      }
    ],
    "row_count": 4,
    "_total_rows": 4,
    "_showing": 3
  },
  "bar_ontime_by_mode": {
    "status": "success",
    "data": [
      {
        "shipping_mode": "sea",
        "on_time_rate": 0.8790322580645161
      },
      {
        "shipping_mode": "truck",
        "on_time_rate": 0.8677685950413223
      },
      {
        "shipping_mode": "rail",
        "on_time_rate": 0.8253968253968254
      }
    ],
    "row_count": 4,
    "_total_rows": 4,
    "_showing": 3
  },
  "line_shipping_cost_trend": {
    "status": "success",
    "data": [
      {
        "order_day": "2024-01-01",
        "avg_shipping_cost": 2430.805
      },
      {
        "order_day": "2024-01-02",
        "avg_shipping_cost": 4647.7
      },
      {
        "order_day": "2024-01-03",
        "avg_shipping_cost": 2718.67
      }
    ],
    "row_count": 365,
    "_total_rows": 365,
    "_showing": 3
  },
  "line_delivery_performance_trend": {
    "status": "success",
    "data": [
      {
        "order_day": "2024-01-01",
        "on_time_rate": 1.0
      },
      {
        "order_day": "2024-01-02",
        "on_time_rate": 1.0
      },
      {
        "order_day": "2024-01-03",
        "on_time_rate": 1.0
      }
    ],
    "row_count": 365,
    "_total_rows": 365,
    "_showing": 3
  },
  "scatter_cost_vs_delivery_days": {
    "status": "success",
    "data": [
      {
        "shipping_mode": "sea",
        "delivery_days": 30,
        "shipping_cost": 3134.27
      },
      {
        "shipping_mode": "rail",
        "delivery_days": 42,
        "shipping_cost": 1727.34
      },
      {
        "shipping_mode": "rail",
        "delivery_days": 5,
        "shipping_cost": 4647.7
      }
    ],
    "row_count": 500,
    "_total_rows": 500,
    "_showing": 3
  },
  "table_mode_summary": {
    "status": "success",
    "data": [
      {
        "shipping_mode": "air",
        "total_orders": 129,
        "avg_shipping_cost": 2453.3712403100776,
        "avg_delivery_days": 23.697674418604652,
        "on_time_rate": 0.7984496124031008
      },
      {
        "shipping_mode": "rail",
        "total_orders": 126,
        "avg_shipping_cost": 2494.874206349206,
        "avg_delivery_days": 26.150793650793652,
        "on_time_rate": 0.8253968253968254
      },
      {
        "shipping_mode": "sea",
        "total_orders": 124,
        "avg_shipping_cost": 2498.3345161290326,
        "avg_delivery_days": 24.096774193548388,
        "on_time_rate": 0.8790322580645161
      }
    ],
    "row_count": 4,
    "_total_rows": 4,
    "_showing": 3
  }
}
```

### result["validation"]

```json
{
  "overall_status": "success",
  "components": [
    {
      "id": "kpi_avg_shipping_cost",
      "title": "Average Shipping Cost per Order",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "Average Shipping Cost per Order: Displays a single metric value (1 data point)"
    },
    {
      "id": "kpi_on_time_rate",
      "title": "Overall On-Time Delivery Rate",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "Overall On-Time Delivery Rate: Displays a single metric value (1 data point)"
    },
    {
      "id": "bar_shipping_cost_by_mode",
      "title": "Average Shipping Cost by Shipping Mode",
      "type": "bar_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Average Shipping Cost by Shipping Mode: Compares 4 categories"
    },
    {
      "id": "bar_ontime_by_mode",
      "title": "On-Time Delivery Rate by Shipping Mode",
      "type": "bar_chart",
      "status": "success",
      "warnings": [],
      "explanation": "On-Time Delivery Rate by Shipping Mode: Compares 4 categories"
    },
    {
      "id": "line_shipping_cost_trend",
      "title": "Shipping Cost Trend Over Time",
      "type": "line_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Shipping Cost Trend Over Time: Shows trend across 365 time points"
    },
    {
      "id": "line_delivery_performance_trend",
      "title": "On-Time Delivery Trend Over Time",
      "type": "line_chart",
      "status": "success",
      "warnings": [],
      "explanation": "On-Time Delivery Trend Over Time: Shows trend across 365 time points"
    },
    {
      "id": "scatter_cost_vs_delivery_days",
      "title": "Shipping Cost vs Delivery Days by Mode",
      "type": "scatter_plot",
      "status": "success",
      "warnings": [],
      "explanation": "Shipping Cost vs Delivery Days by Mode: Plots 500 data points"
    },
    {
      "id": "table_mode_summary",
      "title": "Shipping Mode Performance Summary",
      "type": "table",
      "status": "success",
      "warnings": [],
      "explanation": "Shipping Mode Performance Summary: Shows 4 rows across 5 columns"
    }
  ],
  "total_warnings": 0
}
```

### result["governance"]

```json
{
  "overall_status": "pass",
  "passed": true,
  "role": "analyst",
  "checks": [
    {
      "name": "pii_detection",
      "status": "pass",
      "details": "No PII detected"
    },
    {
      "name": "access_control",
      "status": "pass",
      "details": "Role 'analyst' granted create_app"
    },
    {
      "name": "query_complexity",
      "status": "pass",
      "details": "Analyzed 8 queries"
    },
    {
      "name": "data_quality",
      "status": "pass",
      "details": "good"
    },
    {
      "name": "export_control",
      "status": "pass",
      "details": "1244 rows (limit: 100000)"
    }
  ],
  "pii_detected": [],
  "access_granted": true,
  "query_complexity": {
    "kpi_avg_shipping_cost": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "kpi_on_time_rate": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "bar_shipping_cost_by_mode": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "bar_ontime_by_mode": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "line_shipping_cost_trend": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "line_delivery_performance_trend": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "scatter_cost_vs_delivery_days": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": false,
      "is_complex": false
    },
    "table_mode_summary": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    }
  },
  "data_quality": {
    "has_null_values": false,
    "has_duplicates": false,
    "overall_quality": "good"
  },
  "export_allowed": true,
  "warnings": []
}
```

---

## Prompt 3: "Give me a complete supply chain overview with KPIs, charts, and a detail table"

**Input:**
```python
result = run_pipeline(
    user_message="Give me a complete supply chain overview with KPIs, charts, and a detail table",
    filters=None,
    role="analyst",
)
```

### result["app_definition"]

```json
{
  "app_title": "Supply Chain Overview Dashboard",
  "app_description": "A comprehensive overview of supply chain performance with cost, delivery, and quality KPIs, trend charts, and a detailed order table.",
  "components": [
    {
      "id": "kpi_total_cost",
      "type": "kpi_card",
      "title": "Total Supply Chain Cost",
      "sql_query": "SELECT SUM(total_cost) AS total_cost FROM supply_chain;",
      "config": {
        "value_column": "total_cost",
        "metric_name": "Total Cost",
        "format": "currency"
      }
    },
    {
      "id": "kpi_total_orders",
      "type": "kpi_card",
      "title": "Total Orders",
      "sql_query": "SELECT COUNT(DISTINCT order_id) AS total_orders FROM supply_chain;",
      "config": {
        "value_column": "total_orders",
        "metric_name": "Total Orders",
        "format": "number"
      }
    },
    {
      "id": "kpi_on_time_rate",
      "type": "kpi_card",
      "title": "On-Time Delivery Rate",
      "sql_query": "SELECT CASE WHEN COUNT(*) = 0 THEN 0 ELSE CAST(SUM(on_time_delivery) AS DOUBLE)/CAST(COUNT(*) AS DOUBLE) END AS on_time_rate FROM supply_chain;",
      "config": {
        "value_column": "on_time_rate",
        "metric_name": "On-Time Delivery Rate",
        "format": "percentage"
      }
    },
    {
      "id": "kpi_avg_defect_rate",
      "type": "kpi_card",
      "title": "Average Defect Rate",
      "sql_query": "SELECT AVG(defect_rate) AS avg_defect_rate FROM supply_chain;",
      "config": {
        "value_column": "avg_defect_rate",
        "metric_name": "Average Defect Rate",
        "format": "percentage"
      }
    },
    {
      "id": "area_cost_over_time",
      "type": "area_chart",
      "title": "Total Cost Over Time (Monthly)",
      "sql_query": "SELECT strftime(order_date, '%Y-%m') AS order_month, SUM(total_cost) AS total_cost FROM supply_chain GROUP BY order_month ORDER BY order_month;",
      "config": {
        "x_axis": "order_month",
        "y_axis": "total_cost",
        "format": "currency",
        "sort_column": "order_month",
        "sort_order": "asc"
      }
    },
    {
      "id": "bar_cost_by_region",
      "type": "bar_chart",
      "title": "Total Cost by Region",
      "sql_query": "SELECT region, SUM(total_cost) AS total_cost FROM supply_chain GROUP BY region ORDER BY total_cost DESC;",
      "config": {
        "x_axis": "region",
        "y_axis": "total_cost",
        "format": "currency",
        "sort_column": "total_cost",
        "sort_order": "desc"
      }
    },
    {
      "id": "bar_cost_by_category",
      "type": "bar_chart",
      "title": "Total Cost by Category",
      "sql_query": "SELECT category, SUM(total_cost) AS total_cost FROM supply_chain GROUP BY category ORDER BY total_cost DESC;",
      "config": {
        "x_axis": "category",
        "y_axis": "total_cost",
        "format": "currency",
        "sort_column": "total_cost",
        "sort_order": "desc"
      }
    },
    {
      "id": "bar_ontime_by_supplier",
      "type": "bar_chart",
      "title": "On-Time Delivery Rate by Supplier",
      "sql_query": "SELECT supplier, CASE WHEN COUNT(*) = 0 THEN 0 ELSE CAST(SUM(on_time_delivery) AS DOUBLE)/CAST(COUNT(*) AS DOUBLE) END AS on_time_rate FROM supply_chain GROUP BY supplier ORDER BY on_time_rate DESC;",
      "config": {
        "x_axis": "supplier",
        "y_axis": "on_time_rate",
        "format": "percentage",
        "sort_column": "on_time_rate",
        "sort_order": "desc"
      }
    },
    {
      "id": "scatter_delivery_vs_cost",
      "type": "scatter_plot",
      "title": "Delivery Days vs Total Cost",
      "sql_query": "SELECT delivery_days, total_cost FROM supply_chain;",
      "config": {
        "x_axis": "delivery_days",
        "y_axis": "total_cost",
        "format": "currency",
        "sort_column": "delivery_days",
        "sort_order": "asc"
      }
    },
    {
      "id": "pie_cost_by_shipping_mode",
      "type": "pie_chart",
      "title": "Cost Share by Shipping Mode",
      "sql_query": "SELECT shipping_mode, SUM(total_cost) AS total_cost FROM supply_chain GROUP BY shipping_mode ORDER BY total_cost DESC;",
      "config": {
        "x_axis": "shipping_mode",
        "y_axis": "total_cost",
        "format": "currency",
        "sort_column": "total_cost",
        "sort_order": "desc"
      }
    },
    {
      "id": "table_order_details",
      "type": "table",
      "title": "Order Details",
      "sql_query": "SELECT order_id, order_date, supplier, region, product, category, quantity, unit_cost, defect_rate, delivery_days, on_time_delivery, shipping_mode, shipping_cost, warehouse_cost, total_cost FROM supply_chain ORDER BY order_date DESC, order_id DESC;",
      "config": {
        "columns": [
          "order_id",
          "order_date",
          "supplier",
          "region",
          "product",
          "category",
          "quantity",
          "unit_cost",
          "defect_rate",
          "delivery_days",
          "on_time_delivery",
          "shipping_mode",
          "shipping_cost",
          "warehouse_cost",
          "total_cost"
        ],
        "sort_column": "order_date",
        "sort_order": "desc",
        "format": "number"
      }
    },
    {
      "id": "metric_cost_per_unit",
      "type": "metric_highlight",
      "title": "Average Cost per Unit",
      "sql_query": "SELECT CASE WHEN SUM(quantity) = 0 THEN 0 ELSE SUM(total_cost)/SUM(quantity) END AS avg_cost_per_unit FROM supply_chain;",
      "config": {
        "value_column": "avg_cost_per_unit",
        "metric_name": "Avg Cost per Unit",
        "format": "currency"
      }
    }
  ],
  "filters": [
    {
      "id": "filter_date_range",
      "name": "Order Date",
      "column": "order_date",
      "type": "date_range"
    },
    {
      "id": "filter_region",
      "name": "Region",
      "column": "region",
      "type": "multiselect"
    },
    {
      "id": "filter_supplier",
      "name": "Supplier",
      "column": "supplier",
      "type": "multiselect"
    },
    {
      "id": "filter_category",
      "name": "Category",
      "column": "category",
      "type": "multiselect"
    },
    {
      "id": "filter_shipping_mode",
      "name": "Shipping Mode",
      "column": "shipping_mode",
      "type": "multiselect"
    },
    {
      "id": "filter_delivery_days",
      "name": "Delivery Days",
      "column": "delivery_days",
      "type": "numeric_range"
    }
  ]
}
```

### result["execution_results"]

> Data trimmed to first 3 rows per component for readability. Actual results may have more rows.

```json
{
  "kpi_total_cost": {
    "status": "success",
    "data": [
      {
        "total_cost": 6626121.460000003
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  },
  "kpi_total_orders": {
    "status": "success",
    "data": [
      {
        "total_orders": 500
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  },
  "kpi_on_time_rate": {
    "status": "success",
    "data": [
      {
        "on_time_rate": 0.842
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  },
  "kpi_avg_defect_rate": {
    "status": "success",
    "data": [
      {
        "avg_defect_rate": 2.5294000000000025
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  },
  "area_cost_over_time": {
    "status": "success",
    "data": [
      {
        "order_month": "2024-01",
        "total_cost": 572685.78
      },
      {
        "order_month": "2024-02",
        "total_cost": 448626.75999999995
      },
      {
        "order_month": "2024-03",
        "total_cost": 694919.5999999999
      }
    ],
    "row_count": 12,
    "_total_rows": 12,
    "_showing": 3
  },
  "bar_cost_by_region": {
    "status": "success",
    "data": [
      {
        "region": "North America",
        "total_cost": 1586725.6999999995
      },
      {
        "region": "Africa",
        "total_cost": 1402320.2299999997
      },
      {
        "region": "Asia Pacific",
        "total_cost": 1327014.8299999996
      }
    ],
    "row_count": 5,
    "_total_rows": 5,
    "_showing": 3
  },
  "bar_cost_by_category": {
    "status": "success",
    "data": [
      {
        "category": "Materials",
        "total_cost": 1370146.7099999993
      },
      {
        "category": "Electronics",
        "total_cost": 1360626.62
      },
      {
        "category": "Mechanical",
        "total_cost": 1347052.1699999997
      }
    ],
    "row_count": 5,
    "_total_rows": 5,
    "_showing": 3
  },
  "bar_ontime_by_supplier": {
    "status": "success",
    "data": [
      {
        "supplier": "Reliable Suppliers Co",
        "on_time_rate": 0.9247311827956989
      },
      {
        "supplier": "BuildRight Inc",
        "on_time_rate": 0.8736842105263158
      },
      {
        "supplier": "Superior Materials",
        "on_time_rate": 0.8392857142857143
      }
    ],
    "row_count": 5,
    "_total_rows": 5,
    "_showing": 3
  },
  "scatter_delivery_vs_cost": {
    "status": "success",
    "data": [
      {
        "delivery_days": 30,
        "total_cost": 2651.2
      },
      {
        "delivery_days": 42,
        "total_cost": 19818.99
      },
      {
        "delivery_days": 5,
        "total_cost": 7165.8
      }
    ],
    "row_count": 500,
    "_total_rows": 500,
    "_showing": 3
  },
  "pie_cost_by_shipping_mode": {
    "status": "success",
    "data": [
      {
        "shipping_mode": "sea",
        "total_cost": 1770329.5599999996
      },
      {
        "shipping_mode": "rail",
        "total_cost": 1657798.1999999995
      },
      {
        "shipping_mode": "truck",
        "total_cost": 1613811.5
      }
    ],
    "row_count": 4,
    "_total_rows": 4,
    "_showing": 3
  },
  "table_order_details": {
    "status": "success",
    "data": [
      {
        "order_id": "ORD-00500",
        "order_date": "2024-12-30 00:00:00",
        "supplier": "Acme Corp",
        "region": "Asia Pacific",
        "product": "Rubber Seals",
        "category": "Mechanical",
        "quantity": 126,
        "unit_cost": 21.06,
        "defect_rate": 4.39,
        "delivery_days": 36,
        "on_time_delivery": 1,
        "shipping_mode": "rail",
        "shipping_cost": 1395.91,
        "warehouse_cost": 1713.21,
        "total_cost": 2653.56
      },
      {
        "order_id": "ORD-00499",
        "order_date": "2024-12-29 00:00:00",
        "supplier": "Acme Corp",
        "region": "Latin America",
        "product": "Aluminum Extrusions",
        "category": "Mechanical",
        "quantity": 150,
        "unit_cost": 5.02,
        "defect_rate": 3.62,
        "delivery_days": 36,
        "on_time_delivery": 1,
        "shipping_mode": "truck",
        "shipping_cost": 1077.12,
        "warehouse_cost": 1414.21,
        "total_cost": 753.0
      },
      {
        "order_id": "ORD-00498",
        "order_date": "2024-12-28 00:00:00",
        "supplier": "Acme Corp",
        "region": "North America",
        "product": "Electronic Sensors",
        "category": "Materials",
        "quantity": 34,
        "unit_cost": 88.05,
        "defect_rate": 1.33,
        "delivery_days": 13,
        "on_time_delivery": 1,
        "shipping_mode": "sea",
        "shipping_cost": 2261.64,
        "warehouse_cost": 1482.68,
        "total_cost": 2993.7
      }
    ],
    "row_count": 500,
    "_total_rows": 500,
    "_showing": 3
  },
  "metric_cost_per_unit": {
    "status": "success",
    "data": [
      {
        "avg_cost_per_unit": 50.96075693718085
      }
    ],
    "row_count": 1,
    "_total_rows": 1,
    "_showing": 1
  }
}
```

### result["validation"]

```json
{
  "overall_status": "success",
  "components": [
    {
      "id": "kpi_total_cost",
      "title": "Total Supply Chain Cost",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "Total Supply Chain Cost: Displays a single metric value (1 data point)"
    },
    {
      "id": "kpi_total_orders",
      "title": "Total Orders",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "Total Orders: Displays a single metric value (1 data point)"
    },
    {
      "id": "kpi_on_time_rate",
      "title": "On-Time Delivery Rate",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "On-Time Delivery Rate: Displays a single metric value (1 data point)"
    },
    {
      "id": "kpi_avg_defect_rate",
      "title": "Average Defect Rate",
      "type": "kpi_card",
      "status": "success",
      "warnings": [],
      "explanation": "Average Defect Rate: Displays a single metric value (1 data point)"
    },
    {
      "id": "area_cost_over_time",
      "title": "Total Cost Over Time (Monthly)",
      "type": "area_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Total Cost Over Time (Monthly): Displays area trend with 12 points"
    },
    {
      "id": "bar_cost_by_region",
      "title": "Total Cost by Region",
      "type": "bar_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Total Cost by Region: Compares 5 categories"
    },
    {
      "id": "bar_cost_by_category",
      "title": "Total Cost by Category",
      "type": "bar_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Total Cost by Category: Compares 5 categories"
    },
    {
      "id": "bar_ontime_by_supplier",
      "title": "On-Time Delivery Rate by Supplier",
      "type": "bar_chart",
      "status": "success",
      "warnings": [],
      "explanation": "On-Time Delivery Rate by Supplier: Compares 5 categories"
    },
    {
      "id": "scatter_delivery_vs_cost",
      "title": "Delivery Days vs Total Cost",
      "type": "scatter_plot",
      "status": "success",
      "warnings": [],
      "explanation": "Delivery Days vs Total Cost: Plots 500 data points"
    },
    {
      "id": "pie_cost_by_shipping_mode",
      "title": "Cost Share by Shipping Mode",
      "type": "pie_chart",
      "status": "success",
      "warnings": [],
      "explanation": "Cost Share by Shipping Mode: Breaks down into 4 segments"
    },
    {
      "id": "table_order_details",
      "title": "Order Details",
      "type": "table",
      "status": "success",
      "warnings": [],
      "explanation": "Order Details: Shows 500 rows across 15 columns"
    },
    {
      "id": "metric_cost_per_unit",
      "title": "Average Cost per Unit",
      "type": "metric_highlight",
      "status": "success",
      "warnings": [],
      "explanation": "Average Cost per Unit: Highlights key metric (1 data point)"
    }
  ],
  "total_warnings": 0
}
```

### result["governance"]

```json
{
  "overall_status": "pass",
  "passed": true,
  "role": "analyst",
  "checks": [
    {
      "name": "pii_detection",
      "status": "pass",
      "details": "No PII detected"
    },
    {
      "name": "access_control",
      "status": "pass",
      "details": "Role 'analyst' granted create_app"
    },
    {
      "name": "query_complexity",
      "status": "pass",
      "details": "Analyzed 12 queries"
    },
    {
      "name": "data_quality",
      "status": "pass",
      "details": "good"
    },
    {
      "name": "export_control",
      "status": "pass",
      "details": "1036 rows (limit: 100000)"
    }
  ],
  "pii_detected": [],
  "access_granted": true,
  "query_complexity": {
    "kpi_total_cost": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "kpi_total_orders": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "kpi_on_time_rate": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "kpi_avg_defect_rate": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "area_cost_over_time": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "bar_cost_by_region": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "bar_cost_by_category": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "bar_ontime_by_supplier": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "scatter_delivery_vs_cost": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": false,
      "is_complex": false
    },
    "pie_cost_by_shipping_mode": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    },
    "table_order_details": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": false,
      "is_complex": false
    },
    "metric_cost_per_unit": {
      "join_count": 0,
      "subquery_count": 0,
      "has_aggregation": true,
      "is_complex": false
    }
  },
  "data_quality": {
    "has_null_values": false,
    "has_duplicates": false,
    "overall_quality": "good"
  },
  "export_allowed": true,
  "warnings": []
}
```

---