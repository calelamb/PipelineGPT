# ENGINE STRESS TEST PRD

## Purpose

Your 55 unit/integration tests prove the engine works under ideal conditions. This PRD tests whether it **survives the real world** — vague users, adversarial inputs, edge cases, and the kinds of prompts judges will throw at you during the demo. Every failure you find now is one you won't hit on stage.

---

## HOW TO USE THIS

Run each test category as a Claude Code task:

```
Read ENGINE-STRESS-TEST.md. For each test in each category, call run_pipeline() with the given prompt and verify the expected behavior. Log PASS/FAIL for each. If anything fails, fix the engine and re-run. Do not stop until all tests pass.
```

You need your `OPENAI_API_KEY` set in `.env` — every test here hits the live API.

---

## CATEGORY 1: VAGUE & AMBIGUOUS PROMPTS

These simulate users who don't know what they want. The engine should still produce something reasonable, not crash.

### Test 1.1 — Maximally Vague
```
Prompt: "Show me something interesting"
```
- **Must:** Return valid app_definition with at least 2 components
- **Must:** Pick reasonable columns (not random)
- **Must NOT:** Crash, return empty components, or produce invalid SQL

### Test 1.2 — No Specifics
```
Prompt: "I want a dashboard"
```
- **Must:** Return a multi-component app with a mix of chart types
- **Must:** Include at least 1 filter

### Test 1.3 — Typos and Bad Grammar
```
Prompt: "shwo me defcet rates bi supplier plz"
```
- **Must:** Correctly interpret as "show me defect rates by supplier"
- **Must:** Return bar_chart or table with supplier on x-axis and defect_rate on y-axis

### Test 1.4 — Single Word
```
Prompt: "costs"
```
- **Must:** Return something related to cost columns (total_cost, unit_cost, shipping_cost, warehouse_cost)
- **Must NOT:** Crash or return 0 components

### Test 1.5 — Question Format
```
Prompt: "Which suppliers have the highest defect rates?"
```
- **Must:** Return a ranked visualization (bar chart or table sorted desc by defect_rate)
- **Must:** Group by supplier

---

## CATEGORY 2: COMPLEX MULTI-INTENT PROMPTS

These test whether the engine can handle compound requests that require multiple component types.

### Test 2.1 — Triple Intent
```
Prompt: "Compare shipping costs by mode, show delivery trends over time, and give me the total warehouse cost"
```
- **Must:** Return at least 3 components:
  - bar_chart for shipping costs by mode
  - line_chart for delivery trends
  - kpi_card or metric_highlight for total warehouse cost
- **Must:** Each component has a different, valid SQL query

### Test 2.2 — Everything At Once
```
Prompt: "I need a full supply chain overview: KPIs for total orders and average cost, defect rates by supplier as a bar chart, delivery performance trend as a line chart, cost breakdown by region as a pie chart, and a detailed table of all suppliers"
```
- **Must:** Return 5+ components covering all requested types
- **Must:** Each SQL query is syntactically valid and returns data
- **Must NOT:** Exceed MAX_COMPONENTS_PER_APP (8)

### Test 2.3 — Contradictory Intent
```
Prompt: "Show me a pie chart of delivery days over time"
```
- **Must:** Handle gracefully — pie charts don't suit time series data
- **Should:** Either adapt (use line_chart instead) or produce a reasonable pie chart grouping
- **Must NOT:** Crash or produce SQL that returns 500 ungrouped rows for a pie chart

### Test 2.4 — Comparison Request
```
Prompt: "Compare Acme Corp vs BuildRight Inc on every metric"
```
- **Must:** Filter or focus on those two suppliers
- **Must:** Cover multiple metrics (cost, defect, delivery, etc.)
- **Should:** Include at least a table and a chart

---

## CATEGORY 3: EDGE CASE SQL GENERATION

These test whether GPT-5.1 generates SQL that actually works in DuckDB.

### Test 3.1 — Aggregation Without GROUP BY Trap
```
Prompt: "Show average defect rate and list all suppliers"
```
- **Must:** Not generate `SELECT supplier, AVG(defect_rate) FROM supply_chain` without GROUP BY
- **Must:** Either split into two components (KPI + table) or use proper GROUP BY

### Test 3.2 — Date Handling
```
Prompt: "Show monthly order trends for 2024"
```
- **Must:** Generate valid DuckDB date extraction (e.g., `EXTRACT(MONTH FROM CAST(order_date AS DATE))` or `strftime`)
- **Must:** Return 12 or fewer data points (one per month)
- **Must NOT:** Use MySQL/PostgreSQL-specific date functions that DuckDB doesn't support

### Test 3.3 — Calculated Fields
```
Prompt: "Show profit margin by product assuming 40% markup on unit cost"
```
- **Must:** Generate SQL with inline calculations (e.g., `unit_cost * 1.4 - unit_cost as margin`)
- **Must:** Return valid numeric results

### Test 3.4 — CASE WHEN Usage
```
Prompt: "Categorize suppliers as 'Good' if defect rate < 2%, 'Average' if 2-3%, 'Poor' if above 3%"
```
- **Must:** Generate valid CASE WHEN statement
- **Must:** Return a column with 'Good', 'Average', 'Poor' values

### Test 3.5 — Subquery / Window Function
```
Prompt: "Show each supplier's defect rate compared to the overall average"
```
- **Should:** Use a subquery or window function to compute global average alongside per-supplier rates
- **Must:** Return valid SQL that executes in DuckDB

### Test 3.6 — Column That Doesn't Exist
```
Prompt: "Show me revenue by customer"
```
- **Must NOT:** Generate SQL referencing `revenue` or `customer` columns (they don't exist)
- **Must:** Adapt — use `total_cost` for revenue proxy, `supplier` instead of customer
- **Must NOT:** Produce a DuckDB execution error

---

## CATEGORY 4: FILTER STRESS TESTS

These test the filter system under unusual conditions.

### Test 4.1 — Many Filters
```
Prompt: "Show cost breakdown with filters for region, supplier, category, shipping mode, and date range"
```
- **Must:** Return 5 filters matching the requested dimensions
- **Must:** Each filter has correct column mapping and type

### Test 4.2 — Filter on Non-Categorical Column
```
Prompt: "Let me filter by defect rate range"
```
- **Must:** Return a numeric_range filter on defect_rate
- **Must NOT:** Return a multiselect with 500 individual defect rate values

### Test 4.3 — Filter Application
After getting an app_definition with a region filter, execute:
```python
result = run_pipeline(
    "Show costs by supplier",
    filters={"region_filter": ["North America"]}
)
```
- **Must:** All component results contain only North America data
- **Must:** Row counts be less than unfiltered results

### Test 4.4 — Empty Filter
```python
result = run_pipeline(
    "Show costs by supplier",
    filters={"region_filter": ["Antarctica"]}
)
```
- **Must NOT:** Crash
- **Must:** Return empty DataFrames or handle gracefully
- **Validation:** Should flag "Query returned no data" warnings

---

## CATEGORY 5: CONVERSATIONAL REFINEMENT

These test the incremental compilation mode.

### Test 5.1 — Add a Component
```python
# Step 1: Build initial app
result1 = run_pipeline("Show defect rates by supplier")
app1 = result1["app_definition"]

# Step 2: Refine
result2 = run_pipeline(
    "Also add a line chart showing delivery days trend over time",
    existing_app=app1
)
app2 = result2["app_definition"]
```
- **Must:** app2 contains all components from app1 PLUS a new line_chart
- **Must:** Original component IDs and SQL queries are preserved
- **Must NOT:** Rebuild the entire app from scratch

### Test 5.2 — Remove a Component
```python
result2 = run_pipeline(
    "Remove the table, I only want the charts",
    existing_app=app1
)
```
- **Must:** Return app without table components
- **Must:** Keep all chart components intact

### Test 5.3 — Modify Existing
```python
result2 = run_pipeline(
    "Change the bar chart to show percentages instead of raw numbers",
    existing_app=app1
)
```
- **Must:** Same component structure but with modified SQL or config
- **Must:** format field should be "percentage"

### Test 5.4 — Complete Pivot
```python
result2 = run_pipeline(
    "Actually, forget all that. Show me shipping analysis instead",
    existing_app=app1
)
```
- **Must:** Return a completely new app focused on shipping
- **Must:** Not contain any supplier/defect components from app1

### Test 5.5 — Three-Round Conversation
```python
r1 = run_pipeline("Show supplier overview")
r2 = run_pipeline("Add a cost breakdown pie chart", existing_app=r1["app_definition"])
r3 = run_pipeline("Now add filters for region and category", existing_app=r2["app_definition"])
```
- **Must:** r3 contains components from r1 + r2 + new filters
- **Must:** Each round builds on the previous, not replaces it

---

## CATEGORY 6: GOVERNANCE EDGE CASES

### Test 6.1 — PII in Prompt
```
Prompt: "Show orders for john@acme.com"
```
- **Must:** Governance flags PII (email detected in query or prompt)
- **Must:** `governance.passed` should be `false`

### Test 6.2 — Viewer Role Restrictions
```python
result = run_pipeline(
    "Show all supplier data",
    role="viewer"
)
```
- **Must:** `governance.access_granted` should be `false` (viewers can't create_app)
- **Must:** Warning generated about role permissions

### Test 6.3 — Large Result Set
```python
result = run_pipeline("Show every single order with all columns")
```
- **Must:** If result exceeds viewer row limit (10k), export_allowed should be false for viewer role
- **Validation:** Should warn about result size

### Test 6.4 — SQL Injection Attempt
```
Prompt: "Show suppliers; DROP TABLE supply_chain; --"
```
- **Must NOT:** Execute destructive SQL
- **Must:** Either ignore the injection or produce a normal dashboard about suppliers
- **Must:** Governance should flag complexity if SQL looks suspicious

---

## CATEGORY 7: TEMPLATE COVERAGE

Test all 6 built-in templates to make sure GPT-5.1 produces quality output for each.

### Test 7.1-7.6 — Run Each Template
```python
templates = [
    "Analyze supplier defect rates and delivery performance",                    # supplier_performance
    "Compare regional supply chain metrics with cost breakdown",                 # regional_analysis
    "Display product margins, unit costs, and order volumes by category",        # product_profitability
    "Compare shipping modes by cost, delivery time, and on-time performance",    # shipping_optimization
    "Show inventory turnover, warehouse costs, and stock levels by category",    # inventory_health
    "Display defect rates by supplier and product with trend analysis",          # quality_assurance
]
```
For each:
- **Must:** Return 3+ components
- **Must:** All SQL queries execute without errors
- **Must:** Validation passes with 0 or minimal warnings
- **Must:** Component types match what the template suggests (e.g., shipping_optimization should have bar_chart for costs)

---

## CATEGORY 8: PERFORMANCE & RELIABILITY

### Test 8.1 — Rapid Fire (5 sequential calls)
```python
prompts = [
    "Show defect rates",
    "Compare regions",
    "Shipping cost analysis",
    "Top 5 suppliers by volume",
    "Monthly delivery trend"
]
for p in prompts:
    result = run_pipeline(p)
    assert result["validation"]["overall_status"] in ["success", "warning"]
```
- **Must:** All 5 complete without errors
- **Must:** Total time < 60 seconds (12s per call average)

### Test 8.2 — Identical Prompt Consistency
```python
results = [run_pipeline("Show defect rates by supplier") for _ in range(3)]
```
- **Must:** All 3 produce valid app_definitions
- **Should:** Component types be consistent across runs (same prompt = similar structure)
- **Acceptable:** Minor SQL variations (different ORDER BY, aliases, etc.)

---

## SCORING

Run all tests and log results:

```
CATEGORY 1 (Vague):           _/5
CATEGORY 2 (Complex):         _/4
CATEGORY 3 (SQL Edge Cases):  _/6
CATEGORY 4 (Filters):         _/4
CATEGORY 5 (Refinement):      _/5
CATEGORY 6 (Governance):      _/4
CATEGORY 7 (Templates):       _/6
CATEGORY 8 (Performance):     _/2

TOTAL:                         _/36
```

**Target: 30/36 or higher before integration with Person 2.**

Any test that fails → fix the engine (usually means tweaking the system prompt, adding validation, or handling edge cases in executor.py) → re-run until it passes.

---

## CLAUDE CODE PROMPT

```
Read ENGINE-STRESS-TEST.md. This is your stress test suite.

For each test, call run_pipeline() with the specified prompt and parameters.
Check every "Must" and "Must NOT" condition.
Log PASS or FAIL with a brief reason.

If a test FAILS:
1. Diagnose the root cause
2. Fix the relevant engine file (usually intent_parser.py system prompt or executor.py)
3. Re-run ALL tests to make sure the fix didn't break anything

After all tests pass, run `pytest tests/ -v` to confirm the original 55 tests still pass.

Print the final scorecard.
```
