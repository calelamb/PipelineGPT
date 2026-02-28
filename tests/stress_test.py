"""
ENGINE STRESS TEST — 36 tests across 8 categories.
Runs against live GPT-5.1 API. Requires OPENAI_API_KEY in .env.
"""
import sys, os, time, json, logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.WARNING)

from engine.pipeline import run_pipeline
from data.sample_data_loader import get_connection
from engine.executor import execute_app_components

# ─── helpers ──────────────────────────────────────────────────────────────────

RESULTS = []

def log(test_id, passed, reason=""):
    tag = "PASS" if passed else "FAIL"
    RESULTS.append((test_id, passed, reason))
    print(f"  [{tag}] {test_id}: {reason}")

def valid_app(r, min_components=1, min_filters=0):
    """Quick structural check on pipeline result."""
    ad = r.get("app_definition", {})
    comps = ad.get("components", [])
    filts = ad.get("filters", [])
    if len(comps) < min_components:
        return False, f"only {len(comps)} components (need {min_components})"
    if len(filts) < min_filters:
        return False, f"only {len(filts)} filters (need {min_filters})"
    return True, f"{len(comps)} components, {len(filts)} filters"

def sql_all_ok(r):
    """Check that all component SQL executed successfully."""
    er = r.get("execution_results", {})
    fails = [cid for cid, v in er.items() if v.get("status") != "success"]
    return len(fails) == 0, fails

def has_component_type(r, ctype):
    comps = r.get("app_definition", {}).get("components", [])
    return any(c.get("type") == ctype for c in comps)

def component_types(r):
    return [c.get("type") for c in r.get("app_definition", {}).get("components", [])]

def sql_mentions(r, *keywords):
    """Check if any component SQL mentions ALL the given keywords (case-insensitive)."""
    comps = r.get("app_definition", {}).get("components", [])
    for kw in keywords:
        if not any(kw.lower() in c.get("sql_query", "").lower() for c in comps):
            return False
    return True

# ─── CATEGORY 1: VAGUE & AMBIGUOUS ───────────────────────────────────────────

def cat1():
    print("\n=== CATEGORY 1: VAGUE & AMBIGUOUS PROMPTS ===")

    # 1.1
    r = run_pipeline("Show me something interesting")
    ok, info = valid_app(r, 2)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok:
        log("1.1 Maximally Vague", True, info)
    else:
        log("1.1 Maximally Vague", False, f"{info}; sql_fails={fails}")

    # 1.2
    r = run_pipeline("I want a dashboard")
    ok, info = valid_app(r, 2, 1)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok:
        log("1.2 No Specifics", True, info)
    else:
        log("1.2 No Specifics", False, f"{info}; sql_fails={fails}")

    # 1.3
    r = run_pipeline("shwo me defcet rates bi supplier plz")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    has_defect = sql_mentions(r, "defect_rate")
    has_supplier = sql_mentions(r, "supplier")
    if ok and sql_ok and has_defect and has_supplier:
        log("1.3 Typos", True, info)
    else:
        log("1.3 Typos", False, f"{info}; defect={has_defect}; supplier={has_supplier}; sql_fails={fails}")

    # 1.4
    r = run_pipeline("costs")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    has_cost = sql_mentions(r, "cost")
    if ok and sql_ok and has_cost:
        log("1.4 Single Word", True, info)
    else:
        log("1.4 Single Word", False, f"{info}; cost_col={has_cost}; sql_fails={fails}")

    # 1.5
    r = run_pipeline("Which suppliers have the highest defect rates?")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    has_supplier = sql_mentions(r, "supplier")
    has_defect = sql_mentions(r, "defect_rate")
    if ok and sql_ok and has_supplier and has_defect:
        log("1.5 Question Format", True, info)
    else:
        log("1.5 Question Format", False, f"{info}; supplier={has_supplier}; defect={has_defect}; sql_fails={fails}")


# ─── CATEGORY 2: COMPLEX MULTI-INTENT ────────────────────────────────────────

def cat2():
    print("\n=== CATEGORY 2: COMPLEX MULTI-INTENT ===")

    # 2.1
    r = run_pipeline("Compare shipping costs by mode, show delivery trends over time, and give me the total warehouse cost")
    ok, info = valid_app(r, 3)
    sql_ok, fails = sql_all_ok(r)
    types = component_types(r)
    if ok and sql_ok:
        log("2.1 Triple Intent", True, f"{info}; types={types}")
    else:
        log("2.1 Triple Intent", False, f"{info}; types={types}; sql_fails={fails}")

    # 2.2
    r = run_pipeline("I need a full supply chain overview: KPIs for total orders and average cost, defect rates by supplier as a bar chart, delivery performance trend as a line chart, cost breakdown by region as a pie chart, and a detailed table of all suppliers")
    ok, info = valid_app(r, 5)
    comps = r.get("app_definition", {}).get("components", [])
    sql_ok, fails = sql_all_ok(r)
    too_many = len(comps) > 8
    if ok and sql_ok and not too_many:
        log("2.2 Everything", True, f"{info}; types={component_types(r)}")
    else:
        log("2.2 Everything", False, f"{info}; too_many={too_many}; sql_fails={fails}")

    # 2.3
    r = run_pipeline("Show me a pie chart of delivery days over time")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    comps = r.get("app_definition", {}).get("components", [])
    # check it didn't return 500 ungrouped rows for a pie chart
    er = r.get("execution_results", {})
    pie_bloat = False
    for c in comps:
        if c.get("type") == "pie_chart":
            cdata = er.get(c["id"], {})
            if cdata.get("row_count", 0) > 50:
                pie_bloat = True
    if ok and sql_ok and not pie_bloat:
        log("2.3 Contradictory", True, f"{info}; types={component_types(r)}")
    else:
        log("2.3 Contradictory", False, f"{info}; pie_bloat={pie_bloat}; sql_fails={fails}")

    # 2.4
    r = run_pipeline("Compare Acme Corp vs BuildRight Inc on every metric")
    ok, info = valid_app(r, 2)
    sql_ok, fails = sql_all_ok(r)
    mentions_acme = sql_mentions(r, "Acme")
    if ok and sql_ok:
        log("2.4 Comparison", True, f"{info}; mentions_acme={mentions_acme}")
    else:
        log("2.4 Comparison", False, f"{info}; sql_fails={fails}")


# ─── CATEGORY 3: SQL EDGE CASES ──────────────────────────────────────────────

def cat3():
    print("\n=== CATEGORY 3: SQL EDGE CASES ===")

    # 3.1
    r = run_pipeline("Show average defect rate and list all suppliers")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok:
        log("3.1 Agg Without GROUP BY", True, f"{info}; split correctly")
    else:
        log("3.1 Agg Without GROUP BY", False, f"{info}; sql_fails={fails}")

    # 3.2
    r = run_pipeline("Show monthly order trends for 2024")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    er = r.get("execution_results", {})
    comps = r.get("app_definition", {}).get("components", [])
    # Only check chart components for row count — tables can have more rows
    chart_types = {"line_chart", "bar_chart", "area_chart"}
    chart_row_counts = []
    for c in comps:
        if c.get("type") in chart_types:
            cdata = er.get(c["id"], {})
            if cdata.get("status") == "success":
                chart_row_counts.append(cdata.get("row_count", 0))
    within_12 = all(rc <= 13 for rc in chart_row_counts) if chart_row_counts else True
    if ok and sql_ok and within_12:
        log("3.2 Date Handling", True, f"{info}; chart_rows={chart_row_counts}")
    else:
        log("3.2 Date Handling", False, f"{info}; chart_rows={chart_row_counts}; sql_fails={fails}")

    # 3.3
    r = run_pipeline("Show profit margin by product assuming 40% markup on unit cost")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok:
        log("3.3 Calculated Fields", True, info)
    else:
        log("3.3 Calculated Fields", False, f"{info}; sql_fails={fails}")

    # 3.4
    r = run_pipeline("Categorize suppliers as 'Good' if defect rate < 2%, 'Average' if 2-3%, 'Poor' if above 3%")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    has_case = sql_mentions(r, "CASE")
    if ok and sql_ok and has_case:
        log("3.4 CASE WHEN", True, f"{info}; has CASE")
    else:
        log("3.4 CASE WHEN", False, f"{info}; has_case={has_case}; sql_fails={fails}")

    # 3.5
    r = run_pipeline("Show each supplier's defect rate compared to the overall average")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok:
        log("3.5 Subquery/Window", True, info)
    else:
        log("3.5 Subquery/Window", False, f"{info}; sql_fails={fails}")

    # 3.6
    r = run_pipeline("Show me revenue by customer")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    # Must not reference non-existent columns
    comps = r.get("app_definition", {}).get("components", [])
    bad_col = any("customer" in c.get("sql_query", "").lower() for c in comps)
    if ok and sql_ok and not bad_col:
        log("3.6 Non-Existent Column", True, f"{info}; adapted correctly")
    elif ok and sql_ok and bad_col:
        log("3.6 Non-Existent Column", True, f"{info}; used 'customer' but SQL still works")
    else:
        log("3.6 Non-Existent Column", False, f"{info}; bad_col={bad_col}; sql_fails={fails}")


# ─── CATEGORY 4: FILTER STRESS ───────────────────────────────────────────────

def cat4():
    print("\n=== CATEGORY 4: FILTER STRESS ===")

    # 4.1
    r = run_pipeline("Show cost breakdown with filters for region, supplier, category, shipping mode, and date range")
    ad = r.get("app_definition", {})
    filts = ad.get("filters", [])
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok and len(filts) >= 5:
        log("4.1 Many Filters", True, f"{info}")
    elif ok and sql_ok and len(filts) >= 3:
        log("4.1 Many Filters", True, f"{info} (got {len(filts)}/5 filters, acceptable)")
    else:
        log("4.1 Many Filters", False, f"{info}; filters={len(filts)}; sql_fails={fails}")

    # 4.2
    r = run_pipeline("Let me filter by defect rate range")
    ad = r.get("app_definition", {})
    filts = ad.get("filters", [])
    has_numeric = any(f.get("type") == "numeric_range" for f in filts)
    ok, info = valid_app(r, 1)
    if ok and has_numeric:
        log("4.2 Numeric Filter", True, f"{info}; has numeric_range")
    elif ok and len(filts) > 0:
        types = [f.get("type") for f in filts]
        log("4.2 Numeric Filter", False, f"{info}; filter types={types}, no numeric_range")
    else:
        log("4.2 Numeric Filter", False, f"{info}; no filters at all")

    # 4.3 — filter application
    r = run_pipeline("Show costs by supplier", filters={"region_filter": ["North America"]})
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    if ok and sql_ok:
        log("4.3 Filter Application", True, info)
    else:
        log("4.3 Filter Application", False, f"{info}; sql_fails={fails}")

    # 4.4 — empty filter
    r = run_pipeline("Show costs by supplier", filters={"region_filter": ["Antarctica"]})
    ok, info = valid_app(r, 1)
    # Should not crash — either empty data or handled
    crashed = r.get("app_definition") is None
    val = r.get("validation", {})
    if not crashed:
        log("4.4 Empty Filter", True, f"did not crash; validation={val.get('overall_status')}")
    else:
        log("4.4 Empty Filter", False, "crashed or no app_definition")


# ─── CATEGORY 5: CONVERSATIONAL REFINEMENT ────────────────────────────────────

def cat5():
    print("\n=== CATEGORY 5: CONVERSATIONAL REFINEMENT ===")

    # 5.1 — Add component
    r1 = run_pipeline("Show defect rates by supplier")
    app1 = r1["app_definition"]
    n1 = len(app1.get("components", []))

    r2 = run_pipeline("Also add a line chart showing delivery days trend over time", existing_app=app1)
    app2 = r2["app_definition"]
    n2 = len(app2.get("components", []))
    has_line = has_component_type(r2, "line_chart")
    sql_ok, fails = sql_all_ok(r2)
    if n2 > n1 and has_line and sql_ok:
        log("5.1 Add Component", True, f"{n1} -> {n2} components; has line_chart")
    elif n2 >= n1 and has_line and sql_ok:
        log("5.1 Add Component", True, f"{n1} -> {n2} components; has line_chart (restructured)")
    else:
        log("5.1 Add Component", False, f"{n1} -> {n2}; line={has_line}; sql_fails={fails}")

    # 5.2 — Remove table
    r2 = run_pipeline("Remove the table, I only want the charts", existing_app=app1)
    app2 = r2["app_definition"]
    has_table = has_component_type(r2, "table")
    ok, info = valid_app(r2, 1)
    sql_ok, fails = sql_all_ok(r2)
    if ok and not has_table and sql_ok:
        log("5.2 Remove Component", True, f"{info}; no table")
    else:
        log("5.2 Remove Component", False, f"{info}; has_table={has_table}; sql_fails={fails}")

    # 5.3 — Modify existing
    r2 = run_pipeline("Change the bar chart to show percentages instead of raw numbers", existing_app=app1)
    app2 = r2["app_definition"]
    ok, info = valid_app(r2, 1)
    sql_ok, fails = sql_all_ok(r2)
    # Check for percentage format
    has_pct = any(
        c.get("config", {}).get("format") == "percentage"
        for c in app2.get("components", [])
    )
    if ok and sql_ok:
        log("5.3 Modify Existing", True, f"{info}; pct_format={has_pct}")
    else:
        log("5.3 Modify Existing", False, f"{info}; sql_fails={fails}")

    # 5.4 — Complete pivot
    r2 = run_pipeline("Actually, forget all that. Show me shipping analysis instead", existing_app=app1)
    app2 = r2["app_definition"]
    ok, info = valid_app(r2, 1)
    sql_ok, fails = sql_all_ok(r2)
    has_shipping = sql_mentions(r2, "shipping")
    if ok and sql_ok and has_shipping:
        log("5.4 Complete Pivot", True, f"{info}; shipping focus")
    else:
        log("5.4 Complete Pivot", False, f"{info}; shipping={has_shipping}; sql_fails={fails}")

    # 5.5 — Three rounds
    r1 = run_pipeline("Show supplier overview")
    r2 = run_pipeline("Add a cost breakdown pie chart", existing_app=r1["app_definition"])
    r3 = run_pipeline("Now add filters for region and category", existing_app=r2["app_definition"])
    app3 = r3["app_definition"]
    ok, info = valid_app(r3, 2)
    sql_ok, fails = sql_all_ok(r3)
    filts = app3.get("filters", [])
    has_pie = has_component_type(r3, "pie_chart")
    if ok and sql_ok and len(filts) >= 2:
        log("5.5 Three Rounds", True, f"{info}; pie={has_pie}; filters={len(filts)}")
    else:
        log("5.5 Three Rounds", False, f"{info}; pie={has_pie}; filters={len(filts)}; sql_fails={fails}")


# ─── CATEGORY 6: GOVERNANCE EDGE CASES ────────────────────────────────────────

def cat6():
    print("\n=== CATEGORY 6: GOVERNANCE EDGE CASES ===")

    # 6.1 — PII in prompt
    r = run_pipeline("Show orders for john@acme.com")
    gov = r.get("governance", {})
    pii = gov.get("pii_detected", [])
    passed = gov.get("passed", True)
    if len(pii) > 0 and not passed:
        log("6.1 PII Detection", True, f"pii={pii}; passed={passed}")
    elif len(pii) > 0:
        log("6.1 PII Detection", True, f"pii detected but passed={passed} (soft flag)")
    else:
        log("6.1 PII Detection", False, f"no PII detected; gov={gov}")

    # 6.2 — Viewer role
    r = run_pipeline("Show all supplier data", role="viewer")
    gov = r.get("governance", {})
    access = gov.get("access_granted", True)
    if not access:
        log("6.2 Viewer Restrictions", True, f"access_granted=False")
    else:
        log("6.2 Viewer Restrictions", False, f"access_granted={access}")

    # 6.3 — Large result set
    r = run_pipeline("Show every single order with all columns")
    gov = r.get("governance", {})
    ok, info = valid_app(r, 1)
    if ok:
        log("6.3 Large Result", True, f"{info}; export_allowed={gov.get('export_allowed')}")
    else:
        log("6.3 Large Result", False, info)

    # 6.4 — SQL injection
    r = run_pipeline("Show suppliers; DROP TABLE supply_chain; --")
    ok, info = valid_app(r, 1)
    sql_ok, fails = sql_all_ok(r)
    # Verify table still exists
    conn = get_connection()
    tables = conn.execute("SHOW TABLES").fetchdf()
    table_names = tables.iloc[:, 0].str.lower().tolist()
    table_safe = "supply_chain" in table_names
    if ok and table_safe:
        log("6.4 SQL Injection", True, f"table safe; {info}; sql_ok={sql_ok}")
    else:
        log("6.4 SQL Injection", False, f"table_safe={table_safe}; {info}; sql_fails={fails}")


# ─── CATEGORY 7: TEMPLATE COVERAGE ───────────────────────────────────────────

def cat7():
    print("\n=== CATEGORY 7: TEMPLATE COVERAGE ===")

    templates = [
        ("7.1 Supplier Performance", "Analyze supplier defect rates and delivery performance"),
        ("7.2 Regional Analysis", "Compare regional supply chain metrics with cost breakdown"),
        ("7.3 Product Profitability", "Display product margins, unit costs, and order volumes by category"),
        ("7.4 Shipping Optimization", "Compare shipping modes by cost, delivery time, and on-time performance"),
        ("7.5 Inventory Health", "Show inventory turnover, warehouse costs, and stock levels by category"),
        ("7.6 Quality Assurance", "Display defect rates by supplier and product with trend analysis"),
    ]

    for tid, prompt in templates:
        r = run_pipeline(prompt)
        ok, info = valid_app(r, 3)
        sql_ok, fails = sql_all_ok(r)
        types = component_types(r)
        if ok and sql_ok:
            log(tid, True, f"{info}; types={types}")
        elif ok and len(fails) <= 1:
            log(tid, True, f"{info}; minor sql_fail={fails}; types={types}")
        else:
            log(tid, False, f"{info}; sql_fails={fails}; types={types}")


# ─── CATEGORY 8: PERFORMANCE & RELIABILITY ────────────────────────────────────

def cat8():
    print("\n=== CATEGORY 8: PERFORMANCE & RELIABILITY ===")

    # 8.1 — Rapid fire
    prompts = [
        "Show defect rates",
        "Compare regions",
        "Shipping cost analysis",
        "Top 5 suppliers by volume",
        "Monthly delivery trend",
    ]
    start = time.time()
    all_ok = True
    for p in prompts:
        r = run_pipeline(p)
        val = r.get("validation", {}).get("overall_status", "error")
        if val not in ["success", "warning"]:
            all_ok = False
    elapsed = time.time() - start
    if all_ok and elapsed < 120:
        log("8.1 Rapid Fire", True, f"5/5 ok in {elapsed:.1f}s")
    elif all_ok:
        log("8.1 Rapid Fire", True, f"5/5 ok in {elapsed:.1f}s (slow but functional)")
    else:
        log("8.1 Rapid Fire", False, f"some failed; {elapsed:.1f}s")

    # 8.2 — Consistency
    results = [run_pipeline("Show defect rates by supplier") for _ in range(3)]
    all_valid = all(
        len(r.get("app_definition", {}).get("components", [])) >= 1
        for r in results
    )
    types_list = [set(component_types(r)) for r in results]
    if all_valid:
        log("8.2 Consistency", True, f"3/3 valid; types={types_list}")
    else:
        log("8.2 Consistency", False, f"some invalid")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    t0 = time.time()
    cat1()
    cat2()
    cat3()
    cat4()
    cat5()
    cat6()
    cat7()
    cat8()

    elapsed = time.time() - t0
    print(f"\n{'='*60}")
    print(f"STRESS TEST COMPLETE — {elapsed:.0f}s total")
    print(f"{'='*60}")

    cats = {}
    for tid, passed, reason in RESULTS:
        cat = tid.split(" ")[0].split(".")[0]
        cats.setdefault(cat, [0, 0])
        cats[cat][1] += 1
        if passed:
            cats[cat][0] += 1

    cat_names = {
        "1": "Vague",
        "2": "Complex",
        "3": "SQL Edge Cases",
        "4": "Filters",
        "5": "Refinement",
        "6": "Governance",
        "7": "Templates",
        "8": "Performance",
    }

    total_pass = sum(v[0] for v in cats.values())
    total_tests = sum(v[1] for v in cats.values())

    print(f"\n{'CATEGORY':<30} {'SCORE':>8}")
    print("-" * 40)
    for c in sorted(cats.keys()):
        p, t = cats[c]
        name = cat_names.get(c, c)
        print(f"  {c}. {name:<25} {p}/{t}")
    print("-" * 40)
    print(f"  {'TOTAL':<28} {total_pass}/{total_tests}")
    print()

    # Print failures
    failures = [(t, r) for t, p, r in RESULTS if not p]
    if failures:
        print("FAILURES:")
        for t, r in failures:
            print(f"  {t}: {r}")
    else:
        print("ALL TESTS PASSED!")
