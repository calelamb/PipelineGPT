import streamlit as st
import pandas as pd
import plotly.express as px
import json
from pathlib import Path
from datetime import datetime

from ui.styles import inject_custom_css, LUCIDE

# ─── Auth constants ───
PASSWORDS = {"admin": "admin123", "analyst": "analyst", "viewer": "viewer"}
ROLE_DISPLAY = {"admin": "Administrator", "analyst": "Data Analyst", "viewer": "Viewer"}
ROLE_DESC = {
    "admin": "Full access. View all data, export, manage apps.",
    "analyst": "Analyze data, create apps, export CSV/JSON.",
    "viewer": "View public dashboards only.",
}

# ─── Session state defaults ───
DEFAULTS = {
    "logged_in": False,
    "user_role": None,
    "pipeline_result": None,
    "current_app": None,
    "active_filters": None,
    "messages": [],
    "show_engine": False,
    "current_page": "chat",
    "uploaded_tables": {},  # {table_name: {"rows": int, "columns": int, "file_name": str}}
}

# ─── Templates ───
TEMPLATES = [
    {
        "name": "Supplier Performance",
        "prompt": (
            "Create a supplier performance dashboard with KPIs for total orders, "
            "average defect rate, and on-time delivery percentage. Include a bar chart "
            "of defect rate by supplier, a line chart of delivery trends over time, "
            "a pie chart of orders by region, and a supplier details table. "
            "Add filters for region and category."
        ),
    },
    {
        "name": "Cost Analysis",
        "prompt": (
            "Create a cost analysis dashboard with KPIs for total cost, average unit "
            "cost, and total shipping cost. Include a bar chart of costs by region, "
            "a pie chart of cost distribution by category, and a detailed cost table. "
            "Add filters for region and shipping mode."
        ),
    },
    {
        "name": "Quality Control",
        "prompt": (
            "Build a quality control dashboard with KPIs for average defect rate and "
            "total defective orders. Include a bar chart of defect rates by supplier, "
            "a scatter plot of defect rate vs unit cost, and a line chart of defect "
            "trends over time. Add filters for region and supplier."
        ),
    },
    {
        "name": "Logistics Overview",
        "prompt": (
            "Create a logistics dashboard with KPIs for total shipping cost and "
            "average delivery days. Include a bar chart of shipping cost by shipping "
            "mode, a line chart of order volume over time, and a shipment details "
            "table. Add filters for region and shipping mode."
        ),
    },
    {
        "name": "Regional Analysis",
        "prompt": (
            "Show me a regional analysis dashboard with KPIs for total orders and "
            "average defect rate. Include a bar chart comparing regions by total cost, "
            "a pie chart of order distribution by region, and a table of regional "
            "metrics. Add filters for category and shipping mode."
        ),
    },
    {
        "name": "Executive Summary",
        "prompt": (
            "Build an executive KPI summary with total orders, total cost, average "
            "defect rate, and average shipping cost as KPI cards. Include a bar chart "
            "of costs by region and a line chart of monthly order trends. "
            "Add a region filter."
        ),
    },
]


# ============================================================================
# PIPELINE
# ============================================================================


def call_pipeline(user_prompt: str) -> dict:
    from engine.pipeline import run_pipeline
    return run_pipeline(
        user_message=user_prompt,
        existing_app=st.session_state.get("current_app"),
        filters=st.session_state.get("active_filters"),
        role=st.session_state.get("user_role", "analyst"),
    )


def _save_graph_output(result: dict, prompt: str) -> Path:
    """Persist a pipeline result to graphs/<timestamp>.json and return the path."""
    graphs_dir = Path("graphs")
    graphs_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    out_path = graphs_dir / f"output_{ts}.json"
    payload = {
        "saved_at": datetime.now().isoformat(),
        "prompt": prompt,
        "result": result,
    }
    with open(out_path, "w") as f:
        json.dump(payload, f, default=str, indent=2)
    return out_path


def process_prompt(prompt: str):
    """Run pipeline, store results, add to chat with inline result."""
    st.session_state.messages.append({
        "role": "user", "content": prompt,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })
    result = call_pipeline(prompt)
    st.session_state.pipeline_result = result
    st.session_state.current_app = result.get("app_definition")

    # Persist to graphs/ folder
    _save_graph_output(result, prompt)

    gov = result.get("governance", {})
    app_def = result.get("app_definition", {})
    exec_results = result.get("execution_results", {})

    if gov.get("passed", True):
        n = len(app_def.get("components", []))
        title = app_def.get("app_title", "dashboard")
        comps = app_def.get("components", [])
        comp_types = [c.get("type", "").replace("_", " ") for c in comps]
        type_summary = ", ".join(dict.fromkeys(comp_types))  # unique, ordered

        # Check if all components returned empty data
        empty_count = 0
        for comp in comps:
            cid = comp.get("id", "")
            comp_result = exec_results.get(cid, {})
            data = comp_result.get("data", []) if isinstance(comp_result, dict) else (comp_result if isinstance(comp_result, list) else [])
            if not data:
                empty_count += 1

        if empty_count == n and n > 0:
            # All components empty — give an intelligent message
            msg = (
                f"I built <strong>{title}</strong>, but all {n} queries returned empty results. "
                f"This usually means the filters or date range in your request don't match the "
                f"available data. Try rephrasing without specific time constraints, or check the "
                f"<strong>Your Data</strong> section to see what's loaded."
            )
        elif empty_count > 0:
            msg = (
                f"I've built <strong>{title}</strong> with {n} components — "
                f"including {type_summary}. "
                f"Note: {empty_count} component(s) returned no data — some filters may not "
                f"match the dataset. Expand below to explore."
            )
        else:
            msg = (
                f"I've built <strong>{title}</strong> with {n} components — "
                f"including {type_summary}. "
                f"Expand the dashboard below to explore the data interactively."
            )
    else:
        msg = "Governance blocked this request. See the details below for more information."

    st.session_state.messages.append({
        "role": "assistant", "content": msg,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "pipeline_result": result,
        "stream": True,  # flag for streaming animation
    })


# ============================================================================
# PLOTLY CONFIG
# ============================================================================

PLOTLY_DEFAULTS = dict(
    template="simple_white",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#6b7280", family="DM Sans, -apple-system, sans-serif"),
    title_font=dict(color="#111111", size=14),
    height=380,
    margin=dict(l=40, r=20, t=50, b=40),
)
PLOTLY_GRID = dict(gridcolor="#e5e7eb")
ACCENT_COLORS = ["#3b82f6", "#8b5cf6", "#06b6d4", "#f59e0b", "#10b981", "#ef4444", "#ec4899", "#6366f1"]


# ============================================================================
# DATA HELPER
# ============================================================================


def _get_data(comp_result):
    if isinstance(comp_result, dict):
        return comp_result.get("data", [])
    elif isinstance(comp_result, list):
        return comp_result
    return []


# ============================================================================
# RENDERERS
# ============================================================================


def _clean_label(col_name: str) -> str:
    """Turn 'total_shipping_cost' into 'Total Shipping Cost'."""
    if not col_name:
        return col_name
    return col_name.replace("_", " ").strip().title()


def _format_kpi_value(val, fmt):
    """Format a KPI value, handling None/NaN gracefully."""
    import math
    if val is None:
        return "—"
    try:
        val = float(val)
        if math.isnan(val) or math.isinf(val):
            return "—"
    except (TypeError, ValueError):
        return str(val)
    if fmt == "percentage":
        return f"{val:.1f}%"
    elif fmt == "currency":
        if abs(val) >= 1_000_000:
            return f"${val/1_000_000:,.1f}M"
        elif abs(val) >= 1_000:
            return f"${val/1_000:,.1f}K"
        return f"${val:,.2f}"
    else:
        if abs(val) >= 1_000_000:
            return f"{val/1_000_000:,.1f}M"
        elif abs(val) >= 10_000:
            return f"{val/1_000:,.1f}K"
        return f"{val:,.2f}"


def render_kpi(component, data, chart_key=None):
    cfg = component.get("config", {})
    value_col = cfg.get("value_column", "")
    label = cfg.get("metric_name", component.get("title", "KPI"))
    fmt = cfg.get("format", "")
    if data:
        row = data[0]
        val = row.get(value_col) if value_col and value_col in row else list(row.values())[0]
        display = _format_kpi_value(val, fmt)
    else:
        display = "—"
    st.metric(label=label, value=display)


def _render_empty_state(component):
    """Show a styled empty-state message when a chart has no data."""
    title = component.get("title", "Chart")
    st.markdown(
        f'<div style="text-align:center;padding:40px 16px;color:#9ca3af;font-size:13px">'
        f'<p style="font-weight:600;color:#6b7280;margin-bottom:4px">{title}</p>'
        f'No data returned — the query filters may not match the dataset.'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_bar_chart(component, data, chart_key=None):
    cfg = component.get("config", {})
    df = pd.DataFrame(data)
    if df.empty:
        _render_empty_state(component)
        return
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = None
    for c in df.columns:
        if c != x and c != y and df[c].dtype == "object":
            color_col = c
            break
    _labels = {x: _clean_label(x), y: _clean_label(y)}
    if color_col:
        _labels[color_col] = _clean_label(color_col)
    fig = px.bar(df, x=x, y=y, color=color_col, title=component.get("title", ""),
                 barmode="group", color_discrete_sequence=ACCENT_COLORS, labels=_labels)
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True, key=chart_key)


def render_table(component, data, chart_key=None):
    df = pd.DataFrame(data)
    if df.empty:
        _render_empty_state(component)
        return
    cfg = component.get("config", {})
    sort_col = cfg.get("sort_column")
    if sort_col and sort_col in df.columns:
        df = df.sort_values(sort_col, ascending=(cfg.get("sort_order", "asc") == "asc"))
    # Clean column headers
    df.columns = [_clean_label(c) for c in df.columns]
    st.markdown(
        f"<p style='font-weight:600;color:#111111;margin-bottom:4px;font-size:14px'>"
        f"{component.get('title', 'Table')}</p>",
        unsafe_allow_html=True,
    )
    st.dataframe(df, use_container_width=True, height=380, key=chart_key)


def render_line_chart(component, data, chart_key=None):
    df = pd.DataFrame(data)
    if df.empty:
        _render_empty_state(component)
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.line(df, x=x, y=y, title=component.get("title", ""), markers=True,
                  color_discrete_sequence=ACCENT_COLORS,
                  labels={x: _clean_label(x), y: _clean_label(y)})
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True, key=chart_key)


def render_pie_chart(component, data, chart_key=None):
    df = pd.DataFrame(data)
    if df.empty:
        _render_empty_state(component)
        return
    cfg = component.get("config", {})
    names = cfg.get("names", cfg.get("x_axis", df.columns[0]))
    values = cfg.get("values", cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0]))
    fig = px.pie(df, names=names, values=values, title=component.get("title", ""),
                 color_discrete_sequence=ACCENT_COLORS,
                 labels={names: _clean_label(names), values: _clean_label(values)})
    fig.update_layout(**PLOTLY_DEFAULTS)
    fig.update_traces(marker=dict(line=dict(color="#ffffff", width=2)))
    st.plotly_chart(fig, use_container_width=True, key=chart_key)


def render_scatter(component, data, chart_key=None):
    df = pd.DataFrame(data)
    if df.empty:
        _render_empty_state(component)
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.scatter(df, x=x, y=y, title=component.get("title", ""),
                     color_discrete_sequence=ACCENT_COLORS,
                     labels={x: _clean_label(x), y: _clean_label(y)})
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True, key=chart_key)


def render_area_chart(component, data, chart_key=None):
    df = pd.DataFrame(data)
    if df.empty:
        _render_empty_state(component)
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.area(df, x=x, y=y, title=component.get("title", ""),
                  color_discrete_sequence=ACCENT_COLORS,
                  labels={x: _clean_label(x), y: _clean_label(y)})
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True, key=chart_key)


def render_metric_highlight(component, data, chart_key=None):
    cfg = component.get("config", {})
    label = cfg.get("metric_name", component.get("title", "Metric"))
    fmt = cfg.get("format", "")
    if data:
        row = data[0]
        value_col = cfg.get("value_column", "")
        val = row.get(value_col) if value_col and value_col in row else list(row.values())[0]
        display = _format_kpi_value(val, fmt)
    else:
        display = "—"
    st.metric(label=label, value=display)


RENDERERS = {
    "kpi_card": render_kpi,
    "bar_chart": render_bar_chart,
    "table": render_table,
    "line_chart": render_line_chart,
    "pie_chart": render_pie_chart,
    "scatter_plot": render_scatter,
    "area_chart": render_area_chart,
    "metric_highlight": render_metric_highlight,
}


# ============================================================================
# GOVERNANCE DISPLAY HELPERS
# ============================================================================


def _indicator(passed: bool) -> str:
    """Return a colored dot HTML span."""
    cls = "ind-pass" if passed else "ind-fail"
    return f'<span class="{cls}">&#x25CF;</span>'


def _render_gov_checks(gov: dict):
    """Render governance check rows using HTML (no emojis)."""
    gcols = st.columns(3)
    sql_safety = gov.get("sql_safety", {})
    col_access = gov.get("column_access", {})
    comp_perms = gov.get("component_permissions", {})
    with gcols[0]:
        safe = sql_safety.get("safe", True)
        st.markdown(
            f'<p class="check-row">{_indicator(safe)} <strong>SQL Safety</strong></p>',
            unsafe_allow_html=True,
        )
    with gcols[1]:
        allowed = col_access.get("allowed", True)
        st.markdown(
            f'<p class="check-row">{_indicator(allowed)} <strong>Column Access</strong></p>',
            unsafe_allow_html=True,
        )
        blocked_cols = col_access.get("blocked_columns", [])
        if blocked_cols:
            st.markdown(
                f'<p class="check-row" style="font-size:11px">Blocked: {", ".join(blocked_cols)}</p>',
                unsafe_allow_html=True,
            )
    with gcols[2]:
        comp_ok = comp_perms.get("allowed", True)
        st.markdown(
            f'<p class="check-row">{_indicator(comp_ok)} <strong>Component Perms</strong></p>',
            unsafe_allow_html=True,
        )
    for check in gov.get("checks", []):
        is_pass = check.get("passed", check.get("status") == "pass")
        name = check.get("name", "?")
        detail = check.get("message", check.get("details", ""))
        st.markdown(
            f'<p class="check-row">{_indicator(is_pass)} <strong>{name}</strong>: {detail}</p>',
            unsafe_allow_html=True,
        )


# ============================================================================
# ENGINE PANEL
# ============================================================================


def _render_engine_panel(result):
    """Tabbed engine panel below dashboard."""
    app_def = result.get("app_definition", {})
    exec_results = result.get("execution_results", {})
    gov = result.get("governance", {})
    validation = result.get("validation", {})

    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(
        "<h4 style='margin-bottom:4px;font-size:16px;font-weight:600'>Engine View</h4>",
        unsafe_allow_html=True,
    )

    # Pipeline stepper
    st.markdown("""
    <div class="stepper">
        <span class="step done"><span class="step-dot"></span> Parse</span>
        <span class="step-line"></span>
        <span class="step done"><span class="step-dot"></span> Execute</span>
        <span class="step-line"></span>
        <span class="step done"><span class="step-dot"></span> Validate</span>
        <span class="step-line"></span>
        <span class="step done"><span class="step-dot"></span> Govern</span>
    </div>
    """, unsafe_allow_html=True)

    tab_sql, tab_data, tab_gov, tab_audit = st.tabs(["SQL", "Data", "Governance", "Audit"])

    with tab_sql:
        for comp in app_def.get("components", []):
            title = comp.get("title", comp.get("id", ""))
            ctype = comp.get("type", "?")
            st.markdown(f"**{title}** &nbsp; `{ctype}`")
            st.code(comp.get("sql_query", "-- No SQL"), language="sql")

    with tab_data:
        for comp in app_def.get("components", []):
            cid = comp.get("id", "")
            title = comp.get("title", cid)
            comp_result = exec_results.get(cid, {})
            data = _get_data(comp_result)
            st.markdown(f"**{title}**")
            if data:
                st.dataframe(pd.DataFrame(data).head(20), use_container_width=True)
                if isinstance(comp_result, dict):
                    st.markdown(
                        f'<p class="check-row" style="font-size:11px">'
                        f'Rows: {comp_result.get("row_count", len(data))}</p>',
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    '<p class="check-row" style="font-size:11px">No data returned</p>',
                    unsafe_allow_html=True,
                )
            for vc in validation.get("components", []):
                if vc.get("id") == cid:
                    ok = vc.get("status") == "success"
                    st.markdown(
                        f'<p class="check-row">{_indicator(ok)} '
                        f'{vc.get("explanation", vc.get("status", "?"))}</p>',
                        unsafe_allow_html=True,
                    )

    with tab_gov:
        _render_gov_checks(gov)
        with st.expander("Full Governance JSON"):
            st.json(gov)

    with tab_audit:
        audit_id = gov.get("audit_entry_id", "N/A")
        st.markdown(f"**Audit Entry ID:** `{audit_id}`")
        st.markdown(f"**Role:** {gov.get('role', '?')} ({gov.get('role_display_name', '?')})")
        passed = gov.get("passed", True)
        st.markdown(
            f'<p class="check-row">{_indicator(passed)} '
            f'<strong>{"Passed" if passed else "Blocked"}</strong></p>',
            unsafe_allow_html=True,
        )
        pii = gov.get("pii_detected", False)
        st.markdown(f"**PII Detected:** {'Yes — redacted' if pii else 'None'}")
        warnings = gov.get("warnings", [])
        if warnings:
            st.markdown("**Warnings:**")
            for w in warnings:
                st.markdown(
                    f'<p class="check-row"><span class="ind-warn">&#x25CF;</span> {w}</p>',
                    unsafe_allow_html=True,
                )
        with st.expander("Full Pipeline JSON"):
            st.json(result)


# ============================================================================
# INLINE DASHBOARD RENDERER
# ============================================================================


def _render_inline_dashboard(result, dashboard_key="dash"):
    """Render a complete dashboard inline in a chat message."""
    app_def = result.get("app_definition", {})
    exec_results = result.get("execution_results", {})
    gov = result.get("governance", {})
    overview = result.get("overview", {})
    passed = gov.get("passed", True)
    role_display = gov.get("role_display_name", gov.get("role", "?"))

    # Build narration lookup: component_id → narration text
    narration_map = {}
    for nc in overview.get("components", []):
        nid = nc.get("id", "")
        ntxt = nc.get("narration", "")
        if nid and ntxt:
            narration_map[nid] = ntxt

    # ── Governance badge ──
    if passed:
        st.markdown(
            f'<span class="gov-badge gov-pass">Passed · {role_display}</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<span class="gov-badge gov-fail">Blocked · {role_display}</span>',
            unsafe_allow_html=True,
        )

    # ── Governance blocked ──
    if not passed:
        blocked_reasons = gov.get("blocked_reasons", [])
        for reason in blocked_reasons or ["Access denied for this role."]:
            st.markdown(
                f'<div class="gov-badge gov-fail" style="display:block;margin:4px 0;'
                f'border-radius:6px;padding:8px 12px">{reason}</div>',
                unsafe_allow_html=True,
            )
        return

    # ── Overview summary ──
    summary = overview.get("summary", "")
    if summary:
        st.markdown(
            f'<div class="narration-summary">{summary}</div>',
            unsafe_allow_html=True,
        )

    # ── Render components ──
    components = app_def.get("components", [])
    kpis = [c for c in components if c.get("type") in ("kpi_card", "metric_highlight")]
    charts = [c for c in components if c.get("type") not in ("kpi_card", "metric_highlight")]

    if kpis:
        for row_start in range(0, len(kpis), 4):
            row_kpis = kpis[row_start : row_start + 4]
            kpi_cols = st.columns(len(row_kpis))
            for col, comp in zip(kpi_cols, row_kpis):
                with col:
                    cid = comp.get("id", "")
                    data = _get_data(exec_results.get(cid, {}))
                    renderer = RENDERERS.get(comp.get("type"))
                    if renderer:
                        renderer(comp, data, chart_key=f"{dashboard_key}_{cid}")
                    narration = narration_map.get(cid, "")
                    if narration:
                        st.markdown(
                            f'<div class="narration-component">{narration}</div>',
                            unsafe_allow_html=True,
                        )

    if charts:
        for i in range(0, len(charts), 2):
            row_comps = charts[i : i + 2]
            cols = st.columns(len(row_comps))
            for col, comp in zip(cols, row_comps):
                with col:
                    cid = comp.get("id", "")
                    ctype = comp.get("type", "")
                    data = _get_data(exec_results.get(cid, {}))
                    renderer = RENDERERS.get(ctype)
                    if renderer:
                        renderer(comp, data, chart_key=f"{dashboard_key}_{cid}")
                    else:
                        st.info(f"Unsupported: {ctype}")
                    narration = narration_map.get(cid, "")
                    if narration:
                        st.markdown(
                            f'<div class="narration-component">{narration}</div>',
                            unsafe_allow_html=True,
                        )

    # ── Governance report ──
    with st.expander("Governance Report"):
        _render_gov_checks(gov)


# ============================================================================
# LOGIN SCREEN
# ============================================================================


def render_login_screen():
    """Minimal login screen — logo, role picker, password, go."""
    ROLE_OPTIONS = ["Data Analyst", "Administrator", "Viewer"]
    ROLE_KEY_MAP = {"Administrator": "admin", "Data Analyst": "analyst", "Viewer": "viewer"}

    # ── Scoped CSS ──
    st.markdown("""<style>
    section[data-testid="stSidebar"],
    [data-testid="stSidebarCollapsedControl"],
    div[data-testid="stBottom"],
    div[data-testid="stDecoration"],
    header[data-testid="stHeader"],
    div[data-testid="stToolbar"],
    #MainMenu, footer {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
        overflow: hidden !important;
    }
    .stMainBlockContainer {
        max-width: 320px !important;
        margin: 0 auto !important;
        padding-top: 14vh !important;
    }
    .stMainBlockContainer [data-testid="stVerticalBlock"] {
        align-items: center !important;
        gap: 0.35rem !important;
    }
    .stMainBlockContainer .stMarkdown { width: 100% !important; }
    .stMainBlockContainer .stSelectbox,
    .stMainBlockContainer .stTextInput,
    .stMainBlockContainer .stButton { width: 100% !important; }

    /* Inputs */
    .stSelectbox > div > div {
        border-radius: 10px !important;
        min-height: 44px !important;
        font-size: 14px !important;
        border: 1px solid #e5e7eb !important;
        background: #ffffff !important;
    }
    .stSelectbox > div > div:focus-within {
        border-color: #9ca3af !important;
        box-shadow: 0 0 0 3px rgba(0,0,0,0.03) !important;
    }
    .stSelectbox label { display: none !important; }
    .stTextInput > div,
    .stTextInput > div > div {
        width: 100% !important;
        background: transparent !important;
        background-color: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0 !important;
    }
    .stTextInput input {
        border-radius: 10px !important;
        height: 44px !important;
        min-height: 44px !important;
        font-size: 14px !important;
        padding: 0 14px !important;
        border: 1px solid #e5e7eb !important;
        background: #ffffff !important;
        background-color: #ffffff !important;
        color: #111111 !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }
    .stTextInput input:focus {
        border-color: #9ca3af !important;
        box-shadow: 0 0 0 3px rgba(0,0,0,0.03) !important;
        outline: none !important;
    }
    .stTextInput input::placeholder { color: #9ca3af !important; }
    .stTextInput label { display: none !important; }
    .stTextInput button { display: none !important; }

    /* Button — target ALL buttons on login page to force dark fill */
    .stMainBlockContainer .stButton > button,
    .stMainBlockContainer .stButton > button[kind="primary"],
    .stMainBlockContainer [data-testid="baseButton-primary"],
    .stMainBlockContainer [data-testid="baseButton-primaryFormSubmit"] {
        width: 100% !important;
        height: 44px !important;
        background-color: #111111 !important;
        background: #111111 !important;
        color: #ffffff !important;
        border-radius: 10px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        border: none !important;
        margin-top: 6px !important;
        cursor: pointer !important;
    }
    .stMainBlockContainer .stButton > button:hover,
    .stMainBlockContainer [data-testid="baseButton-primary"]:hover {
        background-color: #333333 !important;
        background: #333333 !important;
        color: #ffffff !important;
    }
    </style>""", unsafe_allow_html=True)

    # ── Logo ──
    st.markdown("""
    <div style="text-align:center;margin-bottom:32px">
        <div style="width:48px;height:48px;background:#111111;border-radius:12px;
                    display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L21 7V17L12 22L3 17V7L12 2Z" stroke="white" stroke-width="1.5"/>
            </svg>
        </div>
        <div style="font-size:26px;font-weight:700;color:#111111;letter-spacing:-0.5px;
                    font-family:'DM Sans',-apple-system,sans-serif">StackForge</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Role dropdown (no label — the dropdown speaks for itself) ──
    selected_display = st.selectbox(
        "Role",
        options=ROLE_OPTIONS,
        index=0,
        key="login_role_select",
        label_visibility="collapsed",
    )
    role_key = ROLE_KEY_MAP.get(selected_display, "analyst")

    # ── Password (no label — placeholder is enough) ──
    pwd = st.text_input(
        "Password",
        type="password",
        key="login_pwd",
        label_visibility="collapsed",
        placeholder="Password",
    )
    if st.session_state.get("login_error"):
        st.markdown(
            '<p style="color:#dc2626;font-size:12px;text-align:center;margin:0">Incorrect password</p>',
            unsafe_allow_html=True,
        )

    # ── Sign in button ──
    if st.button("Sign in", key="login_btn", type="primary", use_container_width=True):
        if pwd == PASSWORDS.get(role_key, ""):
            st.session_state.logged_in = True
            st.session_state.user_role = role_key
            st.session_state.messages = []
            st.session_state.pipeline_result = None
            st.session_state.current_app = None
            st.session_state.login_error = False
            st.rerun()
        else:
            st.session_state.login_error = True
            st.rerun()

    # ── Footer — single line ──
    st.markdown(
        '<p style="text-align:center;color:#c0c0c0;font-size:11px;margin-top:24px">'
        'HackUSU 2026</p>',
        unsafe_allow_html=True,
    )


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


def main():
    st.set_page_config(
        page_title="StackForge",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_custom_css(st)

    # ── Initialize session state ──
    for k, v in DEFAULTS.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # ── STATE 1: Not logged in ──
    if not st.session_state["logged_in"]:
        render_login_screen()
        return  # HARD RETURN — nothing else renders

    # ── STATE 2: Logged in — everything below is authenticated-only ──

    # ── SIDEBAR ──
    with st.sidebar:
        st.markdown('''
        <div class="sidebar-brand">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" style="flex-shrink:0">
                <path d="M12 2L21 7V17L12 22L3 17V7L12 2Z" stroke="#111111" stroke-width="1.5"/>
            </svg>
            <span>StackForge</span>
        </div>
        ''', unsafe_allow_html=True)
        role = st.session_state["user_role"]
        role_colors = {"admin": "#111111", "analyst": "#3b82f6", "viewer": "#6b7280"}
        badge_color = role_colors.get(role, "#6b7280")
        st.markdown(
            f'<div class="role-badge">'
            f'<span class="role-dot" style="background:{badge_color}"></span>'
            f'{ROLE_DISPLAY.get(role, role)}</div>',
            unsafe_allow_html=True,
        )

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Home ──
        if st.button("Home", key="home_btn", use_container_width=True):
            if st.session_state.current_page != "chat":
                st.session_state.current_page = "chat"
                st.rerun()

        # ── Templates ──
        st.markdown('<div class="section-label">Quick start</div>', unsafe_allow_html=True)
        for idx, tmpl in enumerate(TEMPLATES):
            if st.button(tmpl["name"], key=f"tmpl-{idx}", use_container_width=True):
                with st.spinner("Building..."):
                    process_prompt(tmpl["prompt"])
                st.rerun()

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Data Sources ──
        from data.sample_data_loader import get_available_tables, register_uploaded_csv, remove_table
        current_tables = get_available_tables()
        uploaded = st.session_state.get("uploaded_tables", {})

        st.markdown('<div class="section-label">Your Data</div>', unsafe_allow_html=True)
        for tbl in current_tables:
            if tbl in uploaded:
                info = uploaded[tbl]
                st.markdown(
                    f'<div style="display:flex;align-items:center;justify-content:space-between;'
                    f'padding:6px 10px;background:#f0fdf4;border:1px solid #bbf7d0;'
                    f'border-radius:8px;margin-bottom:4px;font-size:12px">'
                    f'<span style="color:#166534;font-weight:600">'
                    f'{LUCIDE["database"]} &nbsp;{tbl}</span>'
                    f'<span style="color:#6b7280">{info["rows"]} rows</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div style="display:flex;align-items:center;justify-content:space-between;'
                    f'padding:6px 10px;background:#f8fafc;border:1px solid #e2e8f0;'
                    f'border-radius:8px;margin-bottom:4px;font-size:12px">'
                    f'<span style="color:#334155;font-weight:500">'
                    f'{LUCIDE["database"]} &nbsp;{tbl}</span>'
                    f'<span style="color:#94a3b8;font-size:11px">built-in</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

        # ── CSV Upload ──
        csv_files = st.file_uploader(
            "Upload CSV",
            type=["csv"],
            accept_multiple_files=True,
            key="csv_uploader",
            label_visibility="collapsed",
        )
        if csv_files:
            for uploaded_file in csv_files:
                file_name = uploaded_file.name
                table_name_check = file_name.replace(".csv", "").lower().replace(" ", "_").replace("-", "_")
                if table_name_check in uploaded:
                    continue
                try:
                    df = pd.read_csv(uploaded_file)
                    table_name = register_uploaded_csv(file_name, df)
                    st.session_state.uploaded_tables[table_name] = {
                        "rows": len(df),
                        "columns": len(df.columns),
                        "file_name": file_name,
                    }
                    st.session_state.pipeline_result = None
                    st.session_state.current_app = None
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to load {file_name}: {e}")

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Engine toggle ──
        st.session_state.show_engine = st.toggle(
            "Show Engine", value=st.session_state.show_engine
        )

        # ── Navigation ──
        st.markdown('<div class="section-label">Navigation</div>', unsafe_allow_html=True)
        if st.button("Graph History", key="graph_history_btn", use_container_width=True):
            if st.session_state.current_page != "graph_history":
                st.session_state.current_page = "graph_history"
                st.rerun()
        if role == "admin":
            if st.button("Audit History", key="audit_history_btn", use_container_width=True):
                if st.session_state.current_page != "audit_history":
                    st.session_state.current_page = "audit_history"
                    st.rerun()

        # ── Sign out at bottom (subtle) ──
        st.markdown('<div style="height:24px"></div>', unsafe_allow_html=True)
        if st.button("Sign out", key="logout_btn"):
            st.session_state["logged_in"] = False
            st.session_state["user_role"] = None
            st.rerun()

        # ── Footer ──
        st.markdown(
            '<div class="sidebar-footer">StackForge v1.0</div>',
            unsafe_allow_html=True,
        )

    # ── Page routing ──
    if st.session_state.current_page == "audit_history" and role == "admin":
        _render_audit_history()
    elif st.session_state.current_page == "graph_history":
        _render_graph_history()
    else:
        # ── Layout: chat + optional engine right panel ──
        _engine_on = st.session_state.show_engine and st.session_state.get("pipeline_result")
        if _engine_on:
            st.markdown("""<style>
            .stMainBlockContainer { max-width: 100% !important; padding-left: 1rem !important; padding-right: 1rem !important; }
            </style>""", unsafe_allow_html=True)
            _chat_col, _engine_col = st.columns([3, 2], gap="medium")
        else:
            _chat_col, _engine_col = st.container(), None

        with _chat_col:
            _render_main_content()

        # ── Right engine panel ──
        if _engine_col is not None:
            with _engine_col:
                st.markdown(
                    f'<div class="engine-panel-header">{LUCIDE["sparkles"]} &nbsp;'
                    f'<strong>Engine View</strong></div>',
                    unsafe_allow_html=True,
                )
                _render_engine_panel(st.session_state.pipeline_result)

        # ── Chat input (always at bottom) ──
        user_input = st.chat_input("Describe the app you want to build...")
        if user_input:
            with st.spinner("Building..."):
                process_prompt(user_input)
            st.rerun()


def _render_graph_history():
    """All roles: browse previously generated dashboards saved in graphs/."""
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
        f'{LUCIDE["bar-chart-3"]}'
        f'<span style="font-size:22px;font-weight:700;letter-spacing:-0.02em">Graph History</span>'
        f'</div>'
        f'<p style="color:#6b7280;font-size:13px;margin-bottom:20px">'
        f'All dashboards generated in this workspace, newest first.</p>',
        unsafe_allow_html=True,
    )

    graphs_dir = Path("graphs")
    if not graphs_dir.exists():
        st.info("No saved graphs yet. Generate a dashboard in the chat to get started.")
        return

    files = sorted(graphs_dir.glob("output_*.json"), reverse=True)
    if not files:
        st.info("No saved graphs yet. Generate a dashboard in the chat to get started.")
        return

    st.markdown(
        f'<p style="color:#6b7280;font-size:12px;margin-bottom:12px">{len(files)} saved dashboard(s)</p>',
        unsafe_allow_html=True,
    )

    for f in files:
        try:
            with open(f, "r") as fh:
                payload = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue

        result = payload.get("result", {})
        prompt = payload.get("prompt", "")
        saved_at = payload.get("saved_at", "")
        app_def = result.get("app_definition", {})
        gov = result.get("governance", {})
        app_title = app_def.get("app_title", "Dashboard")
        n_comps = len(app_def.get("components", []))
        passed = gov.get("passed", True)

        try:
            dt = datetime.fromisoformat(saved_at)
            ts_display = dt.strftime("%b %d %Y · %H:%M:%S")
        except Exception:
            ts_display = saved_at[:19] if saved_at else f.stem

        status_badge = (
            '<span style="background:#dcfce7;color:#16a34a;font-size:10px;'
            'font-weight:600;padding:2px 7px;border-radius:4px">Passed</span>'
            if passed else
            '<span style="background:#fee2e2;color:#dc2626;font-size:10px;'
            'font-weight:600;padding:2px 7px;border-radius:4px">Blocked</span>'
        )

        with st.expander(
            f"{app_title}  ·  {ts_display}  ·  {n_comps} components",
            expanded=False,
        ):
            st.markdown(
                f'<p style="color:#6b7280;font-size:12px;margin-bottom:8px">'
                f'<strong>Prompt:</strong> {prompt}</p>',
                unsafe_allow_html=True,
            )
            st.markdown(status_badge, unsafe_allow_html=True)
            st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)

            # Re-render the dashboard using the stored execution results
            _render_inline_dashboard(result, dashboard_key=f"hist_{f.stem}")

            col_dl, _ = st.columns([1, 4])
            with col_dl:
                with open(f, "rb") as fh:
                    st.download_button(
                        "Download JSON",
                        data=fh,
                        file_name=f.name,
                        mime="application/json",
                        key=f"dl_{f.stem}",
                    )


def _render_audit_history():
    """Admin-only: render full audit trail from the JSONL file."""
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
        f'{LUCIDE["shield-check"]}'
        f'<span style="font-size:22px;font-weight:700;letter-spacing:-0.02em">Audit History</span>'
        f'</div>'
        f'<p style="color:#6b7280;font-size:13px;margin-bottom:20px">'
        f'Persistent governance log — every check the system has run.</p>',
        unsafe_allow_html=True,
    )

    audit_path = Path("audit_trail.jsonl")
    if not audit_path.exists():
        st.info("No audit trail file found yet.")
        return

    # Read all entries
    entries = []
    with open(audit_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not entries:
        st.info("Audit trail is empty.")
        return

    # Newest first
    entries.reverse()

    # ── Summary KPIs ──
    total = len(entries)
    passed = sum(1 for e in entries if e.get("details", {}).get("passed") is True)
    failed = sum(1 for e in entries if e.get("details", {}).get("passed") is False)
    unique_sessions = len(set(e.get("session_id", "") for e in entries))

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Events", total)
    k2.metric("Passed", passed)
    k3.metric("Blocked", failed)
    k4.metric("Sessions", unique_sessions)

    st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)

    # ── Filters ──
    col_action, col_status, col_role = st.columns(3)
    actions = sorted(set(e.get("action", "unknown") for e in entries))
    with col_action:
        filter_action = st.selectbox("Action", ["All"] + actions, key="audit_filter_action")
    with col_status:
        filter_status = st.selectbox("Status", ["All", "Passed", "Blocked"], key="audit_filter_status")
    roles_in_log = sorted(set(e.get("details", {}).get("role", "") for e in entries if e.get("details", {}).get("role")))
    with col_role:
        filter_role = st.selectbox("Role", ["All"] + roles_in_log, key="audit_filter_role")

    # Apply filters
    filtered = entries
    if filter_action != "All":
        filtered = [e for e in filtered if e.get("action") == filter_action]
    if filter_status == "Passed":
        filtered = [e for e in filtered if e.get("details", {}).get("passed") is True]
    elif filter_status == "Blocked":
        filtered = [e for e in filtered if e.get("details", {}).get("passed") is False]
    if filter_role != "All":
        filtered = [e for e in filtered if e.get("details", {}).get("role") == filter_role]

    st.markdown(f'<p style="color:#6b7280;font-size:12px;margin:8px 0 12px 0">'
                f'Showing {len(filtered)} of {total} entries</p>',
                unsafe_allow_html=True)

    # ── Table view ──
    if filtered:
        rows = []
        for e in filtered:
            d = e.get("details", {})
            ts = e.get("timestamp", "")
            # Format timestamp nicely
            try:
                dt = datetime.fromisoformat(ts)
                ts_display = dt.strftime("%b %d, %H:%M:%S")
            except Exception:
                ts_display = ts[:19] if len(ts) > 19 else ts

            status = "Pass" if d.get("passed") is True else ("Blocked" if d.get("passed") is False else "—")
            blocked_reasons = d.get("blocked_reasons", [])
            reason_str = "; ".join(blocked_reasons) if blocked_reasons else ""

            rows.append({
                "Time": ts_display,
                "Session": e.get("session_id", "")[:6],
                "Action": e.get("action", ""),
                "Role": d.get("role", "—"),
                "App": d.get("app_id", "—"),
                "Status": status,
                "Reasons": reason_str,
            })

        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            height=min(len(rows) * 35 + 38, 600),
            column_config={
                "Time": st.column_config.TextColumn(width="small"),
                "Session": st.column_config.TextColumn(width="small"),
                "Action": st.column_config.TextColumn(width="small"),
                "Role": st.column_config.TextColumn(width="small"),
                "App": st.column_config.TextColumn(width="medium"),
                "Status": st.column_config.TextColumn(width="small"),
                "Reasons": st.column_config.TextColumn(width="large"),
            },
        )

        # ── Expandable detail view for latest entries ──
        st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
        with st.expander(f"Raw JSON — latest {min(10, len(filtered))} entries"):
            for e in filtered[:10]:
                st.json(e)
    else:
        st.info("No entries match the current filters.")


def _render_main_content():
    """Main area — welcome screen or chat history."""
    if not st.session_state.messages:
        _icon_sparkles = LUCIDE["sparkles"]
        _icon_chart = LUCIDE["bar-chart-3"]
        _icon_shield = LUCIDE["shield-check"]
        st.markdown(f"""
        <div class="welcome-container">
            <div class="welcome-title">
                <span class="t-stack">Stack</span><span class="t-forge">Forge</span>
            </div>
            <div class="welcome-sub">
                Describe the data app you want. We build it in seconds.
            </div>
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-icon">{_icon_sparkles}</div>
                    <div class="feature-label">Natural Language In</div>
                    <div class="feature-desc">
                        Describe what you need. The compiler handles the rest.
                    </div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">{_icon_chart}</div>
                    <div class="feature-label">Live SQL Out</div>
                    <div class="feature-desc">
                        Queries generated, executed, and validated in real time.
                    </div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">{_icon_shield}</div>
                    <div class="feature-label">Governed by Default</div>
                    <div class="feature-desc">
                        Role-based access, PII scanning, full audit trail.
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        _, btn_col, _ = st.columns([1.5, 2, 1.5])
        with btn_col:
            if st.button(
                "Try: Supplier defect rates by region →",
                key="example-btn",
                use_container_width=True,
            ):
                with st.spinner("Building..."):
                    process_prompt(
                        "Show supplier defect rates by region with KPIs for total orders "
                        "and average defect rate, a bar chart of defects by supplier, "
                        "and a line chart of defect trends over time"
                    )
                st.rerun()
    else:
        for idx, msg in enumerate(st.session_state.messages):
            ts = msg.get("timestamp", "")
            if msg["role"] == "user":
                st.markdown(
                    f'<div class="msg-user-wrap">'
                    f'<div class="msg-label">You · {ts}</div>'
                    f'<div class="msg-user">{msg["content"]}</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )
            else:
                is_latest = (idx == len(st.session_state.messages) - 1)
                should_stream = msg.get("stream", False) and is_latest

                if should_stream:
                    import time
                    st.markdown(
                        f'<div class="msg-asst-wrap">'
                        f'<div class="msg-label">StackForge · {ts}</div>',
                        unsafe_allow_html=True,
                    )
                    placeholder = st.empty()
                    full_text = msg["content"]
                    streamed = ""
                    for i in range(0, len(full_text), 3):
                        streamed = full_text[:i+3]
                        placeholder.markdown(
                            f'<div class="msg-asst">{streamed}</div></div>',
                            unsafe_allow_html=True,
                        )
                        time.sleep(0.012)
                    placeholder.markdown(
                        f'<div class="msg-asst">{full_text}</div></div>',
                        unsafe_allow_html=True,
                    )
                    msg["stream"] = False
                else:
                    st.markdown(
                        f'<div class="msg-asst-wrap">'
                        f'<div class="msg-label">StackForge · {ts}</div>'
                        f'<div class="msg-asst">{msg["content"]}</div>'
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                pipeline_result = msg.get("pipeline_result")
                if pipeline_result:
                    app_title = pipeline_result.get("app_definition", {}).get("app_title", "Dashboard")
                    with st.expander(f"Dashboard: {app_title}", expanded=is_latest):
                        _render_inline_dashboard(pipeline_result, dashboard_key=f"msg_{idx}")


main()
