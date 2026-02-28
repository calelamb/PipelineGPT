import streamlit as st
import json
import pandas as pd
import plotly.express as px
from datetime import datetime

# ─── Page config ───
st.set_page_config(page_title="StackForge", page_icon="🏗️", layout="wide")

# ─── Session state defaults ───
DEFAULTS = {
    "current_role": "analyst",
    "pipeline_result": None,
    "current_app": None,
    "active_filters": None,
    "messages": [],
    "show_engine": False,
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ─── Templates ───
TEMPLATES = [
    {
        "name": "Supplier Performance",
        "icon": "📦",
        "prompt": (
            "Create a supplier performance dashboard with KPIs for total orders, "
            "average defect rate, and on-time delivery percentage. Include a bar chart "
            "of defect rate by supplier, a line chart of delivery trends over time, "
            "a pie chart of orders by region, and a supplier details table. "
            "Add filters for region and category."
        ),
    },
    {
        "name": "Supply Chain Costs",
        "icon": "💰",
        "prompt": (
            "Create a cost analysis dashboard with KPIs for total cost, average unit cost, "
            "and total shipping cost. Include a bar chart of costs by region, a pie chart "
            "of cost distribution by category, and a detailed cost table. "
            "Add filters for region and shipping mode."
        ),
    },
    {
        "name": "Quality Control",
        "icon": "🔍",
        "prompt": (
            "Build a quality control dashboard with KPIs for average defect rate and "
            "total defective orders. Include a bar chart of defect rates by supplier, "
            "a scatter plot of defect rate vs unit cost, and a line chart of defect "
            "trends over time. Add filters for region and supplier."
        ),
    },
    {
        "name": "Logistics & Shipping",
        "icon": "🚚",
        "prompt": (
            "Create a logistics dashboard with KPIs for total shipping cost and "
            "average delivery days. Include a bar chart of shipping cost by shipping mode, "
            "a line chart of order volume over time, and a shipment details table. "
            "Add filters for region and shipping mode."
        ),
    },
    {
        "name": "Regional Analysis",
        "icon": "🌍",
        "prompt": (
            "Show me a regional analysis dashboard with KPIs for total orders and "
            "average defect rate. Include a bar chart comparing regions by total cost, "
            "a pie chart of order distribution by region, and a table of regional metrics. "
            "Add filters for category and shipping mode."
        ),
    },
    {
        "name": "Executive Summary",
        "icon": "📈",
        "prompt": (
            "Build an executive KPI summary with total orders, total cost, average defect "
            "rate, and average shipping cost as KPI cards. Include a bar chart of costs by "
            "region and a line chart of monthly order trends. Add a region filter."
        ),
    },
]


# ============================================================================
# PIPELINE
# ============================================================================


def call_pipeline(user_prompt: str) -> dict:
    """Call the real StackForge engine pipeline."""
    from engine.pipeline import run_pipeline

    result = run_pipeline(
        user_message=user_prompt,
        existing_app=st.session_state.get("current_app"),
        filters=st.session_state.get("active_filters"),
        role=st.session_state.get("current_role", "analyst"),
    )
    return result


def process_prompt(prompt: str):
    """Run pipeline, store result, add to chat history."""
    result = call_pipeline(prompt)
    st.session_state.pipeline_result = result
    st.session_state.current_app = result.get("app_definition")
    st.session_state.messages.append({
        "role": "user",
        "content": prompt,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })


# ============================================================================
# RENDERERS
# ============================================================================

PLOTLY_DEFAULTS = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e2e8f0"),
    height=400,
    margin=dict(l=40, r=20, t=50, b=40),
)


def render_kpi(component: dict, data: list):
    cfg = component.get("config", {})
    value_col = cfg.get("value_column", "")
    label = cfg.get("metric_name", component.get("title", "KPI"))
    fmt = cfg.get("format", "")
    if data:
        row = data[0]
        val = row.get(value_col) if value_col and value_col in row else list(row.values())[0]
        if val is not None:
            if fmt == "percentage":
                display = f"{val:.2f}%"
            elif fmt == "currency":
                display = f"${val:,.2f}"
            else:
                display = f"{val:,.2f}"
        else:
            display = "N/A"
    else:
        display = "N/A"
    st.metric(label=label, value=display)


def render_bar_chart(component: dict, data: list):
    cfg = component.get("config", {})
    df = pd.DataFrame(data)
    if df.empty:
        st.warning(f"No data for: {component.get('title')}")
        return
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = None
    for c in df.columns:
        if c != x and c != y and df[c].dtype == "object":
            color_col = c
            break
    fig = px.bar(df, x=x, y=y, color=color_col, title=component.get("title", ""), barmode="group")
    fig.update_layout(**PLOTLY_DEFAULTS)
    st.plotly_chart(fig, use_container_width=True)


def render_table(component: dict, data: list):
    df = pd.DataFrame(data)
    if df.empty:
        st.warning(f"No data for: {component.get('title')}")
        return
    cfg = component.get("config", {})
    sort_col = cfg.get("sort_column")
    if sort_col and sort_col in df.columns:
        df = df.sort_values(sort_col, ascending=(cfg.get("sort_order", "asc") == "asc"))
    st.markdown(f"**{component.get('title', 'Table')}**")
    st.dataframe(df, use_container_width=True, height=400)


def render_line_chart(component: dict, data: list):
    df = pd.DataFrame(data)
    if df.empty:
        st.warning(f"No data for: {component.get('title')}")
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.line(df, x=x, y=y, title=component.get("title", ""), markers=True)
    fig.update_layout(**PLOTLY_DEFAULTS)
    st.plotly_chart(fig, use_container_width=True)


def render_pie_chart(component: dict, data: list):
    df = pd.DataFrame(data)
    if df.empty:
        st.warning(f"No data for: {component.get('title')}")
        return
    cfg = component.get("config", {})
    names = cfg.get("names", cfg.get("x_axis", df.columns[0]))
    values = cfg.get("values", cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0]))
    fig = px.pie(df, names=names, values=values, title=component.get("title", ""))
    fig.update_layout(**PLOTLY_DEFAULTS)
    st.plotly_chart(fig, use_container_width=True)


def render_scatter(component: dict, data: list):
    df = pd.DataFrame(data)
    if df.empty:
        st.warning(f"No data for: {component.get('title')}")
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.scatter(df, x=x, y=y, title=component.get("title", ""))
    fig.update_layout(**PLOTLY_DEFAULTS)
    st.plotly_chart(fig, use_container_width=True)


def render_area_chart(component: dict, data: list):
    df = pd.DataFrame(data)
    if df.empty:
        st.warning(f"No data for: {component.get('title')}")
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.area(df, x=x, y=y, title=component.get("title", ""))
    fig.update_layout(**PLOTLY_DEFAULTS)
    st.plotly_chart(fig, use_container_width=True)


def render_metric_highlight(component: dict, data: list):
    cfg = component.get("config", {})
    label = cfg.get("metric_name", component.get("title", "Metric"))
    fmt = cfg.get("format", "")
    if data:
        row = data[0]
        value_col = cfg.get("value_column", "")
        val = row.get(value_col) if value_col and value_col in row else list(row.values())[0]
        if val is not None:
            if fmt == "percentage":
                display = f"{val:.2f}%"
            elif fmt == "currency":
                display = f"${val:,.2f}"
            else:
                display = f"{val:,.2f}"
        else:
            display = "N/A"
    else:
        display = "N/A"
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
# RENDER DASHBOARD
# ============================================================================


def render_dashboard(result: dict):
    """Render the full dashboard from a pipeline result."""
    app_def = result.get("app_definition", {})
    exec_results = result.get("execution_results", {})
    gov = result.get("governance", {})
    validation = result.get("validation", {})
    show_engine = st.session_state.get("show_engine", False)

    st.subheader(app_def.get("app_title", "Dashboard"))
    st.caption(app_def.get("app_description", ""))

    # ── Governance check: if blocked, show reasons and stop ──
    passed = gov.get("passed", True)
    role_display = gov.get("role_display_name", gov.get("role", "?"))

    if passed:
        st.success(f"✅ Governance: PASSED  |  Role: {role_display}")
    else:
        st.error(f"❌ Governance: BLOCKED  |  Role: {role_display}")
        blocked_reasons = gov.get("blocked_reasons", [])
        if blocked_reasons:
            for reason in blocked_reasons:
                st.warning(reason)
        else:
            st.warning("Access denied for this role.")
        # Still show engine debug even when blocked
        if show_engine:
            _render_pipeline_debug(result)
        return

    # ── Render each component ──
    components = app_def.get("components", [])
    val_components = validation.get("components", [])
    # Build a lookup for validation by component id
    val_lookup = {vc.get("id"): vc for vc in val_components}

    for i, comp in enumerate(components):
        cid = comp.get("id", "")
        ctype = comp.get("type", "")
        comp_result = exec_results.get(cid, {})

        # Extract data list from execution result
        if isinstance(comp_result, dict):
            comp_data = comp_result.get("data", [])
        elif isinstance(comp_result, list):
            comp_data = comp_result
        else:
            comp_data = []

        # Render the chart/table/kpi
        renderer = RENDERERS.get(ctype)
        if renderer:
            renderer(comp, comp_data)
        else:
            st.info(f"Unsupported component type: {ctype}")

        # ── Engine view per component ──
        if show_engine:
            with st.expander(f"🔧 Engine: {comp.get('title', cid)} ({ctype})", expanded=False):
                # SQL query
                st.markdown("**SQL Query:**")
                st.code(comp.get("sql_query", "-- No SQL"), language="sql")

                # Raw data
                st.markdown("**Raw Data:**")
                if comp_data:
                    st.dataframe(pd.DataFrame(comp_data), use_container_width=True)
                else:
                    st.caption("No data returned")

                # Validation status
                val_info = val_lookup.get(cid, {})
                if val_info:
                    st.markdown("**Validation:**")
                    v_status = val_info.get("status", "?")
                    v_icon = "✅" if v_status == "success" else "⚠️"
                    st.caption(f"{v_icon} {val_info.get('explanation', v_status)}")
                    warnings = val_info.get("warnings", [])
                    for w in warnings:
                        st.caption(f"⚠️ {w}")

                # Governance for this component
                st.markdown("**Governance:**")
                st.caption(f"Overall: {'PASSED' if passed else 'BLOCKED'} | Role: {role_display}")

    # ── Pipeline Debug expander ──
    if show_engine:
        _render_pipeline_debug(result)


def _render_pipeline_debug(result: dict):
    """Full pipeline debug view at the bottom."""
    st.markdown("---")
    st.markdown("### 🔧 Pipeline Debug")

    with st.expander("📋 App Definition (AST)", expanded=False):
        st.json(result.get("app_definition", {}))

    with st.expander("✅ Governance Report", expanded=False):
        st.json(result.get("governance", {}))

    with st.expander("📊 Validation Report", expanded=False):
        st.json(result.get("validation", {}))

    with st.expander("📦 Raw Execution Results", expanded=False):
        # execution_results may have DataFrames, convert to serializable
        exec_results = result.get("execution_results", {})
        safe = {}
        for k, v in exec_results.items():
            if isinstance(v, dict):
                safe[k] = {
                    "status": v.get("status"),
                    "row_count": v.get("row_count"),
                    "data_preview": v.get("data", [])[:3],
                }
            else:
                safe[k] = str(v)[:200]
        st.json(safe)


# ============================================================================
# SIDEBAR
# ============================================================================

st.sidebar.markdown("## 🏗️ StackForge")

# Role selector
new_role = st.sidebar.radio(
    "👤 Role",
    options=["admin", "analyst", "viewer"],
    index=["admin", "analyst", "viewer"].index(st.session_state.current_role),
    help="Controls data access, component permissions, and governance checks",
)
if new_role != st.session_state.current_role:
    st.session_state.current_role = new_role
    st.session_state.pipeline_result = None
    st.session_state.current_app = None
    st.rerun()

role_desc = {
    "admin": "🔑 Full access — all data, all components, PII visible",
    "analyst": "📊 Internal data — no restricted columns (supplier)",
    "viewer": "👁️ Public data only — no tables, no scatter, max 4 components",
}
st.sidebar.caption(role_desc.get(st.session_state.current_role, ""))

st.sidebar.markdown("---")

# Engine toggle
st.session_state.show_engine = st.sidebar.toggle(
    "🔧 Show Engine",
    value=st.session_state.show_engine,
)

st.sidebar.markdown("---")

# Governance sidebar summary
if st.session_state.pipeline_result:
    gov = st.session_state.pipeline_result.get("governance", {})
    if gov.get("passed", True):
        st.sidebar.success("✅ Governance: PASSED")
    else:
        st.sidebar.error("❌ Governance: BLOCKED")
    for check in gov.get("checks", [])[:5]:
        icon = "✅" if check.get("passed", check.get("status") == "pass") else "❌"
        st.sidebar.caption(f"{icon} {check.get('name', 'Check')}")


# ============================================================================
# MAIN PAGE
# ============================================================================

st.title("🏗️ StackForge")
st.caption("AI-Powered Data App Factory — describe a dashboard and we'll build it live")

# ─── Input section ───
st.markdown("#### 📋 Quick Templates")
cols = st.columns(3)
for idx, tmpl in enumerate(TEMPLATES):
    with cols[idx % 3]:
        if st.button(
            f"{tmpl['icon']} {tmpl['name']}",
            key=f"tmpl-{idx}",
            use_container_width=True,
        ):
            with st.spinner(f"🧠 Building {tmpl['name']} dashboard..."):
                process_prompt(tmpl["prompt"])
            st.rerun()

st.markdown("---")

user_prompt = st.text_area(
    "✏️ Or describe your own dashboard:",
    placeholder="e.g. Show me supplier defect rates by region with a bar chart and KPIs",
    height=80,
)
if st.button("🚀 Generate", type="primary", use_container_width=True):
    if not user_prompt.strip():
        st.warning("Please enter a prompt first.")
    else:
        with st.spinner("🧠 Building your dashboard..."):
            process_prompt(user_prompt)
        st.rerun()

# ─── Dashboard output (same page, below input) ───
st.markdown("---")

result = st.session_state.pipeline_result
if result:
    render_dashboard(result)
else:
    st.info("No dashboard yet. Choose a template or type a prompt above and click **Generate**.")
