import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# ─── Page config (MUST be first Streamlit call) ───
st.set_page_config(
    page_title="StackForge",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Inject custom CSS ───
from ui.styles import inject_custom_css
inject_custom_css(st)

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
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

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


def process_prompt(prompt: str):
    """Run pipeline, store results, add to chat with inline result."""
    st.session_state.messages.append({
        "role": "user", "content": prompt,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })
    result = call_pipeline(prompt)
    st.session_state.pipeline_result = result
    st.session_state.current_app = result.get("app_definition")

    gov = result.get("governance", {})
    app_def = result.get("app_definition", {})
    if gov.get("passed", True):
        n = len(app_def.get("components", []))
        msg = f"Built **{app_def.get('app_title', 'dashboard')}** with {n} components."
    else:
        msg = "Governance blocked this request. See details below."

    st.session_state.messages.append({
        "role": "assistant", "content": msg,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "pipeline_result": result,
    })


# ============================================================================
# PLOTLY CONFIG
# ============================================================================

PLOTLY_DEFAULTS = dict(
    template="simple_white",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#6b7280", family="Inter"),
    height=380,
    margin=dict(l=40, r=20, t=50, b=40),
)
PLOTLY_GRID = dict(gridcolor="#e5e7eb")
ACCENT_COLORS = ["#111111", "#3b82f6", "#8b5cf6", "#06b6d4", "#f59e0b", "#ef4444"]


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


def render_kpi(component, data):
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


def render_bar_chart(component, data):
    cfg = component.get("config", {})
    df = pd.DataFrame(data)
    if df.empty:
        return
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    color_col = None
    for c in df.columns:
        if c != x and c != y and df[c].dtype == "object":
            color_col = c
            break
    fig = px.bar(df, x=x, y=y, color=color_col, title=component.get("title", ""),
                 barmode="group", color_discrete_sequence=ACCENT_COLORS)
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True)


def render_table(component, data):
    df = pd.DataFrame(data)
    if df.empty:
        return
    cfg = component.get("config", {})
    sort_col = cfg.get("sort_column")
    if sort_col and sort_col in df.columns:
        df = df.sort_values(sort_col, ascending=(cfg.get("sort_order", "asc") == "asc"))
    st.markdown(
        f"<p style='font-weight:600;color:#111111;margin-bottom:4px;font-size:14px'>"
        f"{component.get('title', 'Table')}</p>",
        unsafe_allow_html=True,
    )
    st.dataframe(df, use_container_width=True, height=380)


def render_line_chart(component, data):
    df = pd.DataFrame(data)
    if df.empty:
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.line(df, x=x, y=y, title=component.get("title", ""), markers=True,
                  color_discrete_sequence=ACCENT_COLORS)
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True)


def render_pie_chart(component, data):
    df = pd.DataFrame(data)
    if df.empty:
        return
    cfg = component.get("config", {})
    names = cfg.get("names", cfg.get("x_axis", df.columns[0]))
    values = cfg.get("values", cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0]))
    fig = px.pie(df, names=names, values=values, title=component.get("title", ""),
                 color_discrete_sequence=ACCENT_COLORS)
    fig.update_layout(**PLOTLY_DEFAULTS)
    fig.update_traces(marker=dict(line=dict(color="#ffffff", width=2)))
    st.plotly_chart(fig, use_container_width=True)


def render_scatter(component, data):
    df = pd.DataFrame(data)
    if df.empty:
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.scatter(df, x=x, y=y, title=component.get("title", ""),
                     color_discrete_sequence=ACCENT_COLORS)
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True)


def render_area_chart(component, data):
    df = pd.DataFrame(data)
    if df.empty:
        return
    cfg = component.get("config", {})
    x = cfg.get("x_axis", df.columns[0])
    y = cfg.get("y_axis", df.columns[1] if len(df.columns) > 1 else df.columns[0])
    fig = px.area(df, x=x, y=y, title=component.get("title", ""),
                  color_discrete_sequence=ACCENT_COLORS)
    fig.update_layout(**PLOTLY_DEFAULTS, xaxis=PLOTLY_GRID, yaxis=PLOTLY_GRID)
    st.plotly_chart(fig, use_container_width=True)


def render_metric_highlight(component, data):
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


def _render_inline_dashboard(result):
    """Render a complete dashboard inline in a chat message."""
    app_def = result.get("app_definition", {})
    exec_results = result.get("execution_results", {})
    gov = result.get("governance", {})
    passed = gov.get("passed", True)
    role_display = gov.get("role_display_name", gov.get("role", "?"))

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

    # ── Render components ──
    components = app_def.get("components", [])
    kpis = [c for c in components if c.get("type") in ("kpi_card", "metric_highlight")]
    charts = [c for c in components if c.get("type") not in ("kpi_card", "metric_highlight")]

    if kpis:
        kpi_cols = st.columns(len(kpis))
        for col, comp in zip(kpi_cols, kpis):
            with col:
                cid = comp.get("id", "")
                data = _get_data(exec_results.get(cid, {}))
                renderer = RENDERERS.get(comp.get("type"))
                if renderer:
                    renderer(comp, data)

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
                        renderer(comp, data)
                    else:
                        st.info(f"Unsupported: {ctype}")

    # ── Governance report ──
    with st.expander("Governance Report"):
        _render_gov_checks(gov)


# ============================================================================
# LOGIN SCREEN
# ============================================================================


def render_login_screen():
    """Single centered login form."""
    ROLE_OPTIONS = ["Administrator", "Data Analyst", "Viewer"]
    ROLE_KEY_MAP = {"Administrator": "admin", "Data Analyst": "analyst", "Viewer": "viewer"}

    st.markdown(
        '<div class="login-title">'
        '<h1><span class="t-stack">Stack</span><span class="t-forge">Forge</span></h1>'
        '<p class="login-sub">Sign in to continue</p>'
        "</div>",
        unsafe_allow_html=True,
    )

    _, center, _ = st.columns([1.4, 1, 1.4])
    with center:
        selected_display = st.selectbox(
            "Role",
            options=ROLE_OPTIONS,
            index=1,
            key="login_role_select",
            label_visibility="collapsed",
        )
        role_key = ROLE_KEY_MAP[selected_display]
        st.markdown(
            f'<p style="font-size:12px;color:#6b7280;margin:-8px 0 12px 0">'
            f"{ROLE_DESC[role_key]}</p>",
            unsafe_allow_html=True,
        )
        pwd = st.text_input(
            "Password",
            type="password",
            key="login_pwd",
            label_visibility="collapsed",
            placeholder="Password",
        )
        if st.button("Sign in", key="login_btn", type="primary", use_container_width=True):
            if pwd == PASSWORDS[role_key]:
                st.session_state.logged_in = True
                st.session_state.user_role = role_key
                st.session_state.messages = []
                st.session_state.pipeline_result = None
                st.session_state.current_app = None
                st.rerun()
            else:
                st.session_state.login_error = True
                st.rerun()
        if st.session_state.get("login_error"):
            st.markdown(
                '<p class="login-error">Incorrect password</p>',
                unsafe_allow_html=True,
            )


# ============================================================================
# MAIN APP (after login)
# ============================================================================


def render_main_app():
    """Chat-centric layout with sidebar control panel."""

    # ── SIDEBAR ──
    with st.sidebar:
        st.markdown('<div class="sidebar-brand">StackForge</div>', unsafe_allow_html=True)
        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Templates ──
        st.markdown('<div class="section-label">Quick start</div>', unsafe_allow_html=True)
        for idx, tmpl in enumerate(TEMPLATES):
            if st.button(tmpl["name"], key=f"tmpl-{idx}", use_container_width=True):
                with st.spinner("Building..."):
                    process_prompt(tmpl["prompt"])
                st.rerun()

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Engine toggle ──
        st.session_state.show_engine = st.toggle(
            "Show Engine", value=st.session_state.show_engine
        )

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Settings ──
        st.markdown('<div class="section-label">Session</div>', unsafe_allow_html=True)
        role = st.session_state.user_role
        st.markdown(
            f"<p style='font-size:13px;color:#374151;margin:0'>"
            f"{ROLE_DISPLAY.get(role, role)}</p>"
            f"<p style='font-size:11px;color:#9ca3af;margin:0 0 8px 0'>"
            f"{ROLE_DESC.get(role, '')}</p>",
            unsafe_allow_html=True,
        )
        if st.button("Sign out", key="logout_btn", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        # ── Footer ──
        st.markdown(
            '<div class="sidebar-footer">StackForge v1.0</div>',
            unsafe_allow_html=True,
        )

    # ── MAIN AREA: Chat ──
    if not st.session_state.messages:
        # ── Welcome state ──
        st.markdown("""
        <div class="welcome-container">
            <div class="welcome-title">
                <span class="t-stack">Stack</span><span class="t-forge">Forge</span>
            </div>
            <div class="welcome-sub">
                Describe the data app you want. We build it in seconds.
            </div>
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-label">Natural Language In</div>
                    <div class="feature-desc">
                        Describe what you need. The compiler handles the rest.
                    </div>
                </div>
                <div class="feature-card">
                    <div class="feature-label">Live SQL Out</div>
                    <div class="feature-desc">
                        Queries generated, executed, and validated in real time.
                    </div>
                </div>
                <div class="feature-card">
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
                "Try: Supplier defect rates by region",
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
        # ── Chat messages ──
        for msg in st.session_state.messages:
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
                st.markdown(
                    f'<div class="msg-asst-wrap">'
                    f'<div class="msg-label">StackForge · {ts}</div>'
                    f'<div class="msg-asst">{msg["content"]}</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )
                # ── Inline dashboard ──
                pipeline_result = msg.get("pipeline_result")
                if pipeline_result:
                    with st.container(border=True):
                        _render_inline_dashboard(pipeline_result)

        # ── Engine panel (if toggled) ──
        if st.session_state.show_engine and st.session_state.pipeline_result:
            _render_engine_panel(st.session_state.pipeline_result)

    # ── Chat input (always at bottom) ──
    user_input = st.chat_input("Describe the app you want to build...")
    if user_input:
        with st.spinner("Building..."):
            process_prompt(user_input)
        st.rerun()


# ============================================================================
# TOP-LEVEL ROUTING
# ============================================================================

if not st.session_state.logged_in:
    render_login_screen()
else:
    render_main_app()
