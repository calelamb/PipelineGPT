"""
StackForge UI — Premium light theme.
All CSS in one place. Called via inject_custom_css(st) at the top of app.py.
"""

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&display=swap');

/* Lucide icon base class */
.lucide-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    flex-shrink: 0;
    vertical-align: middle;
}

:root {
    --bg-page: #fafafa;
    --bg-sidebar: #ffffff;
    --bg-card: #ffffff;
    --bg-hover: #f3f4f6;
    --border: #e5e7eb;
    --border-subtle: #f0f0f0;
    --accent: #111111;
    --success: #16a34a;
    --warning: #d97706;
    --danger: #dc2626;
    --text-primary: #111111;
    --text-secondary: #6b7280;
    --text-tertiary: #9ca3af;
    --text-body: #374151;
    --font: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --radius-sm: 6px;
    --radius-md: 8px;
    --radius-lg: 12px;
    --radius-xl: 16px;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
    --shadow-md: 0 1px 3px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.03);
    --transition: 0.15s ease;
}

/* ── Animation keyframes ── */
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

/* ══════════════════════════════════════
   GLOBAL RESETS
   ══════════════════════════════════════ */
html, body, .stApp, [data-testid="stAppViewContainer"],
[data-testid="stAppViewBlockContainer"] {
    background-color: var(--bg-page) !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
}

/* Hide ALL Streamlit chrome */
#MainMenu,
footer,
header[data-testid="stHeader"],
div[data-testid="stDecoration"],
div[data-testid="stToolbar"],
.reportview-container .main footer {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    overflow: hidden !important;
}

[data-testid="stHeader"] { background-color: var(--bg-page) !important; height: 0 !important; }
[data-testid="stMain"] > div { background-color: var(--bg-page) !important; }

h1, h2, h3, h4, h5, h6 {
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
}
p, span, label, li, div {
    font-family: var(--font) !important;
}

/* ══════════════════════════════════════
   SIDEBAR
   ══════════════════════════════════════ */
/* Hide sidebar collapse button (renders raw "keyboard_double_arrow" text) */
[data-testid="stSidebarCollapseButton"],
section[data-testid="stSidebar"] button[kind="header"],
section[data-testid="stSidebar"] [data-testid="stBaseButton-header"],
section[data-testid="stSidebar"] > button,
section[data-testid="stSidebar"] header {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    overflow: hidden !important;
}
section[data-testid="stSidebar"] {
    background-color: var(--bg-sidebar) !important;
    border-right: 1px solid var(--border) !important;
    width: 260px !important;
    min-width: 260px !important;
}
section[data-testid="stSidebar"] > div {
    background-color: var(--bg-sidebar) !important;
    padding-top: 16px !important;
    padding-bottom: 48px !important;
}
/* Force all sidebar content left-aligned */
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
    align-items: flex-start !important;
}
section[data-testid="stSidebar"] .stMarkdown {
    width: 100% !important;
}
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] .stMarkdown span,
section[data-testid="stSidebar"] label {
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    text-align: left !important;
}

/* Sidebar template buttons — look like nav items */
section[data-testid="stSidebar"] .stButton {
    width: 100% !important;
}
section[data-testid="stSidebar"] .stButton > button {
    background-color: transparent !important;
    border: none !important;
    color: var(--text-body) !important;
    border-radius: var(--radius-sm) !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
    font-size: 13px !important;
    padding: 6px 10px !important;
    text-align: left !important;
    justify-content: flex-start !important;
    display: flex !important;
    transition: background-color var(--transition), color var(--transition) !important;
    transform: none !important;
    box-shadow: none !important;
    min-height: 32px !important;
    line-height: 1.4 !important;
    width: 100% !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background-color: var(--bg-hover) !important;
    color: var(--text-primary) !important;
    transform: none !important;
    box-shadow: none !important;
}

/* Engine toggle */
[data-testid="stToggle"] label span {
    color: var(--text-secondary) !important;
    font-size: 12px !important;
}
[data-testid="stToggle"] [role="switch"][aria-checked="true"] {
    background-color: var(--accent) !important;
}

/* Sidebar brand */
.sidebar-brand {
    font-weight: 700;
    font-size: 15px;
    color: var(--text-primary);
    font-family: var(--font);
    padding: 0 0 12px 0;
    display: flex;
    align-items: center;
    gap: 8px;
    letter-spacing: -0.3px;
}

.section-label {
    font-size: 11px;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 500;
    font-family: var(--font);
    margin-bottom: 4px;
}

.sidebar-footer {
    position: fixed;
    bottom: 0;
    width: 260px;
    padding: 10px 12px;
    background-color: var(--bg-sidebar);
    border-top: 1px solid var(--border-subtle);
    border-right: 1px solid var(--border);
    font-size: 10px;
    color: var(--text-tertiary);
    text-align: center;
    font-family: var(--font);
}

/* Role badge in sidebar */
.role-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin: 2px 0 8px 0;
    font-size: 12px;
    color: var(--text-secondary);
    font-family: var(--font);
}
.role-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}

/* ══════════════════════════════════════
   BUTTONS
   ══════════════════════════════════════ */

/* Default: ghost / text-link style */
.stButton > button {
    background-color: transparent !important;
    color: var(--text-secondary) !important;
    border: none !important;
    border-radius: var(--radius-md) !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
    font-size: 13px !important;
    padding: 4px 8px !important;
    transition: color var(--transition), background-color var(--transition) !important;
    transform: none !important;
    box-shadow: none !important;
}
.stButton > button:hover {
    color: var(--text-primary) !important;
    background-color: var(--bg-hover) !important;
    transform: none !important;
    box-shadow: none !important;
}
.stButton > button:active {
    transform: none !important;
    box-shadow: none !important;
}

/* Primary: solid dark (login, CTAs) */
[data-testid="baseButton-primary"] {
    background-color: var(--accent) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: var(--radius-md) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 14px !important;
    padding: 10px 24px !important;
    transition: background-color var(--transition), transform 0.1s ease !important;
    box-shadow: none !important;
}
[data-testid="baseButton-primary"]:hover {
    background-color: #333333 !important;
}
[data-testid="baseButton-primary"]:active {
    background-color: #000000 !important;
    transform: scale(0.98) !important;
}

/* ══════════════════════════════════════
   CHAT MESSAGES
   ══════════════════════════════════════ */
.msg-user-wrap {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    margin: 20px 0;
    animation: fadeIn 0.2s ease;
}
.msg-asst-wrap {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    margin: 20px 0;
    animation: fadeIn 0.2s ease;
}
.msg-label {
    font-size: 11px;
    color: var(--text-tertiary);
    margin-bottom: 4px;
    font-family: var(--font);
    font-weight: 500;
    letter-spacing: 0.02em;
}
.msg-user {
    background: #f3f4f6;
    color: var(--text-primary);
    border-radius: 16px 16px 4px 16px;
    padding: 12px 16px;
    max-width: 85%;
    font-size: 14px;
    line-height: 1.6;
    word-wrap: break-word;
    font-family: var(--font);
}
.msg-asst {
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-body);
    border-radius: 16px 16px 16px 4px;
    padding: 12px 16px;
    max-width: 95%;
    font-size: 14px;
    line-height: 1.6;
    word-wrap: break-word;
    font-family: var(--font);
    box-shadow: var(--shadow-sm);
}

/* ══════════════════════════════════════
   CHAT-DOMINANT LAYOUT
   ══════════════════════════════════════ */

/* Main content — fill available width with some breathing room */
.stMainBlockContainer {
    max-width: 1200px !important;
    margin: 0 auto !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    padding-bottom: 100px !important;
}

/* Dashboard cards */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: var(--border) !important;
    border-radius: var(--radius-lg) !important;
    background-color: var(--bg-card) !important;
    box-shadow: var(--shadow-sm) !important;
}

/* Dashboard expander — compact, looks like an embedded card */
.stExpander,
[data-testid="stExpander"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    background-color: var(--bg-card) !important;
    box-shadow: var(--shadow-sm) !important;
    margin: 8px 0 16px 0 !important;
    overflow: hidden !important;
}
/* Kill the dark expander header — AGGRESSIVE override */
.stExpander details,
.stExpander summary,
.stExpander [data-testid="stExpanderToggleDetails"],
[data-testid="stExpander"] details,
[data-testid="stExpander"] summary,
[data-testid="stExpander"] > details > summary,
details[data-testid="stExpanderDetails"] > summary,
.streamlit-expanderHeader {
    background-color: #f3f4f6 !important;
    background: #f3f4f6 !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    border: none !important;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0 !important;
    padding: 12px 16px !important;
    cursor: pointer !important;
}
/* Fix the expander toggle — kill ALL markers and Material Icon spans */
.stExpander summary::marker,
[data-testid="stExpander"] summary::marker,
details summary::marker {
    content: "" !important;
    display: none !important;
    font-size: 0 !important;
}
.stExpander summary::-webkit-details-marker,
[data-testid="stExpander"] summary::-webkit-details-marker,
details summary::-webkit-details-marker {
    display: none !important;
}
/* Custom chevron arrow via ::before pseudo-element */
.stExpander summary::before,
[data-testid="stExpander"] summary::before {
    content: "›" !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-size: 20px !important;
    line-height: 1 !important;
    color: var(--text-secondary) !important;
    margin-right: 8px !important;
    transition: transform 0.2s ease !important;
    transform: rotate(0deg) !important;
    flex-shrink: 0 !important;
}
.stExpander details[open] summary::before,
[data-testid="stExpander"] details[open] summary::before {
    transform: rotate(90deg) !important;
}
/*
 * NUCLEAR FIX for garbled expander text.
 * Streamlit puts an icon <span> with Material-Icons font in <summary>.
 * The icon font sometimes fails to load, rendering raw ligature text
 * ("expand_more") that overlaps the label.  Strategy:
 *   1. Set font-size:0 on <summary> to collapse ALL text.
 *   2. Re-set font-size on the label <span> only.
 *   3. Hide all SVGs inside summary.
 */
.stExpander summary,
[data-testid="stExpander"] summary,
details summary {
    font-size: 0 !important;
    line-height: 0 !important;
    list-style: none !important;
    display: flex !important;
    align-items: center !important;
    overflow: hidden !important;
}
/* Restore font on the label text (the last span, or markdown container) */
.stExpander summary > span:last-of-type,
[data-testid="stExpander"] summary > span:last-of-type,
.stExpander summary p,
[data-testid="stExpander"] summary p,
.stExpander summary [data-testid="stMarkdownContainer"],
[data-testid="stExpander"] summary [data-testid="stMarkdownContainer"],
.stExpander summary [data-testid="stMarkdownContainer"] p {
    font-size: 13px !important;
    line-height: 1.4 !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
}
/* Hide the Material Icons toggle icon span */
.stExpander summary > span:first-child,
[data-testid="stExpander"] summary > span:first-child,
.stExpander summary [data-testid="stExpanderToggleIcon"],
[data-testid="stExpander"] summary [data-testid="stExpanderToggleIcon"] {
    display: none !important;
    width: 0 !important;
    overflow: hidden !important;
}
/* Hide SVG arrows (we use CSS ::before chevron) */
.stExpander summary svg,
[data-testid="stExpander"] summary svg {
    display: none !important;
}
.stExpander summary:hover,
[data-testid="stExpander"] summary:hover {
    background-color: #e9eaec !important;
    background: #e9eaec !important;
}
.stExpander summary:hover::before,
[data-testid="stExpander"] summary:hover::before {
    color: var(--text-primary) !important;
}
/* Expander content area */
.stExpander [data-testid="stExpanderDetails"],
[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
    padding: 4px 12px 12px 12px !important;
    border-top: 1px solid var(--border-subtle) !important;
    background-color: var(--bg-card) !important;
    background: var(--bg-card) !important;
}
/* Override any dark child divs inside expander — but NOT inside data grids */
.stExpander > details > div,
.stExpander > details > [data-testid="stExpanderDetails"] > div:not([data-testid="stDataFrame"] *) {
    background-color: transparent !important;
}

/* ══════════════════════════════════════
   INPUTS
   ══════════════════════════════════════ */
.stSelectbox > div > div,
.stMultiSelect > div > div,
.stTextArea textarea,
.stTextInput input,
[data-testid="stChatInput"] textarea {
    background-color: #ffffff !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    font-family: var(--font) !important;
    font-size: 14px !important;
    transition: border-color var(--transition), box-shadow var(--transition) !important;
}
.stSelectbox > div > div:focus-within,
.stTextArea textarea:focus,
.stTextInput input:focus,
[data-testid="stChatInput"] textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(0,0,0,0.04) !important;
}

/* ── Bottom bar (frosted glass) ── */
div[data-testid="stBottom"] {
    background-color: rgba(250,250,250,0.85) !important;
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
    border-top: 1px solid var(--border-subtle) !important;
    padding: 12px 24px 16px 24px !important;
}
div[data-testid="stBottom"] > div {
    background-color: transparent !important;
}

/* ── Chat input bar ── */
[data-testid="stChatInput"] {
    background-color: transparent !important;
    border-top: none !important;
    border: none !important;
}
[data-testid="stChatInput"] > div {
    background-color: #ffffff !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    box-shadow: var(--shadow-sm) !important;
    transition: border-color var(--transition), box-shadow var(--transition) !important;
}
[data-testid="stChatInput"] > div:focus-within {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(0,0,0,0.04) !important;
}
[data-testid="stChatInput"] textarea {
    background-color: #ffffff !important;
    color: var(--text-primary) !important;
    border: none !important;
    border-radius: var(--radius-lg) !important;
    font-size: 14px !important;
}
[data-testid="stChatInput"] textarea::placeholder {
    color: var(--text-tertiary) !important;
}
[data-testid="stChatInput"] button {
    background-color: transparent !important;
    color: var(--text-tertiary) !important;
    border: none !important;
    border-radius: var(--radius-sm) !important;
    transition: color var(--transition) !important;
}
[data-testid="stChatInput"] button:hover {
    color: var(--text-primary) !important;
}
/* Kill resize handles / corner brackets on chat input */
[data-testid="stChatInput"] textarea {
    resize: none !important;
}
/* Hide ALL non-button child elements that could be bracket decorations */
[data-testid="stChatInput"] > div > *:not(div):not(button),
[data-testid="stChatInput"] > div > div > *:not(textarea):not(div):not(button) {
    display: none !important;
    visibility: hidden !important;
    width: 0 !important;
    height: 0 !important;
    position: absolute !important;
    overflow: hidden !important;
}
/* Hide SVGs except send button */
[data-testid="stChatInput"] svg {
    visibility: hidden !important;
    width: 0 !important;
    height: 0 !important;
}
[data-testid="stChatInput"] button svg {
    visibility: visible !important;
    width: auto !important;
    height: auto !important;
}
/* Nuke all pseudo-elements */
[data-testid="stChatInput"] > div::before,
[data-testid="stChatInput"] > div::after,
[data-testid="stChatInput"] > div > *::before,
[data-testid="stChatInput"] > div > *::after {
    display: none !important;
    content: none !important;
}
/* Hide any span elements that might be the brackets */
[data-testid="stChatInput"] > div > span,
[data-testid="stChatInput"] > div > div > span:not(button span) {
    display: none !important;
}

/* ══════════════════════════════════════
   METRICS (KPI cards)
   ══════════════════════════════════════ */
[data-testid="stMetric"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    padding: 20px 22px !important;
    animation: fadeInUp 0.3s ease forwards;
    box-shadow: var(--shadow-sm) !important;
    position: relative;
    overflow: hidden;
}
/* Subtle top accent bar on KPI cards */
[data-testid="stMetric"]::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, #3b82f6, #8b5cf6);
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
}
[data-testid="stMetricValue"] {
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-weight: 700 !important;
    font-size: 1.5rem !important;
}
[data-testid="stMetricLabel"] {
    color: var(--text-secondary) !important;
    font-family: var(--font) !important;
    font-size: 11px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    font-weight: 500 !important;
}

/* ══════════════════════════════════════
   DATAFRAMES / EXPANDERS / CODE
   ══════════════════════════════════════ */
[data-testid="stDataFrame"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    overflow: hidden !important;
    animation: fadeInUp 0.3s ease forwards;
}
/* Lighten the dataframe header (glide-data-grid) */
[data-testid="stDataFrame"] [data-testid="glide-data-grid-canvas"],
[data-testid="stDataFrame"] canvas {
    border-radius: var(--radius-md) !important;
}
/* Override the dark header row via the theme variables */
[data-testid="stDataFrame"] .gdg-header,
[data-testid="stDataFrame"] th,
[data-testid="stDataFrame"] [role="columnheader"] {
    background-color: #f9fafb !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 12px !important;
    border-bottom: 1px solid var(--border) !important;
}
/* Legacy expander classes (older Streamlit versions) */
.streamlit-expanderHeader {
    background-color: var(--bg-card) !important;
    background: var(--bg-card) !important;
    border: none !important;
    border-radius: var(--radius-md) !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 13px !important;
}
.streamlit-expanderHeader:hover {
    background-color: var(--bg-hover) !important;
    background: var(--bg-hover) !important;
}
.streamlit-expanderContent {
    background-color: var(--bg-card) !important;
    background: var(--bg-card) !important;
    border: none !important;
    border-top: 1px solid var(--border-subtle) !important;
}
details summary {
    color: var(--text-primary) !important;
    background-color: var(--bg-card) !important;
    background: var(--bg-card) !important;
    cursor: pointer;
}
.stCodeBlock, pre, code {
    background-color: #1e1e2e !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
    border-radius: var(--radius-md) !important;
    font-size: 12px !important;
}
[data-testid="stAlert"] {
    border-radius: var(--radius-md) !important;
    font-family: var(--font) !important;
    font-size: 13px !important;
}

/* ══════════════════════════════════════
   TABS (Engine View)
   ══════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    gap: 2px !important;
    background-color: #f3f4f6 !important;
    border-radius: var(--radius-md) !important;
    padding: 3px !important;
    border: none !important;
}
.stTabs [data-baseweb="tab-list"] button {
    border-radius: var(--radius-sm) !important;
    color: var(--text-secondary) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 12px !important;
    padding: 6px 14px !important;
    border-bottom: none !important;
    transition: all var(--transition) !important;
}
.stTabs [data-baseweb="tab-list"] button:hover {
    color: var(--text-primary) !important;
}
.stTabs [aria-selected="true"] {
    background-color: var(--bg-card) !important;
    color: var(--text-primary) !important;
    box-shadow: var(--shadow-sm) !important;
}

/* ══════════════════════════════════════
   PLOTLY CHARTS
   ══════════════════════════════════════ */
[data-testid="stPlotlyChart"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-lg) !important;
    padding: 8px !important;
    animation: fadeInUp 0.4s ease forwards;
    box-shadow: var(--shadow-sm) !important;
}

/* ══════════════════════════════════════
   GOVERNANCE BADGES
   ══════════════════════════════════════ */
.gov-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 500;
    font-family: var(--font);
    letter-spacing: 0.02em;
}
.gov-pass {
    background-color: rgba(22, 163, 74, 0.08);
    color: #15803d;
    border: none;
}
.gov-fail {
    background-color: rgba(220, 38, 38, 0.08);
    color: #b91c1c;
    border: none;
}

/* ── Narration / Overview ── */
.narration-summary {
    font-size: 13.5px;
    line-height: 1.65;
    color: var(--text-body);
    padding: 10px 14px;
    margin: 8px 0 12px;
    border-left: 3px solid var(--accent);
    background: rgba(99, 102, 241, 0.04);
    border-radius: 0 8px 8px 0;
    font-family: var(--font);
}
.narration-component {
    font-size: 12.5px;
    line-height: 1.55;
    color: var(--text-secondary);
    padding: 6px 10px;
    margin: 4px 0 8px;
    border-radius: 6px;
    font-family: var(--font);
    font-style: italic;
}

/* ══════════════════════════════════════
   WELCOME STATE
   ══════════════════════════════════════ */
.welcome-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 50vh;
    text-align: center;
    padding-top: 8vh;
    animation: fadeIn 0.4s ease;
}
.welcome-title {
    font-size: 2.8rem;
    margin-bottom: 8px;
    font-family: var(--font);
    line-height: 1.1;
    color: var(--text-primary);
    letter-spacing: -1px;
}
.welcome-title .t-stack { font-weight: 700; }
.welcome-title .t-forge { font-weight: 300; }
.welcome-sub {
    color: var(--text-secondary);
    font-size: 16px;
    font-weight: 400;
    max-width: 440px;
    line-height: 1.6;
    font-family: var(--font);
    margin-bottom: 2.5rem;
}
.feature-grid {
    display: flex;
    gap: 16px;
    justify-content: center;
    flex-wrap: wrap;
    margin: 0 0 2rem;
    max-width: 720px;
}
.feature-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 20px;
    flex: 1;
    min-width: 190px;
    max-width: 230px;
    text-align: left;
    transition: border-color var(--transition), box-shadow var(--transition);
}
.feature-card:hover {
    border-color: #d1d5db;
    box-shadow: 0 2px 8px rgba(0,0,0,0.04);
}
.feature-icon {
    margin-bottom: 10px;
    color: var(--text-tertiary);
    display: flex;
    align-items: center;
}
.feature-icon svg {
    width: 20px;
    height: 20px;
}
.feature-label {
    font-weight: 600;
    font-size: 14px;
    color: var(--text-primary);
    margin-bottom: 6px;
    font-family: var(--font);
}
.feature-desc {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
    font-family: var(--font);
    font-weight: 400;
}

/* Try suggestion text */
.try-suggestion {
    color: var(--text-tertiary);
    font-size: 14px;
    font-family: var(--font);
    text-align: center;
    margin-top: 12px;
}

/* ══════════════════════════════════════
   PIPELINE STEPPER
   ══════════════════════════════════════ */
.stepper {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 12px 0;
    flex-wrap: wrap;
}
.step {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    font-weight: 500;
    color: var(--text-secondary);
    font-family: var(--font);
}
.step-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background-color: var(--accent);
    display: inline-block;
}
.step.done { color: var(--text-body); }
.step-line {
    width: 20px; height: 1px;
    background-color: var(--accent);
    display: inline-block;
}

/* ══════════════════════════════════════
   UTILITIES
   ══════════════════════════════════════ */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #d1d5db; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #9ca3af; }

hr {
    border: none !important;
    border-top: 1px solid var(--border-subtle) !important;
    opacity: 1 !important;
    margin: 16px 0 !important;
}

[data-testid="stJson"] {
    background-color: #1e1e2e !important;
    border: 1px solid #30363d !important;
    border-radius: var(--radius-md) !important;
}

.ind-pass { color: #16a34a; font-size: 10px; }
.ind-fail { color: #dc2626; font-size: 10px; }
.ind-warn { color: #d97706; font-size: 10px; }
.check-row {
    font-size: 12px;
    color: var(--text-secondary);
    margin: 2px 0;
    line-height: 1.5;
    font-family: var(--font);
}
.check-row strong { color: var(--text-primary); font-weight: 500; }

/* Engine right panel */
.engine-panel-header {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
    font-family: var(--font);
    padding: 8px 0 12px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
}
.engine-panel-header svg {
    width: 18px;
    height: 18px;
    color: var(--text-secondary);
}

/* ── Sidebar expander overrides (minimal) ── */
section[data-testid="stSidebar"] .stExpander,
section[data-testid="stSidebar"] [data-testid="stExpander"] {
    border: none !important;
    box-shadow: none !important;
    background-color: transparent !important;
    margin: 0 !important;
}
section[data-testid="stSidebar"] .stExpander [data-testid="stExpanderDetails"],
section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
    border-top: none !important;
    padding: 0 4px 8px 4px !important;
    background-color: transparent !important;
}

/* Sign-out button — subtle text link, not a nav item */
section[data-testid="stSidebar"] .stButton:last-of-type > button {
    font-size: 11px !important;
    color: var(--text-tertiary) !important;
    padding: 4px 10px !important;
    min-height: 28px !important;
}
section[data-testid="stSidebar"] .stButton:last-of-type > button:hover {
    color: var(--text-secondary) !important;
    background-color: transparent !important;
}

/* "Try" example button on welcome screen — subtle outline pill */
.welcome-container + div .stButton > button,
.stMainBlockContainer > div > div > .stColumns .stButton > button {
    border: 1px solid var(--border) !important;
    border-radius: 20px !important;
    color: var(--text-secondary) !important;
    font-size: 13px !important;
    padding: 8px 20px !important;
    background-color: var(--bg-card) !important;
    transition: all var(--transition) !important;
}
.welcome-container + div .stButton > button:hover,
.stMainBlockContainer > div > div > .stColumns .stButton > button:hover {
    border-color: #d1d5db !important;
    color: var(--text-primary) !important;
    background-color: var(--bg-card) !important;
    box-shadow: var(--shadow-sm) !important;
}

/* ══════════════════════════════════════
   LOGIN PAGE HELPERS
   ══════════════════════════════════════ */
.login-label {
    font-size: 11px;
    font-weight: 500;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin: 0 0 6px 0;
    font-family: var(--font);
    text-align: center;
}
.login-hint {
    font-size: 12px;
    color: var(--text-tertiary);
    margin: 4px 0 20px 0;
    line-height: 1.4;
    font-family: var(--font);
    text-align: center;
}
.login-error {
    color: var(--danger);
    font-size: 12px;
    margin: 4px 0 0 0;
    font-family: var(--font);
    text-align: center;
}
.login-footer {
    text-align: center;
    color: #c0c0c0;
    font-size: 11px;
    margin-top: 32px;
    font-family: var(--font);
}

/* Spinner */
.stSpinner > div {
    border-top-color: var(--accent) !important;
}
</style>
<script src="https://unpkg.com/lucide@latest"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    if (typeof lucide !== 'undefined') { lucide.createIcons(); }
});
// Re-run on Streamlit rerenders
const _lucideObs = new MutationObserver(function() {
    if (typeof lucide !== 'undefined') { lucide.createIcons(); }
});
_lucideObs.observe(document.body, { childList: true, subtree: true });
</script>
"""

# Lucide icon SVGs for inline use (no JS dependency needed)
LUCIDE = {
    "layout-dashboard": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>',
    "bar-chart-3": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>',
    "package-search": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l2-1.14"/><path d="m7.5 4.27 9 5.15"/><polyline points="3.29 7 12 12 20.71 7"/><line x1="12" x2="12" y1="22" y2="12"/><circle cx="18.5" cy="15.5" r="2.5"/><path d="M20.27 17.27 22 19"/></svg>',
    "shield-check": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>',
    "truck": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 18V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v11a1 1 0 0 0 1 1h2"/><path d="M15 18h2a1 1 0 0 0 1-1v-3.65a1 1 0 0 0-.22-.624l-3.48-4.35A1 1 0 0 0 13.52 8H14"/><circle cx="17" cy="18" r="2"/><circle cx="7" cy="18" r="2"/></svg>',
    "globe": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>',
    "file-text": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>',
    "dollar-sign": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" x2="12" y1="2" y2="22"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>',
    "chevron-down": '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>',
    "chevron-right": '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>',
    "sparkles": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/><path d="M20 3v4"/><path d="M22 5h-4"/><path d="M4 17v2"/><path d="M5 18H3"/></svg>',
    "database": '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>',
    "upload": '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/></svg>',
    "home": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
}


def inject_custom_css(st_ref):
    """Inject the light theme CSS + Lucide icons."""
    st_ref.markdown(CUSTOM_CSS, unsafe_allow_html=True)
