"""
StackForge UI — Premium light theme.
All CSS in one place. Called via inject_custom_css(st) at the top of app.py.
"""

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&display=swap');

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
    max-width: 70%;
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
    max-width: 85%;
    font-size: 14px;
    line-height: 1.6;
    word-wrap: break-word;
    font-family: var(--font);
    box-shadow: var(--shadow-sm);
}

/* ══════════════════════════════════════
   CHAT-DOMINANT LAYOUT
   ══════════════════════════════════════ */

/* Main content — constrain width like ChatGPT for readability */
.stMainBlockContainer {
    max-width: 780px !important;
    margin: 0 auto !important;
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
    background-color: var(--bg-card) !important;
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    border: none !important;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0 !important;
    padding: 12px 16px !important;
}
/* Fix the expander toggle marker/arrow — prevent garbled text */
.stExpander summary::marker,
[data-testid="stExpander"] summary::marker,
details summary::marker {
    content: "" !important;
    display: none !important;
}
.stExpander summary::-webkit-details-marker,
[data-testid="stExpander"] summary::-webkit-details-marker,
details summary::-webkit-details-marker {
    display: none !important;
}
/* Ensure the expand/collapse icon inside summary is visible and clean */
.stExpander summary svg,
[data-testid="stExpander"] summary svg {
    display: inline-block !important;
    visibility: visible !important;
    width: 16px !important;
    height: 16px !important;
    flex-shrink: 0 !important;
    margin-right: 6px !important;
    color: var(--text-tertiary) !important;
}
/* Fix the summary span text — prevent overlap */
.stExpander summary span,
[data-testid="stExpander"] summary span {
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
}
.stExpander summary:hover,
[data-testid="stExpander"] summary:hover {
    background-color: var(--bg-hover) !important;
    background: var(--bg-hover) !important;
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
    border-left: 3px solid var(--accent) !important;
    border-radius: var(--radius-md) !important;
    padding: 16px 20px !important;
    animation: fadeInUp 0.3s ease forwards;
    box-shadow: var(--shadow-sm) !important;
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
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 500;
    font-family: var(--font);
}
.gov-pass {
    background-color: rgba(22, 163, 74, 0.06);
    border: 1px solid rgba(22, 163, 74, 0.15);
    color: var(--success);
}
.gov-fail {
    background-color: rgba(220, 38, 38, 0.06);
    border: 1px solid rgba(220, 38, 38, 0.15);
    color: var(--danger);
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
"""


def inject_custom_css(st_ref):
    """Inject the light theme CSS."""
    st_ref.markdown(CUSTOM_CSS, unsafe_allow_html=True)
