"""
StackForge UI — Light theme, chat-centric layout.
All CSS in one place. Called via inject_custom_css(st) at the top of app.py.
"""

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg-page: #fafafa;
    --bg-sidebar: #ffffff;
    --bg-card: #ffffff;
    --bg-hover: #f3f4f6;
    --border: #e5e7eb;
    --accent: #111111;
    --success: #16a34a;
    --warning: #d97706;
    --danger: #dc2626;
    --text-primary: #111111;
    --text-secondary: #6b7280;
    --text-tertiary: #9ca3af;
    --text-body: #374151;
    --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

/* ── Global ── */
html, body, .stApp, [data-testid="stAppViewContainer"],
[data-testid="stAppViewBlockContainer"] {
    background-color: var(--bg-page) !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
}
#MainMenu, footer, header[data-testid="stHeader"] { visibility: hidden; }
[data-testid="stHeader"] { background-color: var(--bg-page) !important; }
[data-testid="stMain"] > div { background-color: var(--bg-page) !important; }
h1, h2, h3, h4, h5, h6 { color: var(--text-primary) !important; font-family: var(--font) !important; }
p, span, label, li, div { font-family: var(--font) !important; }

/* ══════════════════════════════════════
   SIDEBAR (260px control panel)
   ══════════════════════════════════════ */
section[data-testid="stSidebar"] {
    background-color: var(--bg-sidebar) !important;
    border-right: 1px solid var(--border) !important;
    width: 260px !important;
    min-width: 260px !important;
}
section[data-testid="stSidebar"] > div {
    background-color: var(--bg-sidebar) !important;
    padding-top: 12px !important;
    padding-bottom: 40px !important;
}
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] .stMarkdown span,
section[data-testid="stSidebar"] label {
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
}

/* ── Sidebar template buttons ── */
section[data-testid="stSidebar"] .stButton > button {
    background-color: transparent !important;
    border: none !important;
    color: var(--text-body) !important;
    border-radius: 6px !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
    font-size: 13px !important;
    padding: 5px 10px !important;
    text-align: left !important;
    justify-content: flex-start !important;
    transition: background-color 0.1s ease !important;
    transform: none !important;
    box-shadow: none !important;
    min-height: 30px !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background-color: var(--bg-hover) !important;
    color: var(--text-primary) !important;
    transform: none !important;
    box-shadow: none !important;
}

/* ── Engine toggle ── */
[data-testid="stToggle"] label span {
    color: var(--text-secondary) !important;
    font-size: 12px !important;
}

/* ══════════════════════════════════════
   BUTTONS
   ══════════════════════════════════════ */

/* Default: text-link style (for "Try" and other inline actions) */
.stButton > button {
    background-color: transparent !important;
    color: var(--text-secondary) !important;
    border: none !important;
    border-radius: 4px !important;
    font-family: var(--font) !important;
    font-weight: 400 !important;
    font-size: 13px !important;
    padding: 4px 8px !important;
    transition: color 0.1s ease !important;
    transform: none !important;
    box-shadow: none !important;
}
.stButton > button:hover {
    color: var(--text-primary) !important;
    background-color: transparent !important;
    transform: none !important;
    box-shadow: none !important;
}

/* Primary: black filled (for login, CTAs) */
[data-testid="baseButton-primary"] {
    background-color: var(--accent) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 6px !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 13px !important;
    padding: 8px 20px !important;
    transition: background-color 0.1s ease !important;
}
[data-testid="baseButton-primary"]:hover {
    background-color: #374151 !important;
}

/* ══════════════════════════════════════
   CHAT MESSAGES (center area)
   ══════════════════════════════════════ */
.msg-user-wrap {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    margin: 16px 0;
}
.msg-asst-wrap {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    margin: 16px 0;
}
.msg-label {
    font-size: 11px;
    color: var(--text-tertiary);
    margin-bottom: 4px;
    font-family: var(--font);
    font-weight: 500;
}
.msg-user {
    background: #f3f4f6;
    color: var(--text-primary);
    border-radius: 12px 12px 2px 12px;
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
    border-radius: 12px 12px 12px 2px;
    padding: 12px 16px;
    max-width: 85%;
    font-size: 14px;
    line-height: 1.6;
    word-wrap: break-word;
    font-family: var(--font);
}
.msg-ts {
    font-size: 10px;
    color: var(--text-tertiary);
    margin-top: 4px;
}

/* ══════════════════════════════════════
   INLINE DASHBOARD (in chat)
   ══════════════════════════════════════ */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: var(--border) !important;
    border-radius: 12px !important;
    background-color: var(--bg-card) !important;
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
    border-radius: 6px !important;
    font-family: var(--font) !important;
    font-size: 13px !important;
}
.stSelectbox > div > div:focus-within,
.stTextArea textarea:focus,
.stTextInput input:focus,
[data-testid="stChatInput"] textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: none !important;
}
[data-testid="stChatInput"] {
    background-color: var(--bg-page) !important;
    border-top: none !important;
}
[data-testid="stChatInput"] > div {
    background-color: #ffffff !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
}
[data-testid="stChatInput"] textarea {
    border: none !important;
    border-radius: 12px !important;
}
[data-testid="stChatInput"] textarea::placeholder { color: var(--text-tertiary) !important; }
[data-testid="stChatInput"] button {
    background-color: transparent !important;
    color: var(--text-tertiary) !important;
    border: none !important;
}
[data-testid="stChatInput"] button:hover { color: var(--accent) !important; }

/* ══════════════════════════════════════
   METRICS
   ══════════════════════════════════════ */
[data-testid="stMetric"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-left: 3px solid var(--accent) !important;
    border-radius: 8px !important;
    padding: 16px 20px !important;
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
    border-radius: 8px !important;
    overflow: hidden !important;
}
.streamlit-expanderHeader {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    color: var(--text-primary) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 13px !important;
}
.streamlit-expanderContent {
    background-color: #f9fafb !important;
    border: 1px solid var(--border) !important;
    border-top: none !important;
    border-radius: 0 0 6px 6px !important;
}
details summary { color: var(--text-primary) !important; }
.stCodeBlock, pre, code {
    background-color: #1e1e2e !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    font-size: 12px !important;
}
[data-testid="stAlert"] {
    border-radius: 6px !important;
    font-family: var(--font) !important;
    font-size: 13px !important;
}

/* ══════════════════════════════════════
   TABS
   ══════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    gap: 0 !important;
    background-color: var(--bg-card) !important;
    border-radius: 6px !important;
    padding: 3px !important;
    border: 1px solid var(--border) !important;
}
.stTabs [data-baseweb="tab-list"] button {
    border-radius: 4px !important;
    color: var(--text-secondary) !important;
    font-family: var(--font) !important;
    font-weight: 500 !important;
    font-size: 12px !important;
    padding: 5px 14px !important;
    border-bottom: none !important;
}
.stTabs [aria-selected="true"] {
    background-color: var(--accent) !important;
    color: #ffffff !important;
}

/* ══════════════════════════════════════
   PLOTLY
   ══════════════════════════════════════ */
[data-testid="stPlotlyChart"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 8px !important;
}

/* ══════════════════════════════════════
   GOVERNANCE BADGES
   ══════════════════════════════════════ */
.gov-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
    font-family: var(--font);
}
.gov-pass {
    background-color: rgba(22, 163, 74, 0.06);
    border: 1px solid rgba(22, 163, 74, 0.2);
    color: var(--success);
}
.gov-fail {
    background-color: rgba(220, 38, 38, 0.06);
    border: 1px solid rgba(220, 38, 38, 0.2);
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
}
.welcome-title {
    font-size: 2.8rem;
    margin-bottom: 8px;
    font-family: var(--font);
    line-height: 1.1;
    color: var(--text-primary);
}
.welcome-title .t-stack { font-weight: 700; }
.welcome-title .t-forge { font-weight: 400; }
.welcome-sub {
    color: var(--text-secondary);
    font-size: 16px;
    font-weight: 400;
    max-width: 440px;
    line-height: 1.6;
    font-family: var(--font);
    margin-bottom: 2rem;
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
    border-radius: 8px;
    padding: 20px;
    flex: 1;
    min-width: 190px;
    max-width: 230px;
    text-align: left;
    transition: border-color 0.12s ease;
}
.feature-card:hover { border-color: #d1d5db; }
.feature-label {
    font-weight: 600;
    font-size: 14px;
    color: var(--text-primary);
    margin-bottom: 4px;
    font-family: var(--font);
}
.feature-desc {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
    font-family: var(--font);
    font-weight: 400;
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
   SIDEBAR PIECES
   ══════════════════════════════════════ */
.sidebar-brand {
    font-weight: 700;
    font-size: 16px;
    color: var(--text-primary);
    font-family: var(--font);
    padding: 2px 0 8px 0;
}
.section-label {
    font-size: 11px;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 500;
    font-family: var(--font);
    margin-bottom: 6px;
}
.sidebar-footer {
    position: fixed;
    bottom: 0;
    width: 260px;
    padding: 8px 12px;
    background-color: var(--bg-sidebar);
    border-top: 1px solid var(--border);
    border-right: 1px solid var(--border);
    font-size: 10px;
    color: var(--text-tertiary);
    text-align: center;
    font-family: var(--font);
}

/* ══════════════════════════════════════
   LOGIN PAGE
   ══════════════════════════════════════ */
.login-title {
    text-align: center;
    padding-top: 10vh;
    margin-bottom: 2rem;
}
.login-title h1 {
    font-size: 2rem !important;
    font-weight: 700 !important;
    margin-bottom: 4px !important;
}
.login-title .t-stack { font-weight: 700; }
.login-title .t-forge { font-weight: 400; }
.login-sub {
    color: var(--text-secondary);
    font-size: 14px;
    font-weight: 400;
}
.login-error {
    color: #dc2626;
    font-size: 12px;
    margin: 4px 0 0 0;
    font-family: var(--font);
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
    border-top: 1px solid #e5e7eb !important;
    opacity: 1 !important;
    margin: 12px 0 !important;
}

[data-testid="stJson"] {
    background-color: #1e1e2e !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
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

.input-hint {
    text-align: center;
    color: var(--text-tertiary);
    font-size: 11px;
    font-family: var(--font);
    margin: 8px 0 4px;
}
</style>
"""


def inject_custom_css(st_ref):
    """Inject the light theme CSS."""
    st_ref.markdown(CUSTOM_CSS, unsafe_allow_html=True)
