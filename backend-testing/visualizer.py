from pathlib import Path
import json

import streamlit as st
import streamlit.components.v1 as components

try:
    import plotly.io as pio
except Exception:
    pio = None


OUTPUTS_DIR = Path(__file__).resolve().parent / "outputs"
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".svg"}
HTML_EXTS = {".html", ".htm"}
PLOTLY_JSON_EXTS = {".json"}


def list_graph_files(directory: Path):
    if not directory.exists():
        return []

    files = [
        p for p in directory.iterdir()
        if p.is_file() and (p.suffix.lower() in IMAGE_EXTS | HTML_EXTS | PLOTLY_JSON_EXTS)
    ]
    return sorted(files, key=lambda p: p.name.lower())


def show_file(path: Path):
    ext = path.suffix.lower()
    st.subheader(path.name)

    if ext in IMAGE_EXTS:
        st.image(str(path), use_container_width=True)
        return

    if ext in HTML_EXTS:
        html = path.read_text(encoding="utf-8", errors="ignore")
        components.html(html, height=700, scrolling=True)
        return

    if ext in PLOTLY_JSON_EXTS:
        if pio is None:
            st.warning("检测到 Plotly JSON，但未安装 plotly。请先安装：pip install plotly")
            return
        try:
            fig = pio.from_json(path.read_text(encoding="utf-8"))
            st.plotly_chart(fig, use_container_width=True)
        except json.JSONDecodeError:
            st.error("JSON 文件解析失败。")
        except Exception as e:
            st.error(f"渲染失败: {e}")


def main():
    st.set_page_config(page_title="Graph Visualizer", layout="wide")
    st.title("Outputs Graph Visualizer")
    st.caption(f"目录: {OUTPUTS_DIR}")

    files = list_graph_files(OUTPUTS_DIR)
    if not OUTPUTS_DIR.exists():
        st.error(f"未找到 outputs 目录: {OUTPUTS_DIR}")
        return

    if not files:
        st.info("outputs 目录中未找到可显示的图表文件。")
        return

    cols = st.columns(2)
    for i, f in enumerate(files):
        with cols[i % 2]:
            show_file(f)
            st.divider()


if __name__ == "__main__":
    main()