import streamlit as st
import pandas as pd
import os
import io
import json

import config as cfg
from modules import ingestion, markov_engine, context_engine, baseline_manager as bm
from views import main_dashboard, detail_view, training_view, config_view, results_view

st.set_page_config(page_title="Markov chain Analysis", layout="wide", page_icon="🛡️")

# Re-apply Config tab overrides on every rerun so they survive page switches.
if 'cfg_overrides' in st.session_state:
    for k, v in st.session_state.cfg_overrides.items():
        setattr(cfg, k, v)

# Global styles
st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 5px; font-weight: bold; }
    .metric-card { background-color: #0e1117; border: 1px solid #30333F; padding: 15px; border-radius: 8px; }

    /* Light gray sidebar, distinct from the dark main canvas */
    section[data-testid="stSidebar"] {
        background: #e9ecf1;
        border-right: 1px solid #d2d7df;
    }
    /* Dark text inside the light sidebar so headings stay readable */
    section[data-testid="stSidebar"] h3,
    section[data-testid="stSidebar"] .sidebar-footer {
        color: #2a2f3a;
    }

    /* Highlighted accent stripe shown when the sidebar is collapsed. */
    button[data-testid="stSidebarCollapsedControl"] {
        border-left: 4px solid #4c8bf5 !important;
        box-shadow: 2px 0 12px rgba(76,139,245,0.4);
    }

    /* Nav buttons: real toggle buttons, full width, on the light background. */
    .nav-btn button {
        text-align: left !important;
        background: transparent;
        border: 1px solid transparent;
        color: #3a4150;
        transition: background .15s ease, border-color .15s ease;
    }
    .nav-btn button:hover {
        background: #dce1e9;
        border-color: #c2c8d2;
    }
    /* Active tab: filled blue so it is obvious which page you are on. */
    .nav-btn-active button {
        background: #4c8bf5 !important;
        border-color: #4c8bf5 !important;
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* "Made By Danny" footer pinned to the bottom of the open sidebar. */
    .sidebar-footer {
        position: fixed;
        bottom: 14px;
        width: inherit;
        text-align: center;
        font-size: 0.78rem;
        color: #6c727e;
        letter-spacing: 0.5px;
    }
</style>
""", unsafe_allow_html=True)

# Session state
if 'master_df' not in st.session_state:
    st.session_state.master_df = None
if 'selected_row' not in st.session_state:
    st.session_state.selected_row = None
if 'active_context' not in st.session_state:
    st.session_state.active_context = {"file": False, "net": False}
if 'operating_threshold' not in st.session_state:
    st.session_state.operating_threshold = None
if 'page' not in st.session_state:
    st.session_state.page = "Detect"
if 'markov_order' not in st.session_state:
    st.session_state.markov_order = 2
if 'has_run' not in st.session_state:
    st.session_state.has_run = False
# file_uploader returns None after switching pages, so keep the bytes here.
if 'uploaded' not in st.session_state:
    st.session_state.uploaded = {"proc": None, "file": None, "net": None}


def baseline_exists(stream, suffix=None):
    """Check a baseline exists for the stream (newest one if no suffix)."""
    if stream not in ("process", "file", "net"):
        return False
    if suffix is None:
        suffix = bm.newest_suffix(stream)
    return bm.has_baseline(stream, suffix)


def info_icon(text):
    """Small 'i' icon with a CSS hover tooltip."""
    safe = text.replace('"', "&quot;")
    return (f'<span style="display:inline-flex;align-items:center;justify-content:center;'
            f'width:15px;height:15px;border-radius:50%;border:1px solid #4a515f;color:#9aa1ad;'
            f'font-size:.62rem;font-style:italic;font-weight:700;cursor:help;position:relative;'
            f'font-family:Georgia,serif;margin-left:6px;" class="ttip">i'
            f'<span style="visibility:hidden;opacity:0;width:240px;background:#1d2330;color:#d7dbe2;'
            f'text-align:left;border:1px solid #333b4a;border-radius:8px;padding:9px 11px;font-size:.74rem;'
            f'font-style:normal;font-weight:400;line-height:1.35;position:absolute;z-index:60;bottom:150%;'
            f'left:50%;transform:translateX(-50%);box-shadow:0 6px 20px rgba(0,0,0,.5);pointer-events:none;" '
            f'class="ttip-text">{safe}</span></span>')


st.markdown("""
<style>
.ttip:hover .ttip-text { visibility:visible !important; opacity:1 !important; }
.ttip:hover { background:#4c8bf5; color:#fff; border-color:#4c8bf5; }
</style>
""", unsafe_allow_html=True)


def compute_total(df, has_file, has_net):
    """ALPHA * markov + BETA * context.

    Context is averaged over the streams present so BETA isn't doubled.
    """
    context_parts = []
    if has_file and 'Score_File' in df.columns:
        context_parts.append(df['Score_File'])
    if has_net and 'Score_Net' in df.columns:
        context_parts.append(df['Score_Net'])
    context_score = sum(context_parts) / len(context_parts) if context_parts else 0.0
    return cfg.ALPHA * df['Score_Markov'] + cfg.BETA * context_score


def mode_selector(label, stream, key, suffix=None):
    """Self-Learning / Baseline radio. Baseline only shows if one exists."""
    have_baseline = baseline_exists(stream, suffix)

    self_label = "Self-Learning (Ad-Hoc)"
    base_label = "Baseline Comparison (Standard)"

    st.markdown(
        f'<div style="display:flex;align-items:center;">{label}'
        f'{info_icon("Self-Learning trains on the uploaded batch itself and flags internal outliers. Good for triaging an unknown host, but malicious activity that repeats can hide. Baseline Comparison scores against a pre-trained benign model, giving the most reliable alerts.")}'
        f'</div>',
        unsafe_allow_html=True
    )

    if have_baseline:
        choice = st.radio(
            label, (self_label, base_label),
            key=key, label_visibility="collapsed"
        )
    else:
        choice = st.radio(
            label, (self_label,),
            key=key, label_visibility="collapsed", index=0
        )
        st.caption("Baseline Comparison unlocks once you train a baseline for this stream in the Training tab.")

    return choice


def cache_upload(slot, uploaded_file):
    """Cache the upload in session state and return it as a BytesIO (or None)."""
    if uploaded_file is not None:
        st.session_state.uploaded[slot] = {
            "name": uploaded_file.name,
            "bytes": uploaded_file.getvalue(),
        }
    cached = st.session_state.uploaded.get(slot)
    if not cached:
        return None
    buf = io.BytesIO(cached["bytes"])
    buf.name = cached["name"]
    return buf


def reset_detection_state():
    """Clear results and uploads. Dropping the widget keys empties the pickers."""
    st.session_state.master_df = None
    st.session_state.selected_row = None
    st.session_state.active_context = {"file": False, "net": False}
    st.session_state.operating_threshold = None
    st.session_state.has_run = False
    st.session_state.uploaded = {"proc": None, "file": None, "net": None}
    for k in ("u_proc", "u_file", "u_net"):
        if k in st.session_state:
            del st.session_state[k]


def render_detection_page():
    if st.session_state.master_df is not None and st.session_state.selected_row is not None:
        detail_view.render_detail_view(st.session_state.selected_row, st.session_state.master_df)
        return

    with st.container():
        st.title("🛡️ Context-Aware Weighted Markov Chain Analysis")
        st.caption("Each stream can be scored against its own baseline, and you may mix baselines from different training runs.")

        def baseline_picker(role, key):
            items = bm.list_baselines(role)
            if not items:
                return None
            options = list(range(len(items)))
            captions = []
            for it in items:
                when = it["modified"].strftime("%Y-%m-%d %H:%M:%S") if it["modified"] else "unknown"
                captions.append(f"{when}")
            idx = st.selectbox(
                "Baseline", options=options, format_func=lambda i: captions[i],
                index=0, key=key,
                help="Which trained baseline to use for this stream. Newest first."
            )
            return items[idx]["suffix"]

        def stream_controls(label, role, mode_key, picker_key):
            mode = mode_selector(label, role, mode_key)
            suffix = None
            if "Baseline" in mode:
                suffix = baseline_picker(role, picker_key)
            return mode, suffix

        c1, c2, c3 = st.columns(3)

        with c1:
            st.subheader("1. Process Spine (Required)")
            up_proc = st.file_uploader("Upload Process CSV", type=['csv'], key="u_proc")
            f_proc = cache_upload("proc", up_proc)
            mode_proc, suffix_proc = stream_controls("Process Analysis Mode", "process", "m_proc", "b_proc")

        with c2:
            st.subheader("2. File Context (Optional)")
            up_file = st.file_uploader("Upload File CSV", type=['csv'], key="u_file")
            f_file = cache_upload("file", up_file)
            mode_file, suffix_file = stream_controls("File Analysis Mode", "file", "m_file", "b_file")

        with c3:
            st.subheader("3. Network Context (Optional)")
            up_net = st.file_uploader("Upload Network CSV", type=['csv'], key="u_net")
            f_net = cache_upload("net", up_net)
            mode_net, suffix_net = stream_controls("Network Analysis Mode", "net", "m_net", "b_net")

        # the uploader looks empty after a page switch, so show what's cached
        held = [s for s in ("proc", "file", "net") if st.session_state.uploaded.get(s)]
        if held:
            names = ", ".join(st.session_state.uploaded[s]["name"] for s in held)
            st.caption(f"Loaded and held for this session: {names}")

        st.divider()

        st.markdown(
            f'<div style="display:flex;align-items:center;">Markov Order'
            f'{info_icon("First-order models the Parent to Child transition only. Second-order adds the grandparent (Grandparent to Parent to Child), giving more lineage context at the cost of a larger state space.")}'
            f'</div>',
            unsafe_allow_html=True
        )
        order_label = st.radio(
            "Markov Order",
            ("Second-order (Grandparent \u2192 Parent \u2192 Child)", "First-order (Parent \u2192 Child)"),
            index=0 if st.session_state.markov_order == 2 else 1,
            key="markov_order_radio",
            label_visibility="collapsed",
            horizontal=True,
        )
        st.session_state.markov_order = 1 if order_label.startswith("First") else 2

        st.divider()

        btn_label = "🔁 RECALCULATE" if st.session_state.has_run else "🚀 START CALCULATION"
        bc1, bc2 = st.columns([3, 1])
        with bc1:
            run_btn = st.button(btn_label, type="primary", width='stretch')
        with bc2:
            reset_btn = st.button("♻️ Reset", width='stretch')

        if reset_btn:
            reset_detection_state()
            st.rerun()

    if run_btn:
        if f_proc is None:
            st.error("❌ Process Data is required to build the activity spine.")
            st.stop()

        with st.status("⚙️ Running Hybrid Pipeline...", expanded=True):
            st.write("1️⃣ Ingesting and Merging Data...")
            master_df = ingestion.process_and_merge_data(f_proc, f_file, f_net)

            order = st.session_state.markov_order
            st.write(f"2️⃣ Scoring Process Lineage ({'first' if order == 1 else 'second'}-order)...")
            proc_model = None
            operating_threshold = None
            if "Baseline" in mode_proc:
                markov_records = bm.load_baseline("process", suffix_proc) if suffix_proc else None
                if markov_records is not None:
                    proc_model = pd.DataFrame(markov_records)
                    st.info(f"   - Using process baseline from {suffix_proc}.")
                    # stored 95th percentile is the operating point, Results tab reuses it
                    thr = bm.load_threshold(suffix_proc) or {}
                    operating_threshold = thr.get("markov_95th_threshold")
                else:
                    st.warning("   ⚠️ Baseline not found. Falling back to Self-Learning.")
                    proc_model = markov_engine.train_markov_model(master_df, order=order)
            else:
                proc_model = markov_engine.train_markov_model(master_df, order=order)

            # self-learning, or baseline without a stored threshold
            if operating_threshold is None:
                operating_threshold = float(markov_engine.calculate_percentile_threshold(proc_model, 95))

            p_scores, _ = markov_engine.run_markov_scoring(master_df, baseline_model=proc_model)
            master_df['Score_Markov'] = p_scores

            master_df['Score_File'] = 0.0
            if f_file:
                st.write("3️⃣ Scoring File Context...")
                file_weights = None
                if "Baseline" in mode_file:
                    file_weights = bm.load_baseline("file", suffix_file) if suffix_file else None
                f_scores, _ = context_engine.run_context_scoring(
                    master_df, primary_col=cfg.FILE_SCORING_FIELD,
                    fallback_col=cfg.FILE_SCORING_FALLBACK, weights=file_weights)
                master_df['Score_File'] = f_scores

            master_df['Score_Net'] = 0.0
            if f_net:
                st.write("4️⃣ Scoring Network Context...")
                net_weights = None
                if "Baseline" in mode_net:
                    net_weights = bm.load_baseline("net", suffix_net) if suffix_net else None
                n_scores, _ = context_engine.run_context_scoring(
                    master_df, primary_col=cfg.NET_SCORING_FIELD,
                    fallback_col=cfg.NET_SCORING_FALLBACK, weights=net_weights)
                master_df['Score_Net'] = n_scores

            st.session_state.active_context = {"file": bool(f_file), "net": bool(f_net)}
            master_df['TotalScore'] = compute_total(master_df, bool(f_file), bool(f_net))

            st.session_state.master_df = master_df
            st.session_state.operating_threshold = operating_threshold
            st.session_state.selected_row = None
            st.session_state.has_run = True
            st.rerun()

    if st.session_state.master_df is not None:
        df = st.session_state.master_df
        ctx = st.session_state.active_context
        df['TotalScore'] = compute_total(df, ctx["file"], ctx["net"])
        main_dashboard.render_dashboard(df)


# Sidebar
def nav_button(label, page_key):
    active = st.session_state.page == page_key
    wrapper = "nav-btn nav-btn-active" if active else "nav-btn"
    st.markdown(f'<div class="{wrapper}">', unsafe_allow_html=True)
    if st.button(label, key=f"nav_{page_key}", width='stretch'):
        st.session_state.page = page_key
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)


with st.sidebar:
    st.markdown("### 🛡️ Markov chain Analysis")
    st.divider()
    nav_button("🔍  Detect", "Detect")
    nav_button("🎓  Train", "Train")
    nav_button("📊  Results", "Results")
    nav_button("⚙️  Config", "Config")
    st.markdown('<div class="sidebar-footer">Made By Danny</div>', unsafe_allow_html=True)

# Page router
if st.session_state.page == "Train":
    training_view.render_training_view()
elif st.session_state.page == "Config":
    config_view.render_config_view()
elif st.session_state.page == "Results":
    results_view.render_results_view()
else:
    render_detection_page()