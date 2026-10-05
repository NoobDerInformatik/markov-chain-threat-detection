import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
import json
import os

import config as cfg
from modules import ingestion, markov_engine, context_engine, baseline_manager as bm


# same card styling as the detection dashboard
_TRAIN_CSS = """
<style>
    @keyframes cawmc_rise { 0% { opacity:0; transform:translateY(12px);} 100% { opacity:1; transform:translateY(0);} }
    .stat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:6px 0; }
    @media (max-width:900px){ .stat-grid{ grid-template-columns:repeat(2,1fr);} }
    .stat-card {
        background:linear-gradient(160deg,#161b26 0%,#0e1117 100%);
        border:1px solid #262b38; border-top:3px solid var(--accent,#4c8bf5);
        border-radius:12px; padding:16px; animation:cawmc_rise .45s ease both;
    }
    .stat-label { font-size:.7rem; letter-spacing:1.2px; text-transform:uppercase; color:#8a909c; margin:0; }
    .stat-value { font-size:1.7rem; font-weight:700; color:#f3f5f8; margin:6px 0 0 0; line-height:1.1; }
    .stat-sub { font-size:.72rem; color:#6c727e; margin:4px 0 0 0; }
</style>
"""


def _stat_card(label, value, sub, accent):
    return (
        f'<div class="stat-card" style="--accent:{accent};">'
        f'<p class="stat-label">{label}</p>'
        f'<p class="stat-value">{value}</p>'
        f'<p class="stat-sub">{sub}</p>'
        f'</div>'
    )


def _save_json(data, path):
    bm.ensure_dir()
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)


def _prepare_process_df(raw_df):
    """Same normalisation as the live pipeline, so scores line up."""
    df = raw_df.copy()
    if 'pid' in df.columns and 'ppid' in df.columns:
        df['pid'] = ingestion.clean_pid(df['pid'])
        df['ppid'] = ingestion.clean_pid(df['ppid'])
    df['DeviceName'] = df['DeviceName'].astype(str)

    for col in [cfg.COL_PROC_NAME, cfg.COL_PARENT_NAME]:
        if col in df.columns:
            df[col] = (df[col].fillna('system_root')
                       .replace(['nan', '0', 'None'], 'system_root').astype(str))

    if 'ppid' in df.columns and 'pid' in df.columns:
        df = ingestion.derive_grandparent_column(df)
    else:
        df[cfg.COL_GRANDPARENT_NAME] = 'system_root'
    return df


def _render_process_stats(model_df, df, threshold):
    gp, p, c = cfg.COL_GRANDPARENT_NAME, cfg.COL_PARENT_NAME, cfg.COL_PROC_NAME

    n_triplets = len(model_df)
    n_parents = df[p].nunique()
    n_children = df[c].nunique()
    cards = (
        _stat_card("Training Rows", f"{len(df):,}", "Process events ingested", "#4c8bf5")
        + _stat_card("Distinct Triplets", f"{n_triplets:,}", "Grandparent to parent to child", "#a06bf0")
        + _stat_card("Unique Parents", f"{n_parents:,}", "Distinct parent processes", "#26c0a0")
        + _stat_card("95th Pct Threshold", f"{threshold:.2f}", "Alerting boundary (bits)", "#e5484d")
    )
    st.markdown(f'<div class="stat-grid">{cards}</div>', unsafe_allow_html=True)
    st.divider()

    st.subheader("Score Distribution")
    st.caption("How rare each benign transition is, weighted by how often it occurred. The line marks the 95th percentile alerting threshold.")
    if 'Count' in model_df.columns:
        scores = np.repeat(model_df['Score'].values, model_df['Count'].values.astype(int))
    else:
        scores = model_df['Score'].values
    hist_df = pd.DataFrame({'Score (bits)': scores})

    hist = alt.Chart(hist_df).mark_bar(opacity=0.85, color='#4c8bf5').encode(
        x=alt.X('Score (bits):Q', bin=alt.Bin(maxbins=40), title='Information content (bits)'),
        y=alt.Y('count()', title='Benign transitions')
    )
    rule = alt.Chart(pd.DataFrame({'t': [threshold]})).mark_rule(
        color='#e5484d', strokeDash=[6, 4], size=2
    ).encode(x='t:Q')
    st.altair_chart((hist + rule).properties(height=280), width='stretch')
    st.divider()

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Noisiest Parents")
        st.caption("Parents that spawn the widest variety of children. High branching means a surprise child is penalized more gently.")
        branching = (df.groupby(p)[c].nunique()
                     .sort_values(ascending=False).head(10)
                     .reset_index())
        branching.columns = ['Parent Process', 'Distinct Children']
        st.dataframe(branching, width='stretch', hide_index=True)
    with col_b:
        st.subheader("Rarest Transitions")
        st.caption("The highest-scoring benign lineages. These sit closest to the alerting boundary.")
        rarest = (model_df.sort_values('Score', ascending=False)
                  .head(10)[[gp, p, c, 'Score']].copy())
        rarest['Score'] = rarest['Score'].round(2)
        rarest.columns = ['Grandparent', 'Parent', 'Child', 'Score']
        st.dataframe(rarest, width='stretch', hide_index=True)


def _render_weight_table(weights_dict, title, unit_label):
    st.subheader(title)
    unknown = weights_dict.get('__UNKNOWN__')
    rows = [(k, v) for k, v in weights_dict.items() if k != '__UNKNOWN__']
    if unknown is not None:
        st.caption(f"Unseen artifacts score {unknown:.2f} bits. Showing {len(rows)} learned artifacts.")

    wdf = pd.DataFrame(rows, columns=['Artifact', 'Weight (bits)'])
    wdf = wdf.sort_values('Weight (bits)', ascending=False).reset_index(drop=True)

    query = st.text_input(f"Search {unit_label}", key=f"search_{unit_label}", placeholder="type to filter...")
    if query:
        wdf = wdf[wdf['Artifact'].str.contains(query, case=False, na=False)]
    wdf['Weight (bits)'] = wdf['Weight (bits)'].round(2)
    st.dataframe(wdf, width='stretch', hide_index=True, height=320)


@st.dialog("Rename Baseline")
def _rename_dialog(role, suffix):
    st.write(f"Renaming **{bm.STREAM_LABELS[role]} Baseline ({suffix})**")
    new_name = st.text_input("New name", value=suffix, key=f"dlg_rename_{role}_{suffix}")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Cancel", width='stretch', key=f"dlg_cancel_r_{role}_{suffix}"):
            st.rerun()
    with c2:
        if st.button("Save", type="primary", width='stretch', key=f"dlg_save_r_{role}_{suffix}"):
            try:
                bm.rename_baseline(role, suffix, new_name)
                st.rerun()
            except ValueError as e:
                st.error(str(e))


@st.dialog("Delete Baseline")
def _delete_dialog(role, suffix):
    st.write(f"Delete **{bm.STREAM_LABELS[role]} Baseline ({suffix})**? This cannot be undone.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Cancel", width='stretch', key=f"dlg_cancel_d_{role}_{suffix}"):
            st.rerun()
    with c2:
        if st.button("Confirm", type="primary", width='stretch', key=f"dlg_confirm_d_{role}_{suffix}"):
            bm.delete_baseline(role, suffix)
            st.session_state.pop(f"details_{role}_{suffix}", None)
            st.rerun()


def _render_saved_process_insights(suffix):
    """Rebuild the insights from the saved triplet model (raw events aren't kept)."""
    records = bm.load_baseline("process", suffix)
    if not records:
        st.caption("Process model could not be read.")
        return
    model_df = pd.DataFrame(records)

    thresh = bm.load_threshold(suffix) or {}
    sample = thresh.get("training_sample_size")
    cutoff = thresh.get("markov_95th_threshold")

    gp, p, c = cfg.COL_GRANDPARENT_NAME, cfg.COL_PARENT_NAME, cfg.COL_PROC_NAME

    n_triplets = len(model_df)
    n_parents = model_df[p].nunique() if p in model_df.columns else 0
    cards = (
        _stat_card("Training Events", f"{sample:,}" if isinstance(sample, int) else "n/a", "Process events ingested", "#4c8bf5")
        + _stat_card("Distinct Triplets", f"{n_triplets:,}", "Grandparent to parent to child", "#a06bf0")
        + _stat_card("Unique Parents", f"{n_parents:,}", "Distinct parent processes", "#26c0a0")
        + _stat_card("95th Pct Threshold", f"{cutoff:.2f}" if isinstance(cutoff, (int, float)) else "n/a", "Alerting boundary (bits)", "#e5484d")
    )
    st.markdown(f'<div class="stat-grid">{cards}</div>', unsafe_allow_html=True)

    if 'Score' in model_df.columns:
        st.subheader("Score Distribution")
        st.caption("How rare each benign transition is, weighted by how often it occurred. The line marks the 95th percentile alerting threshold.")
        if 'Count' in model_df.columns:
            scores = np.repeat(model_df['Score'].values, model_df['Count'].values.astype(int))
        else:
            scores = model_df['Score'].values
        hist_df = pd.DataFrame({'Score (bits)': scores})
        hist = alt.Chart(hist_df).mark_bar(opacity=0.85, color='#4c8bf5').encode(
            x=alt.X('Score (bits):Q', bin=alt.Bin(maxbins=40), title='Information content (bits)'),
            y=alt.Y('count()', title='Benign transitions')
        )
        if isinstance(cutoff, (int, float)):
            rule = alt.Chart(pd.DataFrame({'t': [cutoff]})).mark_rule(
                color='#e5484d', strokeDash=[6, 4], size=2).encode(x='t:Q')
            st.altair_chart((hist + rule).properties(height=260), width='stretch')
        else:
            st.altair_chart(hist.properties(height=260), width='stretch')

    if {gp, p, c, 'Score'}.issubset(model_df.columns):
        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("Noisiest Parents")
            st.caption("Parents that spawn the widest variety of children.")
            branching = (model_df.groupby(p)[c].nunique()
                         .sort_values(ascending=False).head(10).reset_index())
            branching.columns = ['Parent Process', 'Distinct Children']
            st.dataframe(branching, width='stretch', hide_index=True)
        with col_b:
            st.subheader("Rarest Transitions")
            st.caption("The highest-scoring benign lineages, closest to the alerting boundary.")
            rarest = model_df.sort_values('Score', ascending=False).head(10)[[gp, p, c, 'Score']].copy()
            rarest['Score'] = rarest['Score'].round(2)
            rarest.columns = ['Grandparent', 'Parent', 'Child', 'Score']
            st.dataframe(rarest, width='stretch', hide_index=True)


def _render_baseline_details(role, suffix):
    if role == "process":
        _render_saved_process_insights(suffix)
    else:
        weights = bm.load_baseline(role, suffix) or {}
        title = "📂 Learned File Weights" if role == "file" else "🌐 Learned Network Weights"
        unit = "files" if role == "file" else "network"
        _render_weight_table(weights, title, f"{unit}_{suffix}")


def _render_baseline_manager():
    items = bm.list_baselines()
    st.subheader("Existing Baselines")
    if not items:
        st.caption("No baselines yet. Train one below to get started.")
        return

    st.caption("Every stream is stored as its own baseline. Manage each one independently, and mix streams from different runs in the Detect tab.")
    for b in items:
        role = b["role"]
        suffix = b["suffix"]
        when = b["modified"].strftime("%Y-%m-%d %H:%M:%S") if b["modified"] else "unknown"
        name = f"{bm.STREAM_LABELS[role]} Baseline ({when})"
        key = f"{role}_{suffix}"

        with st.container(border=True):
            c_info, c_d, c_r, c_x = st.columns([4, 1, 1, 1])
            with c_info:
                st.markdown(f"**{name}**")
            with c_d:
                if st.button("Details", key=f"show_{key}", width='stretch'):
                    dk = f"details_{key}"
                    st.session_state[dk] = not st.session_state.get(dk, False)
            with c_r:
                if st.button("Rename", key=f"ren_{key}", width='stretch'):
                    _rename_dialog(role, suffix)
            with c_x:
                if st.button("Delete", key=f"del_{key}", width='stretch'):
                    _delete_dialog(role, suffix)

            if st.session_state.get(f"details_{key}", False):
                st.divider()
                _render_baseline_details(role, suffix)
    st.divider()


def render_training_view():
    st.markdown(_TRAIN_CSS, unsafe_allow_html=True)
    st.title("🎓 Baseline Training")
    st.caption("Upload benign telemetry to build the gold-standard model the detector compares against. Train any combination of the three streams.")
    st.divider()

    _render_baseline_manager()

    st.subheader("Train a New Baseline")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.subheader("1. Process (Spine)")
        f_proc = st.file_uploader("Benign Process CSV", type=['csv'], key="tr_proc")
    with c2:
        st.subheader("2. File (Optional)")
        f_file = st.file_uploader("Benign File CSV", type=['csv'], key="tr_file")
    with c3:
        st.subheader("3. Network (Optional)")
        f_net = st.file_uploader("Benign Network CSV", type=['csv'], key="tr_net")

    st.divider()
    train_btn = st.button("🧠 TRAIN BASELINES", type="primary", width='stretch')

    if not train_btn:
        return
    if not f_proc:
        st.error("❌ A benign process file is required to train the Markov baseline.")
        return

    # --- process baseline ---
    with st.status("Training baselines...", expanded=True):
        st.write("Reading and normalizing process telemetry...")
        raw = ingestion.load_csv_safe(f_proc)
        if raw is None:
            st.error("Could not read the process CSV.")
            return
        df = _prepare_process_df(raw)

        st.write("Training the second-order Markov model...")
        model_df = markov_engine.train_markov_model(df)
        threshold = markov_engine.calculate_percentile_threshold(model_df, percentile=95)

        # Shared suffix ties the four files of this run together, so runs don't overwrite each other.
        suffix = bm.make_timestamp_suffix()

        _save_json(model_df.to_dict(orient='records'), bm.path_for("process", suffix))
        _save_json({"markov_95th_threshold": float(threshold),
                    "training_sample_size": int(len(df))}, bm.path_for("thresholds", suffix))
        st.write(f"Process baseline saved. Threshold {threshold:.2f} bits.")

        # --- file baseline ---
        file_weights = None
        if f_file:
            st.write("Learning file artifact weights...")
            raw_file = ingestion.load_csv_safe(f_file)
            if raw_file is not None:
                # group per process like ingestion; folder path beats filename
                field = cfg.COL_FILE_PATH if cfg.COL_FILE_PATH in raw_file.columns else cfg.COL_FILE_NAME
                if cfg.COL_INIT_PID in raw_file.columns and field in raw_file.columns:
                    raw_file = raw_file.copy()
                    raw_file['pid'] = ingestion.clean_pid(raw_file[cfg.COL_INIT_PID])
                    per_proc = (raw_file.dropna(subset=[field])
                                .groupby([raw_file['DeviceName'].astype(str), 'pid'])[field]
                                .apply(lambda s: s.astype(str).tolist()))
                    file_weights = context_engine.learn_baseline_weights(list(per_proc.values))
                    _save_json(file_weights, bm.path_for("file", suffix))
                    st.write(f"File baseline saved. {len(file_weights) - 1} artifacts learned.")

        # --- network baseline ---
        net_weights = None
        if f_net:
            st.write("Learning network artifact weights...")
            raw_net = ingestion.load_csv_safe(f_net)
            if raw_net is not None:
                field = cfg.COL_NET_URL if cfg.COL_NET_URL in raw_net.columns else cfg.COL_NET_IP
                if cfg.COL_INIT_PID in raw_net.columns and field in raw_net.columns:
                    raw_net = raw_net.copy()
                    raw_net['pid'] = ingestion.clean_pid(raw_net[cfg.COL_INIT_PID])
                    per_proc = (raw_net.dropna(subset=[field])
                                .groupby([raw_net['DeviceName'].astype(str), 'pid'])[field]
                                .apply(lambda s: s.astype(str).tolist()))
                    net_weights = context_engine.learn_baseline_weights(list(per_proc.values))
                    _save_json(net_weights, bm.path_for("net", suffix))
                    st.write(f"Network baseline saved. {len(net_weights) - 1} artifacts learned.")

    st.success(f"✅ Training complete. Baseline saved as '{suffix}'.")
    st.divider()

    # --- stats ---
    st.header("Process Baseline Insights")
    _render_process_stats(model_df, df, threshold)

    if file_weights or net_weights:
        st.divider()
        st.header("Context Baseline Insights")
        if file_weights:
            _render_weight_table(file_weights, "📂 Learned File Weights", "files")
        if net_weights:
            _render_weight_table(net_weights, "🌐 Learned Network Weights", "network")

    # --- downloads ---
    st.divider()
    st.header("Download Baselines")
    st.caption("The files are already saved to baselines/. Use these to keep a copy or move them to another node.")
    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st.download_button("⬇️ Markov Model",
                           json.dumps(model_df.to_dict(orient='records'), indent=4),
                           file_name=f"default_markov_{suffix}.json", mime="application/json",
                           width='stretch')
    with d2:
        st.download_button("⬇️ Threshold",
                           json.dumps({"markov_95th_threshold": float(threshold),
                                       "training_sample_size": int(len(df))}, indent=4),
                           file_name=f"thresholds_{suffix}.json", mime="application/json",
                           width='stretch')
    with d3:
        st.download_button("⬇️ File Weights",
                           json.dumps(file_weights or {}, indent=4),
                           file_name=f"default_file_weights_{suffix}.json", mime="application/json",
                           disabled=file_weights is None, width='stretch')
    with d4:
        st.download_button("⬇️ Network Weights",
                           json.dumps(net_weights or {}, indent=4),
                           file_name=f"default_net_weights_{suffix}.json", mime="application/json",
                           disabled=net_weights is None, width='stretch')
