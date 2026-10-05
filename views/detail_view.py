import streamlit as st
import pandas as pd
import config as cfg

_DETAIL_CSS = """
<style>
    @keyframes cawmc_rise {
        0%   { opacity: 0; transform: translateY(14px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    @keyframes cawmc_fade {
        0% { opacity: 0; } 100% { opacity: 1; }
    }
    @keyframes cawmc_flow {
        0% { opacity: 0.2; } 50% { opacity: 1; } 100% { opacity: 0.2; }
    }

    .score-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
        margin: 4px 0;
    }
    @media (max-width: 900px) {
        .score-grid { grid-template-columns: repeat(2, 1fr); }
    }

    .score-card {
        position: relative;
        background: linear-gradient(160deg, #161b26 0%, #0e1117 100%);
        border: 1px solid #262b38;
        border-top: 3px solid var(--accent, #4c8bf5);
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        animation: cawmc_rise 0.5s cubic-bezier(0.22, 1, 0.36, 1) both;
        transition: transform 0.18s ease, box-shadow 0.18s ease;
    }
    .score-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
    }
    .score-card.d1 { animation-delay: 0.00s; }
    .score-card.d2 { animation-delay: 0.07s; }
    .score-card.d3 { animation-delay: 0.14s; }
    .score-card.d4 { animation-delay: 0.21s; }

    .score-label {
        display: flex; align-items: center; justify-content: center; gap: 6px;
        font-size: 0.7rem; letter-spacing: 1.3px; text-transform: uppercase;
        color: #8a909c; margin: 0;
    }
    .score-value {
        font-size: 1.9rem; font-weight: 700; margin: 6px 0 0 0; line-height: 1.1;
        color: var(--accent, #f3f5f8);
    }

    .info-dot {
        display: inline-flex; align-items: center; justify-content: center;
        width: 15px; height: 15px; border-radius: 50%;
        border: 1px solid #4a515f; color: #9aa1ad;
        font-size: 0.62rem; font-style: italic; font-weight: 700;
        cursor: help; position: relative; font-family: Georgia, serif;
        transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
    }
    .info-dot:hover { background: #4c8bf5; color: #fff; border-color: #4c8bf5; }
    .info-dot .tip {
        visibility: hidden; opacity: 0; width: 220px;
        background: #1d2330; color: #d7dbe2; text-align: left;
        border: 1px solid #333b4a; border-radius: 8px; padding: 9px 11px;
        font-size: 0.74rem; font-style: normal; font-weight: 400;
        line-height: 1.35; letter-spacing: 0.2px; text-transform: none;
        position: absolute; z-index: 50; bottom: 150%; left: 50%;
        transform: translateX(-50%) translateY(4px);
        transition: opacity 0.18s ease, transform 0.18s ease;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.5); pointer-events: none;
    }
    .info-dot .tip::after {
        content: ""; position: absolute; top: 100%; left: 50%;
        margin-left: -5px; border-width: 5px; border-style: solid;
        border-color: #1d2330 transparent transparent transparent;
    }
    .info-dot:hover .tip {
        visibility: visible; opacity: 1; transform: translateX(-50%) translateY(0);
    }

    /* ---- Process lineage chain ---- */
    .lineage-wrap {
        position: relative;
        padding: 4px 0 4px 0;
    }
    .lineage-node {
        position: relative;
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 14px 16px;
        margin: 0 0 0 28px;
        background: linear-gradient(160deg, #161b26 0%, #0e1117 100%);
        border: 1px solid #262b38;
        border-radius: 12px;
        animation: cawmc_rise 0.45s cubic-bezier(0.22, 1, 0.36, 1) both;
    }
    .lineage-node.is-target {
        border-color: #e5484d;
        box-shadow: 0 0 0 1px rgba(229,72,77,0.35), 0 8px 22px rgba(229,72,77,0.18);
    }
    /* Vertical connector line running down the left rail */
    .lineage-rail {
        position: absolute;
        left: 13px; top: 18px; bottom: 18px;
        width: 2px;
        background: linear-gradient(#3a4150, #4c8bf5);
    }
    /* The dot that sits on the rail next to each node */
    .lineage-dot {
        position: absolute;
        left: -22px; top: 50%;
        transform: translateY(-50%);
        width: 12px; height: 12px;
        border-radius: 50%;
        background: #4c8bf5;
        border: 2px solid #0e1117;
        box-shadow: 0 0 0 3px rgba(76,139,245,0.25);
    }
    .lineage-node.is-target .lineage-dot {
        background: #e5484d;
        box-shadow: 0 0 0 3px rgba(229,72,77,0.3);
        animation: cawmc_flow 1.8s ease-in-out infinite;
    }
    .lineage-badge {
        flex-shrink: 0;
        font-size: 0.62rem;
        letter-spacing: 1px;
        text-transform: uppercase;
        font-weight: 700;
        color: #8a909c;
        background: #1d2330;
        border: 1px solid #2c3340;
        border-radius: 6px;
        padding: 4px 8px;
        min-width: 86px;
        text-align: center;
    }
    .lineage-node.is-target .lineage-badge {
        color: #ffd7d8; background: #2a1416; border-color: #5a2a2c;
    }
    .lineage-name {
        font-size: 1.0rem;
        font-weight: 600;
        color: #f3f5f8;
        font-family: 'SF Mono', Menlo, Consolas, monospace;
    }
    .lineage-pid {
        font-size: 0.75rem;
        color: #6c727e;
        margin-left: 2px;
    }
    .lineage-missing { color: #6c727e; font-style: italic; font-weight: 400; }

    /* Read-only detail rows inside each node's expander. No dead input fields. */
    .det-grid { display: flex; gap: 12px; margin-bottom: 14px; }
    .det-field { flex: 1; }
    .det-label {
        font-size: 0.68rem; letter-spacing: 0.8px; text-transform: uppercase;
        color: #8a909c; margin: 0 0 5px 2px;
    }
    .det-value {
        background: #11151d;
        border: 1px solid #262b38;
        border-radius: 8px;
        padding: 10px 12px;
        color: #e8ebf0;
        font-family: 'SF Mono', Menlo, Consolas, monospace;
        font-size: 0.85rem;
        word-break: break-all;
        line-height: 1.4;
    }
    .det-value.is-empty { color: #6c727e; font-style: italic; font-family: inherit; }
    .det-block { margin-bottom: 14px; }
    .detail-fade { animation: cawmc_fade 0.5s ease both; }
</style>
"""


def _info(text: str) -> str:
    safe = text.replace('"', "&quot;")
    return f'<span class="info-dot">i<span class="tip">{safe}</span></span>'


def format_val(row, key):
    val = row.get(key)
    if pd.isna(val) or val == "" or val == "nan" or val is None:
        return "NaN"
    return str(val)


def get_score_color(score):
    if score < 5:
        return "#26c0a0"
    if score < 10:
        return "#e9b949"
    if score < 15:
        return "#f08a3c"
    return "#e5484d"


def render_score_card(label, value, tooltip, delay_class):
    # No leading whitespace, otherwise Streamlit renders it as a code block.
    color = get_score_color(value)
    html = (
        f'<div class="score-card {delay_class}" style="--accent: {color};">'
        f'<p class="score-label">{label} {_info(tooltip)}</p>'
        f'<p class="score-value">{value:.2f}</p>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def find_ancestor_row(full_df, device, pid):
    if full_df is None or pid in ['0', '?', '', 'NaN', None, '0.0']:
        return None

    search_pid = str(pid).split('.')[0]
    mask = (full_df['DeviceName'] == device) & (full_df['pid'].astype(str) == search_pid)
    matches = full_df[mask]

    if not matches.empty:
        return matches.iloc[0]
    return None


def render_detail_view(row, full_df):
    st.markdown(_DETAIL_CSS, unsafe_allow_html=True)

    c_back, c_title = st.columns([1, 7])
    with c_back:
        if st.button("⬅️ Back", width='stretch'):
            st.session_state.selected_row = None
            st.rerun()
    with c_title:
        st.subheader(f"Deep Dive: {row[cfg.COL_PROC_NAME]}")

    st.divider()

    s1, s2, s3, s4 = st.columns(4)
    with s1:
        render_score_card(
            "Markov Score", row.get('Score_Markov', 0),
            "Information content of the grandparent to parent to child transition. High values mean this lineage was rare or unseen in the benign baseline.",
            "d1"
        )
    with s2:
        render_score_card(
            "File Score", row.get('Score_File', 0),
            "Risk from the files this process touched. A single rare file drives the score through max pooling, so benign noise cannot hide it.",
            "d2"
        )
    with s3:
        render_score_card(
            "Network Score", row.get('Score_Net', 0),
            "Risk from outbound connections. Destinations rarely seen in benign traffic raise this value.",
            "d3"
        )
    with s4:
        render_score_card(
            "Total Threat", row.get('TotalScore', 0),
            "Weighted sum of the Markov, file and network scores. This is the value ranked in the detection queue.",
            "d4"
        )

    st.divider()

    st.markdown("##### 👤 Entity & Host Context")
    ec1, ec2 = st.columns(2)

    with ec1:
        st.info(f"""
        **User Identity**
        * **Name:** {format_val(row, 'Username')}
        * **Job Title:** {format_val(row, 'JobTitle')}
        * **Department:** {format_val(row, 'Department')}
        """)

    with ec2:
        st.info(f"""
        **Device Identity**
        * **Hostname:** {format_val(row, 'DeviceName')}
        * **OS / Group:** {format_val(row, 'OSPlatform')} / {format_val(row, 'MachineGroup')}
        * **Risk Profile:** {format_val(row, 'RiskLevel')}
        """)

    st.divider()

    st.markdown("##### Process Lineage")
    st.caption("Execution chain from the root ancestor down to the flagged process.")

    target_pid = str(row['pid']).split('.')[0] if pd.notna(row['pid']) else '?'
    parent_pid = str(row['ppid']).split('.')[0] if pd.notna(row['ppid']) else '?'
    target_device = row['DeviceName']

    parent_row = find_ancestor_row(full_df, target_device, parent_pid)
    parent_name = parent_row[cfg.COL_PROC_NAME] if parent_row is not None else row.get(cfg.COL_PARENT_NAME, 'Unknown')

    gp_row = None
    gp_name = "Unknown Root"
    gp_pid = "?"

    if parent_row is not None and 'ppid' in parent_row:
        gp_pid = str(parent_row['ppid']).split('.')[0]
        gp_row = find_ancestor_row(full_df, target_device, gp_pid)
        gp_name = gp_row[cfg.COL_PROC_NAME] if gp_row is not None else row.get(cfg.COL_GRANDPARENT_NAME, 'Unknown Root')

    nodes = [
        ("Grandparent", gp_name, gp_pid, gp_row, False),
        ("Parent", parent_name, parent_pid, parent_row, False),
        ("Process", row[cfg.COL_PROC_NAME], target_pid, row, True),
    ]

    chain = ['<div class="lineage-wrap"><div class="lineage-rail"></div>']
    for role, name, pid, data, is_target in nodes:
        cls = "lineage-node is-target" if is_target else "lineage-node"
        missing = "" if data is not None else '<span class="lineage-missing"> · metadata unavailable</span>'
        chain.append(
            f'<div class="{cls}">'
            f'<span class="lineage-dot"></span>'
            f'<span class="lineage-badge">{role}</span>'
            f'<span class="lineage-name">{name}'
            f'<span class="lineage-pid"> · PID {pid}</span>{missing}</span>'
            f'</div>'
        )
    chain.append('</div>')
    st.markdown("".join(chain), unsafe_allow_html=True)
    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    # Plain HTML rather than disabled inputs, which show a no-entry cursor.
    for role, name, pid, data, is_target in nodes:
        with st.expander(f"{role} details — {name} (PID {pid})", expanded=is_target):
            if data is not None:
                pname = format_val(data, cfg.COL_PROC_NAME)
                ppid = format_val(data, 'pid')
                fpath = format_val(data, 'ProcessFilePath')
                cmd = format_val(data, 'ProcessCommandLine')

                def cell(label, value):
                    empty = "" if value and value != "NaN" else " is-empty"
                    shown = value if (value and value != "NaN") else "not recorded"
                    return (f'<div class="det-field"><p class="det-label">{label}</p>'
                            f'<div class="det-value{empty}">{shown}</div></div>')

                html = (
                    f'<div class="det-grid">{cell("Process Name", pname)}{cell("PID", ppid)}</div>'
                    f'<div class="det-block"><p class="det-label">Process File Path</p>'
                    f'<div class="det-value{"" if fpath and fpath != "NaN" else " is-empty"}">'
                    f'{fpath if fpath and fpath != "NaN" else "not recorded"}</div></div>'
                    f'<div class="det-block"><p class="det-label">Command Line</p>'
                    f'<div class="det-value{"" if cmd and cmd != "NaN" else " is-empty"}">'
                    f'{cmd if cmd and cmd != "NaN" else "not recorded"}</div></div>'
                )
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.caption("Full metadata for this ancestor is not available in the current log batch.")

    st.divider()

    st.markdown("##### 🕵️ Forensic Evidence")
    tab_f, tab_n = st.tabs(["📂 File Activity", "🌐 Network Activity"])

    def _safe_table(columns):
        # List columns can differ in length (IP but no URL), so pad them first.
        cleaned = {name: (list(vals) if isinstance(vals, list) else []) for name, vals in columns.items()}
        n = max((len(v) for v in cleaned.values()), default=0)
        if n == 0:
            return None
        for name in cleaned:
            cleaned[name] = cleaned[name] + [""] * (n - len(cleaned[name]))
        return pd.DataFrame(cleaned)

    with tab_f:
        file_df = _safe_table({
            'Action': row.get('Context_FileActions', []),
            'File Name': row.get('Context_FilesCreated', []),
            'Path': row.get('Context_FilePaths', []),
        })
        if file_df is not None:
            st.dataframe(file_df, width='stretch', hide_index=True)
        else:
            st.info("No file modification events correlated to this PID.")

    with tab_n:
        net_df = _safe_table({
            'Protocol': row.get('Context_Protocols', []),
            'Remote IP': row.get('Context_RemoteIPs', []),
            'Remote URL': row.get('Context_RemoteUrls', []),
        })
        if net_df is not None:
            st.dataframe(net_df, width='stretch', hide_index=True)
        else:
            st.info("No network connection events correlated to this PID.")
