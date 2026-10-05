import streamlit as st
import pandas as pd
import altair as alt
import config as cfg
import json
import os

_DASHBOARD_CSS = """
<style>
    /* Fade and lift used by the KPI cards on first paint */
    @keyframes cawmc_rise {
        0%   { opacity: 0; transform: translateY(14px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    @keyframes cawmc_fade {
        0%   { opacity: 0; }
        100% { opacity: 1; }
    }

    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin: 4px 0 8px 0;
    }
    @media (max-width: 900px) {
        .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    }

    .kpi-card {
        position: relative;
        background: linear-gradient(160deg, #161b26 0%, #0e1117 100%);
        border: 1px solid #262b38;
        border-radius: 12px;
        padding: 18px 18px 16px 18px;
        animation: cawmc_rise 0.5s cubic-bezier(0.22, 1, 0.36, 1) both;
        transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
        overflow: hidden;
    }
    .kpi-card::before {
        content: "";
        position: absolute;
        left: 0; top: 0; bottom: 0;
        width: 3px;
        background: var(--accent, #4c8bf5);
        opacity: 0.9;
    }
    .kpi-card:hover {
        transform: translateY(-3px);
        border-color: #3a4150;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
    }
    /* Stagger the entrance so the row assembles left to right */
    .kpi-card.d1 { animation-delay: 0.00s; }
    .kpi-card.d2 { animation-delay: 0.07s; }
    .kpi-card.d3 { animation-delay: 0.14s; }
    .kpi-card.d4 { animation-delay: 0.21s; }

    .kpi-label {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 0.72rem;
        letter-spacing: 1.4px;
        text-transform: uppercase;
        color: #8a909c;
        margin: 0;
    }
    .kpi-value {
        font-size: 2.0rem;
        font-weight: 700;
        color: #f3f5f8;
        margin: 6px 0 0 0;
        line-height: 1.1;
    }
    .kpi-sub {
        font-size: 0.72rem;
        color: #6c727e;
        margin: 4px 0 0 0;
    }

    /* Info icon with a CSS only tooltip on hover */
    .info-dot {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 15px; height: 15px;
        border-radius: 50%;
        border: 1px solid #4a515f;
        color: #9aa1ad;
        font-size: 0.62rem;
        font-style: italic;
        font-weight: 700;
        cursor: help;
        position: relative;
        font-family: Georgia, serif;
        transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
    }
    .info-dot:hover {
        background: #4c8bf5;
        color: #fff;
        border-color: #4c8bf5;
    }
    .info-dot .tip {
        visibility: hidden;
        opacity: 0;
        width: 230px;
        background: #1d2330;
        color: #d7dbe2;
        text-align: left;
        border: 1px solid #333b4a;
        border-radius: 8px;
        padding: 9px 11px;
        font-size: 0.74rem;
        font-style: normal;
        font-weight: 400;
        line-height: 1.35;
        letter-spacing: 0.2px;
        text-transform: none;
        position: absolute;
        z-index: 50;
        bottom: 150%;
        left: 50%;
        transform: translateX(-50%) translateY(4px);
        transition: opacity 0.18s ease, transform 0.18s ease;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.5);
        pointer-events: none;
    }
    .info-dot .tip::after {
        content: "";
        position: absolute;
        top: 100%;
        left: 50%;
        margin-left: -5px;
        border-width: 5px;
        border-style: solid;
        border-color: #1d2330 transparent transparent transparent;
    }
    .info-dot:hover .tip {
        visibility: visible;
        opacity: 1;
        transform: translateX(-50%) translateY(0);
    }

    .section-head {
        animation: cawmc_fade 0.6s ease both;
        animation-delay: 0.25s;
    }
</style>
"""


def _info(text: str) -> str:
    safe = text.replace('"', "&quot;")
    return f'<span class="info-dot">i<span class="tip">{safe}</span></span>'


def _kpi_card(label, value, sub, accent, delay_class, tooltip):
    # No leading whitespace, otherwise Streamlit renders it as a code block.
    return (
        f'<div class="kpi-card {delay_class}" style="--accent: {accent};">'
        f'<p class="kpi-label">{label} {_info(tooltip)}</p>'
        f'<p class="kpi-value">{value}</p>'
        f'<p class="kpi-sub">{sub}</p>'
        f'</div>'
    )


def load_dynamic_threshold():
    """95th percentile threshold from baseline training."""
    threshold_path = os.path.join("baselines", "thresholds.json")
    if os.path.exists(threshold_path):
        try:
            with open(threshold_path, 'r') as f:
                data = json.load(f)
                return data.get("markov_95th_threshold", 10.0)
        except Exception:
            return 10.0
    return 10.0


def render_dashboard(df: pd.DataFrame):
    st.markdown(_DASHBOARD_CSS, unsafe_allow_html=True)

    DYNAMIC_LIMIT = load_dynamic_threshold()

    avg_score = df['TotalScore'].mean()
    max_score = df['TotalScore'].max()
    high_risk_count = len(df[df['TotalScore'] > DYNAMIC_LIMIT])
    high_risk_pct = (high_risk_count / len(df) * 100) if len(df) else 0.0

    cards = (
        _kpi_card(
            "Events Analyzed", f"{len(df):,}", "Total process events scored",
            "#4c8bf5", "d1",
            "Number of process creation events that passed through the scoring pipeline in this batch."
        )
        + _kpi_card(
            "Max Threat Score", f"{max_score:.1f}", "Highest single event",
            "#a06bf0", "d2",
            "The largest combined threat score observed. Driven by rare process lineage and suspicious file or network context."
        )
        + _kpi_card(
            "Avg Threat Score", f"{avg_score:.1f}", "Mean across all events",
            "#26c0a0", "d3",
            "Average threat score over every event. A low average with isolated spikes is the expected healthy pattern."
        )
        + _kpi_card(
            "High Risk", f"{high_risk_count}", f"{high_risk_pct:.1f}% over {DYNAMIC_LIMIT:.2f} bits",
            "#e5484d", "d4",
            f"Events scoring above {DYNAMIC_LIMIT:.2f} bits, the 95th percentile of the benign baseline. These are the events worth an analyst's time."
        )
    )
    st.markdown(f'<div class="kpi-grid">{cards}</div>', unsafe_allow_html=True)

    st.divider()

    st.subheader("Threat Timeline")

    base = alt.Chart(df)

    threshold_rule = alt.Chart(
        pd.DataFrame({'y': [DYNAMIC_LIMIT]})
    ).mark_rule(
        color='#e5484d', strokeDash=[6, 4], opacity=0.6
    ).encode(y='y:Q')

    # Some exports lack Username etc., and Altair errors on missing fields.
    candidate_tooltip = [cfg.COL_PROC_TIME, cfg.COL_PROC_NAME, 'Username', 'DeviceName']
    tooltip = [c for c in candidate_tooltip if c in df.columns]
    tooltip.append(alt.Tooltip('TotalScore', format='.2f'))

    points = base.mark_circle(opacity=0.8).encode(
        x=alt.X(cfg.COL_PROC_TIME, title='Time (UTC)'),
        y=alt.Y('TotalScore', title='Threat Score (bits)'),
        size=alt.Size('TotalScore', scale=alt.Scale(range=[30, 320]), legend=None),
        color=alt.Color(
            'TotalScore',
            scale=alt.Scale(scheme='turbo', domain=[0, 20]),
            title='Score'
        ),
        tooltip=tooltip
    )

    chart = (threshold_rule + points).interactive().properties(height=320)
    st.altair_chart(chart, width='stretch')

    st.subheader("Anomaly Detection Queue")
    st.caption(f"Prioritized by threat score. Alerts trigger above {DYNAMIC_LIMIT:.2f} bits (95th percentile of baseline).")

    cols_to_show = [
        cfg.COL_PROC_TIME,
        'DeviceName',
        'Username',
        cfg.COL_PARENT_NAME,
        cfg.COL_PROC_NAME,
        'Score_Markov',
        'Score_File',
        'Score_Net',
        'TotalScore'
    ]
    display_cols = [c for c in cols_to_show if c in df.columns]
    display_df = df.sort_values('TotalScore', ascending=False)

    # column_config instead of a Styler: Styler caps out around 262k cells.
    score_max = float(display_df['TotalScore'].max()) if len(display_df) else 20.0
    col_config = {
        'TotalScore': st.column_config.ProgressColumn(
            'Total Score', help="Combined threat score (bits)",
            format="%.2f", min_value=0.0, max_value=max(score_max, 20.0)
        ),
    }
    for c in ['Score_Markov', 'Score_File', 'Score_Net']:
        if c in display_cols:
            col_config[c] = st.column_config.NumberColumn(c, format="%.2f")

    event = st.dataframe(
        display_df[display_cols],
        column_config=col_config,
        width='stretch',
        height=560,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )

    if len(event.selection.rows) > 0:
        selected_index = event.selection.rows[0]
        selected_row_data = display_df.iloc[selected_index]
        st.session_state.selected_row = selected_row_data
        st.rerun()
