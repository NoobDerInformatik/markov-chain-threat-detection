import streamlit as st
import pandas as pd
import numpy as np
import altair as alt

import config as cfg

# ground truth column added by the analyst
VERDICT_COL = "verdict"
MALICIOUS_LABELS = {"malicious", "mal", "bad", "1", "true", "positive"}


# Metrics done by hand in numpy to avoid pulling in sklearn.
def confusion_at_threshold(scores, y_true, threshold):
    """TP, FP, TN, FN with score >= threshold counted as malicious."""
    y_pred = scores >= threshold
    tp = int(np.sum(y_pred & y_true))
    fp = int(np.sum(y_pred & ~y_true))
    tn = int(np.sum(~y_pred & ~y_true))
    fn = int(np.sum(~y_pred & y_true))
    return tp, fp, tn, fn


def metrics_from_confusion(tp, fp, tn, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return precision, recall, f1, accuracy


def roc_curve(scores, y_true):
    """Returns fpr, tpr, auc, using every distinct score as a threshold."""
    P = np.sum(y_true)
    N = np.sum(~y_true)
    if P == 0 or N == 0:
        return np.array([0, 1]), np.array([0, 1]), float('nan')

    # start at inf so the curve begins at (0, 0)
    thresholds = np.concatenate(([np.inf], np.sort(np.unique(scores))[::-1]))
    tpr_list, fpr_list = [], []
    for t in thresholds:
        y_pred = scores >= t
        tp = np.sum(y_pred & y_true)
        fp = np.sum(y_pred & ~y_true)
        tpr_list.append(tp / P)
        fpr_list.append(fp / N)

    fpr = np.array(fpr_list)
    tpr = np.array(tpr_list)
    # np.trapz was renamed to np.trapezoid in numpy 2.0
    order = np.argsort(fpr)
    trapz = getattr(np, "trapezoid", getattr(np, "trapz", None))
    auc = float(trapz(tpr[order], fpr[order]))
    return fpr, tpr, auc


def render_results_view():
    st.title("📊 Evaluation & Results")

    # reuses the scored data from the Detect tab
    master = st.session_state.get("master_df")
    if master is None:
        st.info("Run an analysis in the **Detect** tab first. To evaluate, include a "
                "`verdict` column (malicious or benign) in your process CSV before scoring there.")
        return

    if VERDICT_COL not in master.columns:
        st.warning("The scored data has no `verdict` column, so it cannot be evaluated. "
                   "Add a `verdict` column (malicious or benign) to your process CSV in the "
                   "Detect tab and run the analysis again.")
        return

    if 'TotalScore' not in master.columns:
        st.warning("The scored data has no threat scores yet. Run the analysis in the Detect tab first.")
        return

    y_true = master[VERDICT_COL].astype(str).str.strip().str.lower().isin(MALICIOUS_LABELS).values
    n_mal, n_ben = int(np.sum(y_true)), int(np.sum(~y_true))
    if n_mal == 0 or n_ben == 0:
        st.warning(f"Both classes are needed to evaluate. The scored data has "
                   f"{n_mal} malicious and {n_ben} benign rows.")
        return

    scores = master['TotalScore'].values
    st.caption(f"Evaluating {len(master)} scored events from the Detect tab: "
               f"{n_mal} malicious, {n_ben} benign.")
    st.divider()

    default_thr = st.session_state.get("operating_threshold")
    if default_thr is None:
        default_thr = float(np.percentile(scores, 95))
    smin, smax = float(scores.min()), float(scores.max())
    st.subheader("Operating Threshold")
    st.caption("Defaults to the threshold the detector used (the 95th percentile of the benign baseline). Drag to see how the trade-off shifts.")
    # slider needs max > min
    if smax <= smin:
        smax = smin + 1.0
    threshold = st.slider("Decision threshold (bits)", min_value=round(smin, 2), max_value=round(smax, 2),
                          value=float(min(max(default_thr, smin), smax)), step=0.1)

    tp, fp, tn, fn = confusion_at_threshold(scores, y_true, threshold)
    precision, recall, f1, accuracy = metrics_from_confusion(tp, fp, tn, fn)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Precision", f"{precision:.1%}", help="Of everything flagged, how much was truly malicious.")
    m2.metric("Recall", f"{recall:.1%}", help="Of all malicious events, how many were caught.")
    m3.metric("F1 Score", f"{f1:.3f}", help="Harmonic mean of precision and recall.")
    m4.metric("Accuracy", f"{accuracy:.1%}", help="Overall fraction classified correctly.")

    st.divider()
    col_cm, col_roc = st.columns(2)

    with col_cm:
        st.subheader("Confusion Matrix")
        cm_df = pd.DataFrame({
            'Predicted': ['Malicious', 'Benign', 'Malicious', 'Benign'],
            'Actual': ['Malicious', 'Malicious', 'Benign', 'Benign'],
            'Count': [tp, fn, fp, tn],
            'Kind': ['TP', 'FN', 'FP', 'TN'],
        })
        heat = alt.Chart(cm_df).mark_rect().encode(
            x=alt.X('Predicted:N', title='Predicted'),
            y=alt.Y('Actual:N', title='Actual'),
            color=alt.Color('Count:Q', scale=alt.Scale(scheme='blues'), legend=None),
            tooltip=['Kind', 'Count']
        )
        text = alt.Chart(cm_df).mark_text(fontSize=22, fontWeight='bold').encode(
            x='Predicted:N', y='Actual:N', text='Count:Q',
            color=alt.condition(alt.datum.Count > (tp + tn + fp + fn) / 4,
                                alt.value('white'), alt.value('#1d2330'))
        )
        st.altair_chart((heat + text).properties(height=300), width='stretch')

    with col_roc:
        st.subheader("ROC Curve")
        fpr, tpr, auc = roc_curve(scores, y_true)
        roc_df = pd.DataFrame({'FPR': fpr, 'TPR': tpr})
        diagonal = pd.DataFrame({'FPR': [0, 1], 'TPR': [0, 1]})

        line = alt.Chart(roc_df).mark_line(color='#4c8bf5', strokeWidth=2.5).encode(
            x=alt.X('FPR:Q', title='False Positive Rate', scale=alt.Scale(domain=[0, 1])),
            y=alt.Y('TPR:Q', title='True Positive Rate', scale=alt.Scale(domain=[0, 1])),
            tooltip=[alt.Tooltip('FPR', format='.2f'), alt.Tooltip('TPR', format='.2f')]
        )
        chance = alt.Chart(diagonal).mark_line(strokeDash=[5, 5], color='#888').encode(x='FPR:Q', y='TPR:Q')
        st.altair_chart((line + chance).properties(height=300), width='stretch')
        st.metric("AUC", f"{auc:.3f}", help="Area under the ROC curve. 1.0 is perfect, 0.5 is random guessing.")

    st.divider()

    st.subheader("Incident-Level Detection")
    st.caption("Per-event metrics above judge each row on its own. Operationally, an incident counts as caught if any of its malicious rows alerts. Grouped here by device.")
    mal = master[y_true].copy()
    mal['__pred'] = mal['TotalScore'].values >= threshold
    incidents = mal.groupby('DeviceName')['__pred'].any()
    caught = int(incidents.sum())
    total_inc = int(len(incidents))
    rate = caught / total_inc if total_inc else 0.0
    ic1, ic2 = st.columns(2)
    ic1.metric("Incidents Detected", f"{caught} / {total_inc}")
    ic2.metric("Incident Detection Rate", f"{rate:.0%}")

    st.divider()
    st.subheader("Misclassified Events")
    master['__pred'] = scores >= threshold
    master['__truth'] = y_true
    wrong = master[master['__pred'] != master['__truth']]
    if wrong.empty:
        st.success("No misclassifications at this threshold.")
    else:
        kind = np.where(wrong['__truth'], 'False Negative (missed)', 'False Positive (noise)')
        show = wrong[[cfg.COL_PROC_NAME, cfg.COL_PARENT_NAME, 'DeviceName', 'TotalScore']].copy()
        show.insert(0, 'Error Type', kind)
        show['TotalScore'] = show['TotalScore'].round(2)
        st.dataframe(show.sort_values('TotalScore', ascending=False), width='stretch', hide_index=True)
