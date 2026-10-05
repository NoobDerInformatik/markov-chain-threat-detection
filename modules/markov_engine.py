import pandas as pd
import numpy as np
import config as cfg


def train_markov_model(df, order=2):
    """Train the Markov model on benign lineage, P(child | grandparent, parent) in bits.

    order=1 sets the grandparent to a constant so the context becomes just the parent.
    Also stores a per-context UnknownScore used for unseen children.
    """
    gp_col, p_col, c_col = cfg.COL_GRANDPARENT_NAME, cfg.COL_PARENT_NAME, cfg.COL_PROC_NAME

    df_clean = df.copy()
    for col in [gp_col, p_col, c_col]:
        df_clean[col] = df_clean[col].astype(str)

    # first-order: constant grandparent, everything else stays the same
    if order == 1:
        df_clean[gp_col] = '__NONE__'

    triplet_counts = df_clean.groupby([gp_col, p_col, c_col]).size().reset_index(name='Count')

    context_counts = (df_clean.groupby([gp_col, p_col]).size()
                      .reset_index(name='ContextCount'))

    vocab = (df_clean.groupby([gp_col, p_col])[c_col].nunique()
             .reset_index(name='Vocab'))

    triplet_counts = triplet_counts.merge(context_counts, on=[gp_col, p_col])
    triplet_counts = triplet_counts.merge(vocab, on=[gp_col, p_col])

    # P(child | gp, parent) = (count + 1) / (ctx_count + vocab)
    triplet_counts['Prob'] = (
        (triplet_counts['Count'] + 1) /
        (triplet_counts['ContextCount'] + triplet_counts['Vocab'])
    )
    triplet_counts['Score'] = -np.log2(triplet_counts['Prob'])

    # unseen child = smoothed count of 0: log2(ctx_count + vocab)
    triplet_counts['UnknownScore'] = np.log2(
        triplet_counts['ContextCount'] + triplet_counts['Vocab']
    )

    return triplet_counts.drop(columns=['Prob'])


def run_markov_scoring(master_df, baseline_model=None, unknown_floor=20.0):
    """Score each process against the baseline with a backoff:
    exact triplet, context UnknownScore, parent UnknownScore, parent->child pair,
    child name only (+2.0), then unknown_floor.
    """
    if baseline_model is None:
        return pd.Series(0.0, index=master_df.index), None

    model = baseline_model.copy()
    gp_col, p_col, c_col = cfg.COL_GRANDPARENT_NAME, cfg.COL_PARENT_NAME, cfg.COL_PROC_NAME
    has_unknown = 'UnknownScore' in model.columns

    # first-order baseline: match its constant grandparent
    master_df = master_df.copy()
    if set(model[gp_col].astype(str).unique()) == {'__NONE__'}:
        master_df[gp_col] = '__NONE__'

    # merge resets the index and ingestion sorts by timestamp, so restore it at the end
    original_index = master_df.index

    # tier 1: exact triplet
    merged = pd.merge(master_df.reset_index(drop=True), model,
                      on=[gp_col, p_col, c_col], how='left')

    # tier 1b: known (gp, parent) context, unseen child
    if has_unknown:
        missing_mask = merged['Score'].isna()
        if missing_mask.any():
            # constant within a context, so first() is exact
            ctx_unknown = (model.groupby([gp_col, p_col])['UnknownScore']
                           .first().reset_index())
            ctx_scores = pd.merge(
                merged.loc[missing_mask, [gp_col, p_col]],
                ctx_unknown, on=[gp_col, p_col], how='left'
            )['UnknownScore']
            merged.loc[missing_mask, 'Score'] = ctx_scores.values

    # tier 2: known parent only, max UnknownScore across grandparents.
    # Must run before the pair fallback, otherwise winword -> cmd -> certutil is masked.
    if has_unknown:
        missing_mask = merged['Score'].isna()
        if missing_mask.any():
            par_unknown = (model.groupby(p_col)['UnknownScore']
                           .max().reset_index())
            par_scores = pd.merge(
                merged.loc[missing_mask, [p_col]],
                par_unknown, on=p_col, how='left'
            )['UnknownScore']
            merged.loc[missing_mask, 'Score'] = par_scores.values

    # tier 2b: parent -> child pair, lowest score (legacy baselines or unknown parent)
    missing_mask = merged['Score'].isna()
    if missing_mask.any():
        pair_fallback = model.groupby([p_col, c_col])['Score'].min().reset_index()
        pair_scores = pd.merge(
            merged.loc[missing_mask, [p_col, c_col]],
            pair_fallback, on=[p_col, c_col], how='left'
        )['Score']
        merged.loc[missing_mask, 'Score'] = pair_scores.values

    # tier 3: child name only, +2.0 for the lost lineage
    missing_mask = merged['Score'].isna()
    if missing_mask.any():
        proc_fallback = model.groupby(c_col)['Score'].min().reset_index()
        proc_scores = pd.merge(
            merged.loc[missing_mask, [c_col]],
            proc_fallback, on=c_col, how='left'
        )['Score']
        merged.loc[missing_mask, 'Score'] = proc_scores.values + 2.0

    # nothing matched at all
    merged['Score'] = merged['Score'].fillna(unknown_floor)

    scores = merged['Score']
    scores.index = original_index
    return scores, model


def calculate_percentile_threshold(model_df, percentile=95):
    """Alert threshold: count-weighted percentile of baseline scores."""
    if 'Count' in model_df.columns:
        scores = np.repeat(model_df['Score'].values, model_df['Count'].values)
    else:
        scores = model_df['Score'].values

    return np.percentile(scores, percentile)
