import pandas as pd
import numpy as np
import json
import os


def learn_baseline_weights(data_series):
    """Learn -log2(P) weights from a Series of lists, plus an '__UNKNOWN__' fallback."""
    all_items = [item for sublist in data_series for item in sublist]

    if not all_items:
        return {'__UNKNOWN__': 10.0}

    counts = pd.Series(all_items).value_counts()
    N = len(all_items)
    V = len(counts)

    # P = (count + 1) / (N + V)
    probs = (counts + 1) / (N + V)

    # bits, same unit as the Markov engine
    weights = -np.log2(probs)

    # unseen item = smoothed count of 0: log2(N + V)
    unknown_score = np.log2(N + V)

    weights_dict = weights.to_dict()
    weights_dict['__UNKNOWN__'] = float(unknown_score)

    return weights_dict


def score_item_list(items, weights_dict):
    """Score a list of items by its riskiest one."""
    if not items or not isinstance(items, list):
        return 0.0

    unknown_score = weights_dict.get('__UNKNOWN__', 12.0)

    scores = []
    for item in items:
        scores.append(weights_dict.get(str(item), unknown_score))

    # max pooling so lots of benign activity can't dilute one bad item
    return max(scores) if scores else 0.0


def _select_feature_column(df, primary_col, fallback_col):
    """Per row, use the primary list, or the fallback list if the primary is empty."""
    has_primary = primary_col in df.columns
    has_fallback = fallback_col in df.columns

    if not has_primary and not has_fallback:
        return pd.Series([[] for _ in range(len(df))], index=df.index)

    def pick(row):
        primary = row[primary_col] if has_primary else []
        if isinstance(primary, list) and len(primary) > 0:
            return primary
        fallback = row[fallback_col] if has_fallback else []
        return fallback if isinstance(fallback, list) else []

    return df.apply(pick, axis=1)


def run_context_scoring(df, primary_col, fallback_col=None, weights=None):
    """Score a context category (files or network). Returns (scores, weights).

    If weights is None they are learned from this batch.
    """
    if fallback_col is None:
        if primary_col not in df.columns:
            return pd.Series(0.0, index=df.index), {}
        feature_series = df[primary_col]
    else:
        feature_series = _select_feature_column(df, primary_col, fallback_col)

    if weights is None:
        learned_weights = learn_baseline_weights(feature_series)
    else:
        learned_weights = weights

    scores = feature_series.apply(lambda x: score_item_list(x, learned_weights))

    return scores, learned_weights


def load_weights_json(filepath):
    """Load a saved weights baseline, or None if the file doesn't exist."""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None
