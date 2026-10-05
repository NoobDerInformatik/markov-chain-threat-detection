import pandas as pd
import json
import os
import sys
import argparse
import numpy as np

# Put the project root on the path so `import config` works from any directory.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules import ingestion, context_engine, markov_engine, baseline_manager as bm
import config as cfg

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "baselines")

PATH_BENIGN_PROC = os.path.join(DATA_DIR, "benign_process.csv")
PATH_BENIGN_FILE = os.path.join(DATA_DIR, "benign_file.csv")
PATH_BENIGN_NET = os.path.join(DATA_DIR, "benign_network.csv")

# Shared suffix ties this run's four files together (same naming as the dashboard).
RUN_SUFFIX = bm.make_timestamp_suffix()
OUT_PROC = os.path.join(OUTPUT_DIR, f"default_markov_{RUN_SUFFIX}.json")
OUT_FILE = os.path.join(OUTPUT_DIR, f"default_file_weights_{RUN_SUFFIX}.json")
OUT_NET = os.path.join(OUTPUT_DIR, f"default_net_weights_{RUN_SUFFIX}.json")
OUT_THRESH = os.path.join(OUTPUT_DIR, f"thresholds_{RUN_SUFFIX}.json")


def ensure_dir(d):
    if not os.path.exists(d):
        os.makedirs(d)
        print(f"[+] Created directory: {d}")


def save_json(data, fp):
    try:
        with open(fp, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[OK] Saved output to: {fp}")
    except Exception as e:
        print(f"[ERR] Error saving {fp}: {e}")


def _learn_context_field(df, primary_field, fallback_field):
    """Learn context weights per process, grouped the same way ingestion does."""
    field = primary_field if primary_field in df.columns else fallback_field
    if field not in df.columns:
        print(f"    [skip] Neither {primary_field} nor {fallback_field} present.")
        return None

    if cfg.COL_INIT_PID in df.columns:
        df = df.copy()
        df['pid'] = ingestion.clean_pid(df[cfg.COL_INIT_PID])
        per_process = (df.dropna(subset=[field])
                       .groupby([df['DeviceName'].astype(str), 'pid'])[field]
                       .apply(lambda s: s.astype(str).tolist()))
        data_series = list(per_process.values)
    else:
        # no PID column, treat everything as one corpus
        data_series = [df[field].dropna().astype(str).tolist()]

    return context_engine.learn_baseline_weights(data_series)


def train_process(targets):
    print("\n[+] Starting PROCESS Baseline Training...")
    if not os.path.exists(PATH_BENIGN_PROC):
        print(f"[warn] Skipped Process: file not found at {PATH_BENIGN_PROC}")
        return

    df = pd.read_csv(PATH_BENIGN_PROC)
    print(f"    - Loaded {len(df)} rows.")

    # Same normalisation as the live pipeline, so scores line up.
    if 'pid' in df.columns and 'ppid' in df.columns:
        print("    - Normalizing PIDs and PPIDs...")
        df['pid'] = ingestion.clean_pid(df['pid'])
        df['ppid'] = ingestion.clean_pid(df['ppid'])

    for col in [cfg.COL_PROC_NAME, cfg.COL_PARENT_NAME]:
        if col in df.columns:
            df[col] = (df[col].fillna('system_root')
                       .replace(['nan', '0', 'None'], 'system_root').astype(str))

    if 'ppid' in df.columns and 'pid' in df.columns:
        print("    - Deriving Grandparents and Standardizing Roots...")
        df = ingestion.derive_grandparent_column(df)
    else:
        df[cfg.COL_GRANDPARENT_NAME] = 'system_root'

    print("    - Training Markov Chain Model...")
    model_df = markov_engine.train_markov_model(df)

    print("    - Calculating Dynamic 95th Percentile Threshold...")
    dynamic_threshold = markov_engine.calculate_percentile_threshold(model_df, percentile=95)
    print(f"    - 95th Percentile Threshold: {dynamic_threshold:.2f} bits")

    save_json({
        "markov_95th_threshold": float(dynamic_threshold),
        "training_sample_size": int(len(df))
    }, OUT_THRESH)

    save_json(model_df.to_dict(orient='records'), OUT_PROC)


def train_file(targets):
    print("\n[+] Starting FILE Baseline Training...")
    if not os.path.exists(PATH_BENIGN_FILE):
        print(f"[warn] Skipped File: file not found at {PATH_BENIGN_FILE}")
        return

    df = pd.read_csv(PATH_BENIGN_FILE)
    print(f"    - Loaded {len(df)} rows.")
    # folder path is more stable than the filename
    weights = _learn_context_field(df, cfg.COL_FILE_PATH, cfg.COL_FILE_NAME)
    if weights is not None:
        print(f"    - Learned {len(weights) - 1} distinct file artifacts.")
        save_json(weights, OUT_FILE)


def train_network(targets):
    print("\n[+] Starting NETWORK Baseline Training...")
    if not os.path.exists(PATH_BENIGN_NET):
        print(f"[warn] Skipped Network: file not found at {PATH_BENIGN_NET}")
        return

    df = pd.read_csv(PATH_BENIGN_NET)
    print(f"    - Loaded {len(df)} rows.")
    # URL is more stable than the raw IP
    weights = _learn_context_field(df, cfg.COL_NET_URL, cfg.COL_NET_IP)
    if weights is not None:
        print(f"    - Learned {len(weights) - 1} distinct network artifacts.")
        save_json(weights, OUT_NET)


def main():
    parser = argparse.ArgumentParser(
        description="Train benign baselines for the Context-Aware Weighted Markov detector."
    )
    parser.add_argument('--train', nargs='+',
                        choices=['process', 'file', 'network', 'all'], required=True,
                        help="Which baselines to train, e.g. --train all")
    args = parser.parse_args()
    targets = set(args.train)

    print("=" * 60)
    print(f"Starting Baseline Training | Targets: {', '.join(targets).upper()}")
    print("=" * 60)

    ensure_dir(OUTPUT_DIR)

    if 'all' in targets or 'process' in targets:
        train_process(targets)
    if 'all' in targets or 'file' in targets:
        train_file(targets)
    if 'all' in targets or 'network' in targets:
        train_network(targets)

    print("\n" + "=" * 60)
    print("Training sequence completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()