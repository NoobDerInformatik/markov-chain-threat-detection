import os
import re
import json
from datetime import datetime

# One file per stream, so baselines from different runs can be mixed.
BASELINE_DIR = "baselines"

# Thresholds share the process baseline's suffix; they aren't a stream.
STREAM_STEMS = {
    "process": "default_markov",
    "file": "default_file_weights",
    "net": "default_net_weights",
}
THRESHOLD_STEM = "thresholds"

STREAM_LABELS = {
    "process": "Process",
    "file": "File",
    "net": "Network",
}


def _stem_re(stem):
    return re.compile(rf"^{re.escape(stem)}_(.+)\.json$")


def ensure_dir():
    os.makedirs(BASELINE_DIR, exist_ok=True)


def make_timestamp_suffix():
    # no colons, Windows doesn't allow them in filenames
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def path_for(role, suffix):
    if role == "thresholds":
        stem = THRESHOLD_STEM
    else:
        stem = STREAM_STEMS[role]
    return os.path.join(BASELINE_DIR, f"{stem}_{suffix}.json")


def list_baselines(role=None):
    """List baselines on disk, newest first. Pass role to limit to one stream."""
    ensure_dir()
    roles = [role] if role else list(STREAM_STEMS.keys())
    out = []
    for r in roles:
        rx = _stem_re(STREAM_STEMS[r])
        for fname in os.listdir(BASELINE_DIR):
            m = rx.match(fname)
            if not m:
                continue
            suffix = m.group(1)
            full = os.path.join(BASELINE_DIR, fname)
            modified = datetime.fromtimestamp(os.path.getmtime(full))
            out.append({
                "role": r,
                "suffix": suffix,
                "label": f"{STREAM_LABELS[r]} Baseline ({suffix})",
                "modified": modified,
            })
    out.sort(key=lambda s: s["modified"] or datetime.min, reverse=True)
    return out


def newest_suffix(role):
    items = list_baselines(role)
    return items[0]["suffix"] if items else None


def has_baseline(role, suffix):
    if suffix is None:
        return False
    return os.path.exists(path_for(role, suffix))


def load_baseline(role, suffix):
    """Load a baseline JSON, or None if it doesn't exist."""
    if suffix is None:
        return None
    p = path_for(role, suffix)
    if os.path.exists(p):
        with open(p, "r") as f:
            return json.load(f)
    return None


def load_threshold(suffix):
    return load_baseline("thresholds", suffix)


def _safe_suffix(name):
    """Turn a user-supplied name into a filename-safe suffix."""
    cleaned = re.sub(r'[<>:"/\\|?*\s]+', "_", name.strip())
    cleaned = cleaned.strip("_.")
    return cleaned


def rename_baseline(role, old_suffix, new_name):
    """Rename a baseline and return the new suffix.

    Process baselines take their threshold file with them. Raises ValueError
    on an empty name or a clash within the same stream.
    """
    new_suffix = _safe_suffix(new_name)
    if not new_suffix:
        raise ValueError("The name cannot be empty.")
    if new_suffix == old_suffix:
        return old_suffix

    existing = {b["suffix"] for b in list_baselines(role)}
    if new_suffix in existing:
        raise ValueError(f"A {STREAM_LABELS[role]} baseline named '{new_suffix}' already exists.")

    os.rename(path_for(role, old_suffix), path_for(role, new_suffix))

    if role == "process":
        old_thr = path_for("thresholds", old_suffix)
        if os.path.exists(old_thr):
            os.rename(old_thr, path_for("thresholds", new_suffix))

    return new_suffix


def delete_baseline(role, suffix):
    """Delete a baseline (plus thresholds for process). Returns files removed."""
    removed = 0
    p = path_for(role, suffix)
    if os.path.exists(p):
        os.remove(p)
        removed += 1
    if role == "process":
        thr = path_for("thresholds", suffix)
        if os.path.exists(thr):
            os.remove(thr)
            removed += 1
    return removed