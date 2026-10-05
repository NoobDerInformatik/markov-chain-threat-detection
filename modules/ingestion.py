import pandas as pd
import numpy as np
import config as cfg


def load_csv_safe(file_buffer):
    """Read a CSV, sniffing the separator if a comma parse gives one column."""
    if file_buffer is None:
        return None
    try:
        df = pd.read_csv(file_buffer, sep=',', skipinitialspace=True)
        if len(df.columns) < 2:
            file_buffer.seek(0)
            df = pd.read_csv(file_buffer, sep=None, engine='python')
        return df
    except Exception:
        return None


def clean_pid(series):
    """Normalise PIDs to int strings.

    Exports sometimes give floats like 1234.0 or nulls, which break the joins.
    """
    numeric_series = pd.to_numeric(series, errors='coerce')
    return numeric_series.fillna(0).astype(int).astype(str)


def derive_grandparent_column(df):
    """Add the grandparent process name via a (device, pid) lookup.

    Anything without a resolvable ancestor becomes 'system_root' so the chain
    never breaks.
    """
    if 'EventTimestampUTC' in df.columns:
        df = df.sort_values('EventTimestampUTC', ascending=False)

    df['temp_pid_str'] = clean_pid(df['pid'])
    df['temp_ppid_str'] = clean_pid(df['ppid'])

    lookup_df = df.drop_duplicates(subset=['DeviceName', 'temp_pid_str'])
    pid_map = {(str(row['DeviceName']), row['temp_pid_str']):
               {'name': str(row[cfg.COL_PROC_NAME]), 'ppid': row['temp_ppid_str']}
               for _, row in lookup_df.iterrows()}

    def get_gp(row):
        device = str(row['DeviceName'])
        p_id = row['temp_ppid_str']

        if p_id == '0' or p_id == 'unknown':
            return 'system_root'

        parent_info = pid_map.get((device, p_id))
        if not parent_info:
            return 'system_root'

        gp_id = parent_info['ppid']
        gp_info = pid_map.get((device, gp_id))

        return gp_info['name'] if gp_info else 'system_root'

    df[cfg.COL_GRANDPARENT_NAME] = df.apply(get_gp, axis=1)
    df[cfg.COL_PARENT_NAME] = df[cfg.COL_PARENT_NAME].replace(['nan', '0', 'None'], 'system_root')

    df.drop(columns=['temp_pid_str', 'temp_ppid_str'], inplace=True, errors='ignore')
    return df


def aggregate_context(df_ctx, agg_map):
    """Group a file/network stream into one row per (device, pid), with list columns.

    agg_map maps source column -> output column. Returns None if nothing to do.
    """
    if df_ctx is None or df_ctx.empty:
        return None

    df_ctx = df_ctx.copy()

    if cfg.COL_INIT_PID not in df_ctx.columns:
        return None
    df_ctx['pid'] = clean_pid(df_ctx[cfg.COL_INIT_PID])
    df_ctx['DeviceName'] = df_ctx['DeviceName'].astype(str)

    # optional columns (e.g. RemoteUrl) may be missing from the export
    present = {src: tgt for src, tgt in agg_map.items() if src in df_ctx.columns}
    if not present:
        return None

    grouped = df_ctx.groupby(['DeviceName', 'pid']).agg(
        {src: (lambda s: s.dropna().astype(str).tolist()) for src in present}
    ).rename(columns=present).reset_index()

    return grouped


def attach_limbs(df_proc, df_ctx, fill_cols):
    """Left join context onto the spine.

    Processes with no context get [] rather than NaN so downstream code can
    always iterate the column.
    """
    if df_ctx is None:
        for col in fill_cols:
            df_proc[col] = [[] for _ in range(len(df_proc))]
        return df_proc

    df_proc = df_proc.merge(df_ctx, on=['DeviceName', 'pid'], how='left')

    for col in fill_cols:
        if col in df_proc.columns:
            df_proc[col] = df_proc[col].apply(lambda x: x if isinstance(x, list) else [])
        else:
            df_proc[col] = [[] for _ in range(len(df_proc))]
    return df_proc


def process_and_merge_data(proc_file, file_file, net_file):
    """Load the process CSV and attach file and network context to it."""
    df_proc = load_csv_safe(proc_file)
    if df_proc is None:
        raise ValueError("Process Data is missing.")

    df_proc['pid'] = clean_pid(df_proc['pid'])
    df_proc['ppid'] = clean_pid(df_proc['ppid'])
    df_proc['DeviceName'] = df_proc['DeviceName'].astype(str)

    for col in [cfg.COL_PROC_NAME, cfg.COL_PARENT_NAME]:
        df_proc[col] = df_proc[col].fillna('system_root').astype(str)

    df_proc = derive_grandparent_column(df_proc)

    df_file = load_csv_safe(file_file)
    file_agg = aggregate_context(
        df_file,
        agg_map={
            cfg.COL_FILE_NAME: 'Context_FilesCreated',
            cfg.COL_FILE_PATH: 'Context_FilePaths',
            cfg.COL_FILE_ACTION: 'Context_FileActions',
        }
    )
    df_proc = attach_limbs(
        df_proc, file_agg,
        ['Context_FilesCreated', 'Context_FilePaths', 'Context_FileActions']
    )

    df_net = load_csv_safe(net_file)
    net_agg = aggregate_context(
        df_net,
        agg_map={
            cfg.COL_NET_IP: 'Context_RemoteIPs',
            cfg.COL_NET_URL: 'Context_RemoteUrls',
            cfg.COL_NET_PROTOCOL: 'Context_Protocols',
        }
    )
    df_proc = attach_limbs(
        df_proc, net_agg,
        ['Context_RemoteIPs', 'Context_RemoteUrls', 'Context_Protocols']
    )

    return df_proc
