import streamlit as st
import re
import config as cfg

# (key, kind, tooltip). kind is text, float or list (comma separated in the UI).
SETTINGS = {
    "Threat Fusion Weights": [
        ("ALPHA", "float", "Weight on the Markov transition (structural) score in the final threat total. Raise it to trust process lineage more."),
        ("BETA", "float", "Weight on the combined file and network context score. Raise it to trust contextual evidence more."),
    ],
    "Scoring Field Selection": [
        ("FILE_SCORING_FIELD", "text", "Which file feature the engine scores on. The folder path is more stable than the filename, since temp folders are benign even when the filename inside is always new."),
        ("FILE_SCORING_FALLBACK", "text", "Field used when the primary file field is empty for a process."),
        ("NET_SCORING_FIELD", "text", "Which network feature the engine scores on. The remote URL or domain is more stable than the raw IP, which rotates often."),
        ("NET_SCORING_FALLBACK", "text", "Field used when the primary network field is empty for a process."),
    ],
    "Process Stream Columns (The Spine)": [
        ("COL_PROC_TIME", "text", "CSV column holding the event timestamp."),
        ("COL_PROC_NAME", "text", "CSV column for the child process name."),
        ("COL_PARENT_NAME", "text", "CSV column for the parent process name."),
        ("COL_GRANDPARENT_NAME", "text", "Name of the grandparent column. This one is derived during ingestion, not read from the CSV."),
    ],
    "File Stream Columns": [
        ("COL_FILE_NAME", "text", "CSV column for the created or modified file name."),
        ("COL_FILE_PATH", "text", "CSV column for the folder path of the file event."),
        ("COL_FILE_ACTION", "text", "CSV column describing the file action, e.g. FileCreated."),
    ],
    "Network Stream Columns": [
        ("COL_NET_IP", "text", "CSV column for the remote IP address."),
        ("COL_NET_URL", "text", "CSV column for the remote URL or domain."),
        ("COL_NET_PORT", "text", "CSV column for the local port."),
        ("COL_NET_PROTOCOL", "text", "CSV column for the connection protocol."),
    ],
    "Join Keys": [
        ("COL_INIT_PID", "text", "The column in the file and network streams that holds the initiating process PID. The context streams join back onto the process Spine on (DeviceName, this column)."),
        ("JOIN_KEYS", "list", "The pair of columns used to anchor every stream together. Comma separated."),
    ],
}


def _info(text):
    safe = text.replace('"', "&quot;")
    return f'<span class="cfg-info">i<span class="cfg-tip">{safe}</span></span>'


_CFG_CSS = """
<style>
    .cfg-info {
        display:inline-flex; align-items:center; justify-content:center;
        width:15px; height:15px; border-radius:50%; border:1px solid #4a515f;
        color:#9aa1ad; font-size:.62rem; font-style:italic; font-weight:700;
        cursor:help; position:relative; font-family:Georgia,serif; margin-left:6px;
    }
    .cfg-info:hover { background:#4c8bf5; color:#fff; border-color:#4c8bf5; }
    .cfg-info .cfg-tip {
        visibility:hidden; opacity:0; width:260px; background:#1d2330; color:#d7dbe2;
        text-align:left; border:1px solid #333b4a; border-radius:8px; padding:9px 11px;
        font-size:.74rem; font-style:normal; font-weight:400; line-height:1.35;
        position:absolute; z-index:60; bottom:150%; left:50%;
        transform:translateX(-50%); box-shadow:0 6px 20px rgba(0,0,0,.5); pointer-events:none;
        transition:opacity .15s ease;
    }
    .cfg-info:hover .cfg-tip { visibility:visible; opacity:1; }
    .cfg-label { font-size:.85rem; color:#c7ccd6; font-family:monospace; }
</style>
"""


def _current_value(key):
    # cfg may already carry session overrides applied at startup
    return getattr(cfg, key, "")


def _write_config_to_disk(values):
    """Rewrite only the assignment lines in config.py, keep everything else."""
    path = cfg.__file__
    with open(path, 'r') as f:
        source = f.read()

    for key, val in values.items():
        if isinstance(val, list):
            literal = "[" + ", ".join(f"'{v}'" for v in val) + "]"
        elif isinstance(val, float):
            literal = repr(val)
        else:
            literal = f"'{val}'"

        # keep any trailing inline comment
        pattern = rf"(?m)^({re.escape(key)}\s*=\s*)(.*?)(\s*#.*)?$"

        def repl(m):
            comment = m.group(3) or ""
            return f"{m.group(1)}{literal}{comment}"

        source = re.sub(pattern, repl, source, count=1)

    with open(path, 'w') as f:
        f.write(source)


def render_config_view():
    st.markdown(_CFG_CSS, unsafe_allow_html=True)
    st.title("⚙️ Configuration")
    st.caption("Adjust how the detector reads your data and weighs evidence. Changes apply immediately for this session. Use Save to disk to make them permanent.")

    edited = {}

    for group, items in SETTINGS.items():
        st.subheader(group)
        for key, kind, explanation in items:
            current = _current_value(key)
            label_html = f'<span class="cfg-label">{key}</span>{_info(explanation)}'
            st.markdown(label_html, unsafe_allow_html=True)

            if kind == "float":
                edited[key] = st.number_input(
                    key, value=float(current), step=0.1, key=f"cfg_{key}",
                    label_visibility="collapsed"
                )
            elif kind == "list":
                joined = ", ".join(current) if isinstance(current, list) else str(current)
                raw = st.text_input(
                    key, value=joined, key=f"cfg_{key}", label_visibility="collapsed"
                )
                edited[key] = [v.strip() for v in raw.split(",") if v.strip()]
            else:
                edited[key] = st.text_input(
                    key, value=str(current), key=f"cfg_{key}", label_visibility="collapsed"
                )
        st.divider()

    col_apply, col_save, col_reset = st.columns(3)

    with col_apply:
        if st.button("✅ Apply (this session)", width='stretch'):
            # patch the live module only, config.py is left alone
            for key, val in edited.items():
                setattr(cfg, key, val)
            st.session_state.cfg_overrides = dict(edited)
            st.success("Settings applied for this session.")

    with col_save:
        if st.button("💾 Save to disk", type="primary", width='stretch'):
            for key, val in edited.items():
                setattr(cfg, key, val)
            st.session_state.cfg_overrides = dict(edited)
            try:
                _write_config_to_disk(edited)
                st.success("Saved to config.py. Changes are now permanent.")
            except Exception as e:
                st.error(f"Could not write config.py: {e}")

    with col_reset:
        if st.button("↩️ Reset session overrides", width='stretch'):
            st.session_state.pop('cfg_overrides', None)
            st.info("Session overrides cleared. Restart to reload disk values fully.")
