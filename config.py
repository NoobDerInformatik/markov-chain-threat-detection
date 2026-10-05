# Column names. Change these if your CSV headers differ.

JOIN_KEYS = ['DeviceName', 'pid']

# Process events (the spine)
COL_PROC_TIME = 'EventTimestampUTC'
COL_PROC_NAME = 'ProcessName'
COL_PARENT_NAME = 'ParentProcessName'
COL_GRANDPARENT_NAME = 'GrandparentProcessName'  # derived during ingestion

# File events
COL_FILE_NAME = 'FileName'
COL_FILE_PATH = 'FolderPath'
COL_FILE_ACTION = 'ActionType'

# Network events
COL_NET_IP = 'RemoteIP'
COL_NET_URL = 'RemoteUrl'
COL_NET_PORT = 'LocalPort'
COL_NET_PROTOCOL = 'Protocol'

# PID column in the file/network exports (KQL projects InitiatingProcessId -> pid)
COL_INIT_PID = 'pid'

# Scoring fields. Folder paths are more stable than random temp filenames,
# and URLs more stable than IPs (cloud IPs rotate). Fallbacks apply when empty.
FILE_SCORING_FIELD = 'Context_FilePaths'
FILE_SCORING_FALLBACK = 'Context_FilesCreated'

NET_SCORING_FIELD = 'Context_RemoteUrls'
NET_SCORING_FALLBACK = 'Context_RemoteIPs'

# Final score = ALPHA * markov + BETA * avg(file, net context)
ALPHA = 1.0   # markov transition score
BETA = 1.0    # combined context score