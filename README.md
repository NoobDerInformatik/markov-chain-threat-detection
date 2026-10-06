# Context-Aware Weighted Markov Chains for Detecting Malicious Process Paths

A Streamlit app for threat hunting in endpoint telemetry. It scores every process by how unusual its family tree is (grandparent → parent → child) using a Markov chain trained on benign activity, and adds evidence from the files and network connections the process touched.

Rare lineages like `winword.exe → cmd.exe → powershell.exe` score high while everyday ones like `explorer.exe → chrome.exe` score low. Scores are in bits (`-log2(probability)`), so file, network and process scores share the same unit.

## How it works

1. **Process lineage (required).** Each process is matched to its parent and grandparent by `(DeviceName, pid)`. The model learns `P(child | grandparent, parent)` from benign data with Laplace smoothing. Unseen lineages fall back step by step: known context with an unseen child, known parent, parent → child pair, process name only, and finally a fixed penalty of 20 bits.
2. **File and network context (optional).** File and network events are grouped per process. Each folder path or URL gets a rarity weight, and a process gets the score of its rarest item.
3. **Total score.** `Total = ALPHA × process score + BETA × average(file, network)`. Both weights can be changed on the Config page.
4. **Alerting.** Events above the 95th percentile of the benign baseline's scores are flagged as high risk.

Each stream can run in one of two modes:

- **Baseline Comparison:** scores against a model trained on known-good data. The most reliable option.
- **Self-Learning:** trains on the uploaded data itself and highlights outliers inside it. Useful for a quick look at an unknown host, but attacks that repeat often can blend in.

## Installation

Requires Python 3.11 or newer (developed on 3.14).

```bash
git clone https://github.com/NoobDerInformatik/markov-chain-hunting.git
cd markov-chain-hunting
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Running the app

Run it from the project folder, since baselines are read from `./baselines`:

```bash
python -m streamlit run app.py
```

Streamlit opens the app in your browser at http://localhost:8501.

## Using the app

The sidebar has four pages.

### 1. Train: build a baseline

No baselines ship with the repository, so start here if you want to use Baseline Comparison.

1. Upload a **benign process CSV**: telemetry from a period you trust to be clean. More data gives a better model.
2. Optionally upload benign **file** and **network** CSVs.
3. Click **Train Baselines**.

The baseline is saved to `baselines/` with a timestamp, e.g. `default_markov_2026-10-05_14-30-52.json`, together with its alert threshold. You can train as often as you like. Existing baselines can be inspected, renamed or deleted on the same page.

You can also train from the command line. Place your files in `data/` as `benign_process.csv`, `benign_file.csv` and `benign_network.csv`, then run:

```bash
python modules/train_baselines.py --train all
```

Use `--train process`, `file` or `network` to train only some of them.

### 2. Detect: score new data

1. Upload the **process CSV** you want to investigate (required).
2. Optionally upload matching **file** and **network** CSVs.
3. For each stream, choose **Self-Learning** or **Baseline Comparison**. When comparing, pick which baseline to use; you can mix baselines from different training runs.
4. Choose the **Markov order**: second-order (grandparent → parent → child) or first-order (parent → child).
5. Click **Start Calculation**.

The dashboard shows summary cards, a timeline of threat scores with the alert threshold, and the **Anomaly Detection Queue** sorted by score. Click any row to open the **Deep Dive** view with the score breakdown, user and device details, the process lineage with command lines, and the file and network activity of that process.

**Reset** clears the uploads and results.

### 3. Results: evaluate detection quality

If your process CSV has a `verdict` column (`malicious` or `benign` per row), this page evaluates the last Detect run:

- precision, recall, F1 and accuracy at an adjustable threshold
- confusion matrix
- ROC curve and AUC
- incident-level detection rate (grouped by device)
- list of false positives and false negatives

### 4. Config: adjust settings

Change the `ALPHA` / `BETA` weights, which fields are used for scoring, and the CSV column names if your export uses different headers. **Apply** changes the settings for the current session; **Save to disk** writes them to `config.py`.

## Input data format

The column names below are the defaults. They can be changed on the Config page or in `config.py`.

**Process CSV (required)**

| Column | Required | Description |
|---|---|---|
| `EventTimestampUTC` | yes | Event time, e.g. `2026-03-29T08:00:00Z` |
| `DeviceName` | yes | Host name |
| `pid` | yes | Process ID |
| `ppid` | yes | Parent process ID |
| `ProcessName` | yes | Process name, e.g. `powershell.exe` |
| `ParentProcessName` | yes | Parent process name |
| `ProcessFilePath`, `ProcessCommandLine` | no | Shown in the Deep Dive |
| `Username`, `JobTitle`, `Department` | no | User context in the Deep Dive |
| `OSPlatform`, `MachineGroup`, `RiskLevel` | no | Device context in the Deep Dive |
| `verdict` | no | `malicious` / `benign`, needed for the Results page |

**File CSV (optional)**

| Column | Description |
|---|---|
| `DeviceName`, `pid` | ID of the process that caused the event, used to join it to the process data |
| `FolderPath` | Folder of the file (main scoring field) |
| `FileName` | File name (used when the folder path is empty) |
| `ActionType` | e.g. `FileCreated` |

**Network CSV (optional)**

| Column | Description |
|---|---|
| `DeviceName`, `pid` | ID of the process that made the connection |
| `RemoteUrl` | Remote domain (main scoring field) |
| `RemoteIP` | Remote IP (used when the URL is empty) |
| `Protocol` | e.g. `Tcp` |

Sample files are in `data/` (`test_process.csv`, `test_file.csv`, `test_network.csv`) for trying out the interface.

### Exporting from Microsoft Defender

If you use Microsoft Defender advanced hunting, queries along these lines produce the expected columns:

```kql
DeviceProcessEvents
| project EventTimestampUTC = Timestamp, DeviceName, pid = ProcessId, ppid = InitiatingProcessId,
          ProcessName = FileName, ProcessFilePath = FolderPath, ProcessCommandLine,
          ParentProcessName = InitiatingProcessFileName, Username = AccountName

DeviceFileEvents
| project EventTimestampUTC = Timestamp, DeviceName, pid = InitiatingProcessId,
          FileName, FolderPath, ActionType

DeviceNetworkEvents
| project EventTimestampUTC = Timestamp, DeviceName, pid = InitiatingProcessId,
          RemoteUrl, RemoteIP, Protocol
```

## Project structure

```
app.py                 Entry point, Detect page and navigation
config.py              Column names and scoring weights
modules/
  ingestion.py         CSV loading, grandparent derivation, joining file/network events
  markov_engine.py     Markov model training and scoring
  context_engine.py    File and network rarity weights
  baseline_manager.py  Saving, listing, renaming and deleting baselines
  train_baselines.py   Command-line trainer
views/                 Dashboard, Deep Dive, Train, Results and Config pages
data/                  Sample CSV files
baselines/             Trained baselines (created on first training, not in git)
```


