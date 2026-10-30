# RansomWatch 🛡️

### Behaviour-Based Ransomware Detection and Prevention System

**RansomWatch** is a functional cybersecurity system engineered to detect ransomware attacks by monitoring file system behaviour, identifying statistical outliers using machine learning (Isolation Forest), enriching alerts with threat intelligence indicators, and mitigating damage through controlled, safety-bounded incident response.

---

## 🏗️ Technology Stack

- **Backend**: Python 3.12+, FastAPI, Uvicorn, Pydantic v2
- **Frontend Dashboard**: Streamlit, Plotly
- **Machine Learning**: Scikit-learn (Isolation Forest), Joblib
- **File System Monitoring**: Watchdog
- **Database**: SQLite3 (Thread-safe connection pool with WAL mode)
- **Data Processing**: Pandas, NumPy
- **Testing**: Pytest

---

## 📂 Architecture & Project Structure

```
RansomWatch/
├── config.py                 # Central configuration and risk thresholds
├── main.py                   # FastAPI backend entry point
├── run_dashboard.py          # Streamlit dashboard launcher
├── requirements.txt          # Python dependencies
├── database/
│   ├── db.py                 # SQLite database manager & connection pool
│   └── models.py             # Pydantic data schemas and SQLite models
├── monitoring/
│   ├── file_monitor.py       # Watchdog filesystem observer
│   ├── entropy.py            # Shannon entropy calculation engine
│   └── canary.py             # Decoy canary file placement & tripwire detection
├── detection/
│   ├── engine.py             # Multi-signal ransomware heuristic detection engine
│   └── risk_scorer.py        # 0–100 risk scoring & alert structuring
├── ml/
│   ├── model.py              # Isolation Forest anomaly detection model
│   ├── features.py           # Feature extraction pipeline (13 behavioral features)
│   └── synthetic_data.py     # Controlled synthetic activity dataset generator
├── threat_intel/
│   ├── local_db.py           # Local sample threat indicators database (IOCs)
│   └── enrichment.py         # File hash & extension threat enrichment
├── response/
│   ├── incident.py           # DETECT → ASSESS → CONTAIN → ALERT → RECOVER orchestrator
│   ├── containment.py        # Safe containment adapter with safety guarantees
│   └── recovery.py           # Backup snapshots, manifest hashes & recovery plan
├── dashboard/
│   └── app.py                # Interactive Streamlit operations dashboard
└── tests/
    ├── test_infrastructure.py
    ├── test_monitoring_detection.py
    ├── test_ml.py
    └── test_response.py
```

---

## 🧩 The Five Core Modules

### 1. Real-Time File Behaviour Monitoring (`monitoring/`)
- **Explicit Directory Monitoring**: Monitors only user-selected folders (never scans the full drive or private personal data by default).
- **Event Tracking**: Captures file creations, modifications, deletions, and moves.
- **Shannon Entropy Calculation**: Identifies high-entropy content ($> 7.0$) characteristic of encrypted ciphertexts.
- **Tripwire Canary Decoys**: Deploys benign `.docx` and `.xlsx` canary files that trigger instant alerts when altered.

### 2. Multi-Signal Detection Engine (`detection/`)
- Evaluates sliding time windows against multiple behavioural signals:
  - Rapid file modification bursts
  - Mass extension swapping (e.g. `.docx` $\rightarrow$ `.locked`)
  - Sudden entropy spikes
  - Unusually rapid file operation frequency ($> 20\text{ ops/min}$)
  - Canary file access
- Generates a composite risk score from $0$ to $100$ categorized into Low, Medium, High, and Critical severity.
- Provides transparent explanations for every detection reason.

### 3. Machine Learning Anomaly Detection (`ml/`)
- Uses **Isolation Forest** from Scikit-Learn to model normal filesystem activity.
- Extracts 13 behavioral metrics:
  - `files_modified`, `files_renamed`, `files_created`, `files_deleted`
  - `total_operations`, `operation_frequency`, `unusual_ext_ratio`
  - `avg_entropy`, `max_entropy`, `entropy_std`
  - `canary_interactions`, `unique_extensions`, `ext_change_count`
- Generates decision anomaly scores and outlines contributing behavioural anomalies.
- Clearly distinguishes statistical anomalies from confirmed ransomware.

### 4. Threat Intelligence Enrichment (`threat_intel/`)
- Correlates file hashes (MD5, SHA256) and extensions with a local indicator database (WannaCry, LockBit, CryptoLocker, etc.).
- Transparently tags demo records as demonstration data.
- Strict privacy policy: Never uploads user files or sensitive data to external cloud APIs without consent.

### 5. Controlled Incident Response & Recovery (`response/`)
- Implements the complete lifecycle: **DETECT $\rightarrow$ ASSESS $\rightarrow$ CONTAIN $\rightarrow$ ALERT $\rightarrow$ RECOVER**.
- **Simulation Mode by Default**: Safely logs actions without mutating processes or network settings.
- **Safety Protections**:
  - Never terminates arbitrary operating system processes.
  - Never deletes or modifies user documents.
  - Requires explicit configuration and a two-step confirmation passphrase (`CONFIRM_CONTAINMENT`) before enabling real containment actions.
- **Backup & Recovery**:
  - Creates compressed backup snapshots with SHA256 file manifests.
  - Provides structured step-by-step forensic checklists.
  - Never claims files are auto-restored without real validated recovery execution.

---

## 🚀 Getting Started

### 1. Setup Environment
```bash
# Navigate to project directory
cd C:\Users\rawat\.gemini\antigravity\scratch\RansomWatch

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install requirements (already installed in provided env)
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
pytest -v
```
All 49 unit and integration tests will execute.

### 3. Launch Backend API
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at: `http://localhost:8000/docs`

### 4. Launch Streamlit Operations Dashboard
In a second terminal:
```bash
python run_dashboard.py
# or
streamlit run dashboard/app.py
```
Open `http://localhost:8501` in your browser.

---

## 🧪 Safe Attack Simulator

To evaluate detection without risking your personal files:
1. Open the Streamlit dashboard and navigate to **Safe Attack Simulator**.
2. Select one of the benign test scenarios (e.g. *High-Entropy Mass Encryption Burst* or *Ransomware Extension Swapping*).
3. Click **Execute Selected Simulation**.
4. Check **Threat Alerts** and **Executive Overview** to see the multi-signal detection engine flag the suspicious behaviour in real time.
