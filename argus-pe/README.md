# ARGUS

### Static Portable Executable Analyzer & Threat Triage Tool

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![ML](https://img.shields.io/badge/ML-scikit--learn-orange.svg)
![Signatures](https://img.shields.io/badge/signatures-YARA-red.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

**ARGUS** statically inspects unknown Windows executables (`.exe` / `.dll`) and returns a single, actionable threat score — *without ever running the file*. Security analysts routinely face hundreds of unknown samples a day, and triaging each one by hand is slow. ARGUS automates that first pass: it parses the file's internal structure, measures section entropy, flags suspicious memory permissions, matches known malicious patterns with YARA, and feeds the extracted features into a machine-learning classifier. Heuristics, signatures, and the ML model are combined into one threat score from **0 to 100**.

ARGUS is a triage aid, not a verdict engine. It is intentionally modular so analysts and developers can extend its heuristics, signatures, and training data over time.

---

## Table of Contents

- [About This Project](#about-this-project)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Understanding the Output](#understanding-the-output)
- [Project Structure](#project-structure)
- [Contributing & Tuning](#contributing--tuning)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## About This Project

ARGUS is a personal side project. My background is in cybersecurity and systems, and I built it to teach myself how machine learning, data science, and automation apply to security operations — a field I'm genuinely excited about but still early in.

That context matters for how to read this repo:

- It is **not** a production or enterprise-grade malware detection system, and I'm not claiming to be an ML expert. I'm a student using a real problem as a way to learn ML for cyber operations.
- It **is** a working, end-to-end triage pipeline. PE parsing, entropy analysis, YARA matching, and ML scoring all function together and produce a useful automated baseline. The model still needs more training data and tuning before it's dependable — and that's exactly the part I'm actively working on.

I'm building ARGUS in the open. As automation and agentic AI reshape security operations, I believe the analysts who understand *both* the security fundamentals and the ML underneath will have a real edge — and this project is how I'm building toward that.

---

## Key Features

- **Static-only analysis** — inspects the internal structure of a PE file without executing it.
- **Entropy scanning** — computes Shannon entropy per section to detect packing, compression, or encrypted payloads.
- **Structural heuristics** — flags suspicious traits such as writable-and-executable sections, abnormal headers, and hidden code stubs.
- **YARA signature matching** — detects known malware families and patterns via a pluggable rule set.
- **Machine-learning classification** — a Random Forest model estimates the probability that a sample is malicious.
- **Unified threat scoring** — combines all signals into a single 0–100 score mapped to `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`.
- **Multiple report formats** — human-readable terminal output, a shareable HTML report, or structured JSON for pipeline integration.

---

## How It Works

ARGUS runs each sample through a five-stage pipeline:

1. **PE parsing** — `pefile` reads the Windows header structures, sections, and imports.
2. **Entropy analysis** — per-section Shannon entropy is measured to surface packed or obfuscated code.
3. **Heuristic evaluation** — structural red flags accumulate *risk points* (e.g. abnormal section permissions, suspicious characteristics).
4. **Signature matching** — the file is checked against the YARA rule set for known malicious patterns.
5. **ML scoring & aggregation** — extracted features are passed to the Random Forest classifier, and the ML probability plus heuristic points are aggregated into a final threat score and level.

---

## Requirements

- Python **3.10** or higher
- The dependencies below (installed automatically via `pip install -e .`):

| Component | Library | Purpose |
|-----------|---------|---------|
| PE parsing | `pefile` | Read Windows header structures |
| Signatures | `yara-python` | Match known malware patterns |
| Machine learning | `scikit-learn` | Random Forest classifier |
| Data handling | `pandas`, `numpy` | Feature processing |
| Testing | `pytest` | Automated test suite |

---

## Installation

Clone the repository and set up an isolated virtual environment:

```bash
git clone https://github.com/anacoresis/argus-pe.git
cd argus-pe

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

> On Windows, activate the environment with `venv\Scripts\activate` instead.

---

## Usage

### Basic scan

Pass a file path to the `argus` command:

```bash
argus /path/to/target_file.exe
```

### Export an HTML report

```bash
argus /path/to/target_file.exe --format html --output report.html
```

### Export structured JSON

Useful for integrating ARGUS into other security tooling:

```bash
argus /path/to/target_file.exe --format json --output report.json
```

#### Example output

> *Illustrative — replace with output from a real scan, or a screenshot, before publishing.*

```text
  ARGUS  Static PE Triage
  ─────────────────────────────────────────────
  File            target_file.exe
  Threat Level    HIGH
  Threat Score    78 / 100
  ─────────────────────────────────────────────
  ML Malware Probability     0.83
  Heuristic Risk Points      24
  ─────────────────────────────────────────────
  Policy Findings
   • High-entropy section (.text) — likely packed
   • Writable + executable section (.data)
   • YARA match: suspicious_loader_stub
```

---

## Understanding the Output

Every scan produces a summary made up of four parts:

- **Threat Level** — `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`, derived from the overall 0–100 score.
- **ML Malware Probability** — the likelihood of malware predicted by the machine-learning model.
- **Heuristic Risk Points** — points added when suspicious structural features are detected (e.g. compressed code, abnormal memory permissions).
- **Policy Findings** — a plain-language list explaining *why* a file was flagged (e.g. hidden code stubs or matched signature patterns).

---

## Project Structure

> Representative layout — adjust to match your actual repository.

```text
argus-pe/
├── src/
│   └── argus/
│       └── core/
│           └── heuristics.py     # Heuristic risk-scoring rules
├── config/
│   └── yara_rules/               # YARA signature files (.yar)
├── data/
│   └── features.csv              # Training feature dataset
├── models/
│   └── argus_pe_model.pkl        # Trained Random Forest model
├── tests/                        # pytest test suite
├── pyproject.toml                # Package & dependency configuration
├── LICENSE
└── README.md
```

---

## Contributing & Tuning

ARGUS is designed as an open foundation. Analysts and developers can sharpen its detection without touching the core:

1. **Tune heuristic rules** — adjust risk-point thresholds or add new detection checks in `src/argus/core/heuristics.py`.
2. **Add custom YARA signatures** — drop new `.yar` files into `config/yara_rules/` to expand pattern matching automatically.
3. **Retrain the ML model** — update the feature dataset in `data/features.csv` with real-world samples and retrain the model artifact at `models/argus_pe_model.pkl`.
4. **Run the tests** — before submitting changes, make sure the suite passes:

   ```bash
   pytest
   ```

Pull requests and issues are welcome.

---

## Disclaimer

ARGUS performs **static analysis only** and never executes the samples it inspects. It is a triage aid intended to prioritize analyst attention — not a replacement for sandboxing, established antivirus engines, or manual reverse engineering. No detection tool is perfect: treat scores as guidance, not ground truth.

Always handle malware samples in an isolated, controlled environment. This software is provided "as is," without warranty of any kind, and is intended solely for legitimate defensive security research and education.

---

## License

This project is open source and available under the **MIT License**. See the [LICENSE](LICENSE) file for details.
