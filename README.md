# PII Scrubber

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A local PII (Personally Identifiable Information) detection and anonymization tool built with [Microsoft Presidio](https://github.com/microsoft/presidio), [spaCy](https://spacy.io/), and [Streamlit](https://streamlit.io/).

---

## Features

- Detects common PII entities: names, email addresses, phone numbers, SSNs, street addresses, ZIP codes, and locations
- Custom employee ID recognizer (`EMP-00123` format)
- Filters false positives caused by spaCy's English NER model (e.g. phrases like "My Email is" being tagged as PERSON)
- Reclassifies non-Western names mistagged as ORGANIZATION back to PERSON
- Interactive Streamlit UI for real-time analysis and anonymization

---

## Project Structure

```
PII_testing/
├── venv/                   # Virtual environment (not committed)
├── app.py                  # Streamlit UI — main application
├── analyzer_test.py        # Core script — runs PII detection without UI
├── custom_recognizer.py    # Custom EMPLOYEE_ID recognizer example
├── requirements.txt        # Python dependencies
├── .gitignore
└── README.md
```

---

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Download the spaCy English model

```bash
python -m spacy download en_core_web_lg
```

---

## Usage

### Run the Streamlit app

```bash
streamlit run app.py --server.headless true
```

Then open http://localhost:8501 in your browser.

> **Note:** The `--server.headless true` flag skips Streamlit's first-run interactive email prompt, which would otherwise block the process.

### Run the core script (no UI)

```bash
python analyzer_test.py
```

### Run the custom recognizer example

```bash
python custom_recognizer.py
```

---

## Detected Entity Types

| Entity | Example |
|---|---|
| `PERSON` | Sarah Johnson, Pan Mhue Khin Khin |
| `EMAIL_ADDRESS` | sarah.johnson@gmail.com |
| `PHONE_NUMBER` | (312) 555-9876 |
| `US_SSN` | 456-78-9012 |
| `LOCATION` | 456 Oak Avenue, Chicago, IL 60601 |
| `EMPLOYEE_ID` | EMP-00123 |

---

## Known Limitations

- **Non-Western names** (e.g. Burmese, Chinese, Arabic) are often partially detected or mis-tagged by spaCy's English-only model. Partial fixes are in place via context-aware reclassification.
- **`123-45-6789`** is intentionally blocked by Presidio as a known dummy/test SSN.
- **Street addresses** without a recognised suffix (Street, Ave, Rd, etc.) will not be detected by the regex recognizer.
- The `en_core_web_lg` model was trained on English/Western text — accuracy degrades on multilingual input.

---

## Dependencies

| Package | Purpose |
|---|---|
| `presidio-analyzer` | PII entity detection engine |
| `presidio-anonymizer` | Replaces detected PII with placeholders |
| `spacy` | NLP backend (NER, tokenization) |
| `streamlit` | Web UI |

---

## License

This project is licensed under the [MIT License](LICENSE).
