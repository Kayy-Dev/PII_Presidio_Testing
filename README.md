# PII Scrubber

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A local PII (Personally Identifiable Information) detection and anonymization tool built with [Microsoft Presidio](https://github.com/microsoft/presidio), [spaCy](https://spacy.io/), and [Streamlit](https://streamlit.io/).

---

## Features

- Detects common PII entities: names, email addresses, phone numbers, SSNs, street addresses, ZIP codes, and locations
- Custom employee ID recognizer (`EMP-00123` format)
- Supports English and Chinese spaCy pipelines with manual language selection or automatic detection
- Reversible tokenization for LLM prompts using typed placeholders such as `{{PERSON_1}}`
- AES-GCM encryption for stored original values before they are written to a token store
- In-memory token store for local demos and Postgres token store for production deployments
- Filters false positives caused by spaCy's English NER model (e.g. phrases like "My Email is" being tagged as PERSON)
- Reclassifies non-Western names mistagged as ORGANIZATION back to PERSON
- Interactive Streamlit UI for real-time analysis, tokenization, and restoration

---

## Project Structure

```
PII_testing/
├── venv/                   # Virtual environment (not committed)
├── analyzer_factory.py     # Shared Presidio analyzer factory and result cleanup
├── app.py                  # Streamlit UI — tokenization demo application
├── analyzer_test.py        # Minimal CLI reversible-tokenization example
├── crypto.py               # AES-GCM encryption and key-provider abstractions
├── custom_recognizer.py    # Custom EMPLOYEE_ID recognizer example
├── pii_service.py          # Reversible detect -> tokenize -> detokenize service
├── token_store.py          # In-memory and Postgres token-store implementations
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

### 2a. Optional: generate a local AES-GCM key

For persistent encrypted token mapping outside the demo fallback, generate a 32-byte base64 key and export it as `PII_AES_KEY`.

```bash
python -c "from crypto import generate_key_base64; print(generate_key_base64())"
```

Then set:

```bash
# Windows PowerShell
$env:PII_AES_KEY = "<paste-generated-key>"
$env:PII_AES_KEY_VERSION = "dev-v1"
```

### 2b. Optional: create a file-backed local key provider

If you want a local KMS-style file instead of environment variables, generate a key file once:

```bash
python -c "from crypto import create_key_file; print(create_key_file('local_keys.json'))"
```

This creates a JSON file like:

```json
{
	"current_key_version": "local-file-v1",
	"keys": {
		"local-file-v1": "<base64-key>"
	}
}
```

Then set:

```bash
# Windows PowerShell
$env:PII_KEY_FILE = "D:\PythonProject\PII_testing\local_keys.json"
```

When `PII_KEY_FILE` is set, the app uses the file-backed key provider before falling back to environment variables or the in-process development key.

### 3. Download the spaCy models

```bash
python -m spacy download en_core_web_lg
python -m spacy download zh_core_web_sm
```

---

## Usage

### Run the Streamlit app

```bash
streamlit run app.py --server.headless true
```

Then open http://localhost:8501 in your browser.

Choose `Auto`, `English`, or `Chinese` in the app before tokenizing. `Auto` now runs both the English and Chinese analyzers on the same input and merges the results, which is useful for mixed-language text.

Mixed-language example for `Auto` mode:

```text
My name is Kayy Kayy，我叫王小明。
Email me at kayy.kayy@company.com 或者拨打 13800138000。
```

> **Note:** The `--server.headless true` flag skips Streamlit's first-run interactive email prompt, which would otherwise block the process.
>
> If `PII_DATABASE_URL` is not set, the app uses an in-memory token store.
> If `PII_AES_KEY` is not set, the app falls back to a process-local development key.

### Run the reversible tokenization example (no UI)

```bash
python analyzer_test.py
```

The example now runs one English sample, one Chinese sample, and one mixed-language `auto` sample.

### Run the custom recognizer example

```bash
python custom_recognizer.py
```

### Run the auto-mode regression tests

```bash
python -m unittest test_auto_mode.py
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

## Reversible Tokenization Flow

This project now supports a prompt-safe LLM pattern:

1. Detect PII with Presidio.
2. Replace detected spans with typed placeholders such as `{{PERSON_1}}`.
3. Encrypt each original value with AES-GCM.
4. Store the encrypted token map in memory or Postgres.
5. Send only the tokenized prompt to the LLM.
6. Restore the original values after the model responds.

Example:

```text
Input:
My name is Kayy Kayy and my employee id is EMP-00123.

Prompt sent to AI:
My name is {{PERSON_1}} and my employee id is {{EMPLOYEE_ID_1}}.

Restored output:
My name is Kayy Kayy and my employee id is EMP-00123.
```

Mixed-language example:

```text
Input:
My name is Kayy Kayy，我叫王小明。
Email me at kayy.kayy@company.com 或者拨打 13800138000。

Prompt sent to AI:
My name is {{PERSON_1}}，我叫{{PERSON_2}}。
Email me at {{EMAIL_ADDRESS_1}} 或者拨打 {{PHONE_NUMBER_1}}。

Restored output:
My name is Kayy Kayy，我叫王小明。
Email me at kayy.kayy@company.com 或者拨打 13800138000。
```

Do not send encrypted ciphertext to the model. The model should only see semantic tokens.

---

## Production Postgres Mode

Set `PII_DATABASE_URL` to switch the token map to Postgres storage.

```bash
# Example
$env:PII_DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/pii_testing"
```

Recommended local persistence test:

```bash
$env:PII_DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/pii_testing"
$env:PII_KEY_FILE = "D:\PythonProject\PII_testing\local_keys.json"
python -m streamlit run app.py --server.headless true
```

The app automatically creates the `pii_token_map` table and indexes on startup.

Recommended production setup:

- Store only encrypted original values in the token map.
- Use a managed KMS or vault for your AES-GCM key material.
- Keep `request_id` scoped to one user request or one chat turn.
- Add a scheduled cleanup job for expired token rows.
- Avoid logging raw PII or decrypted token values.

## Known Limitations

- **Chinese names and organizations** depend on the quality of the installed Chinese spaCy model. Regex-based entities such as email, postal code, and mobile numbers are generally more reliable than NER-based entities.
- **`123-45-6789`** is intentionally blocked by Presidio as a known dummy/test SSN.
- **Street addresses** without a recognised suffix (Street, Ave, Rd, etc.) will not be detected by the regex recognizer.
- The English address recognizers remain US-centric. Chinese address parsing is intentionally limited to a practical first pass for this release.

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
