# Copilot Instructions

## Project Overview

- This repository is a local PII detection and reversible tokenization demo built around Presidio, spaCy, and Streamlit.
- The main user flow is: detect PII -> replace spans with typed placeholders -> encrypt original values -> store encrypted token mappings -> restore values later with the same request id.
- Read [README.md](../README.md) for environment setup, optional key configuration, and runtime examples.

## Core Files

- `app.py`: Streamlit entry point and UI orchestration.
- `pii_service.py`: main service API for detect, tokenize, detokenize, and round-trip flows.
- `analyzer_factory.py`: shared Presidio analyzer construction, regex recognizers, and post-processing cleanup.
- `crypto.py`: AES-GCM encryption plus environment, file, and local key providers.
- `token_store.py`: token persistence abstractions with in-memory and Postgres implementations.
- `language_utils.py`: language selection for manual and multilingual auto mode.

## Commands Agents Can Run

- Install dependencies: `pip install -r requirements.txt`
- Download models: `python -m spacy download en_core_web_lg` and `python -m spacy download zh_core_web_sm`
- Run UI: `streamlit run app.py --server.headless true`
- Run CLI example: `python analyzer_test.py`
- Run auto-mode regression tests: `python -m unittest test_auto_mode.py`
- Run recognizer example: `python custom_recognizer.py`

## Working Conventions

- Keep changes small and preserve the current module boundaries. Most business logic belongs in `pii_service.py`, not in `app.py`.
- If you add or change built-in recognizers for the real app flow, update `build_analyzer()` in `analyzer_factory.py`. `custom_recognizer.py` is only a standalone example.
- Preserve support for both English (`en`) and Chinese (`zh`) unless the task explicitly narrows scope. `Auto` mode is expected to analyze with both languages on the same input.
- Keep placeholder tokens typed and sequential, using the existing `{{ENTITY_N}}` format.
- Preserve request-scoped tokenization. Detokenization depends on the original `request_id`.
- Keep encrypted storage behavior intact: store ciphertext, nonce, and key version, not plaintext originals.
- Match the current style: frozen dataclasses for transport objects, straightforward functions, minimal abstraction.

## Repo-Specific Pitfalls

- `app.py` caches service initialization with `@st.cache_resource`; changes to environment-driven storage or key configuration usually require restarting Streamlit.
- `analyzer_factory.py` removes false positives and may reclassify some `ORGANIZATION` detections to `PERSON`. Do not bypass `analyze_text()` unless you also preserve that cleanup step.
- The Postgres token store only filters expired rows on read. Cleanup of expired rows is manual through `delete_expired()`.
- The in-memory token store purges expired records opportunistically during reads.
- This repo now has a small `unittest` regression file for auto mode in `test_auto_mode.py`, but most validation is still example-script driven.
- spaCy model availability is a hard dependency for analyzer construction.

## Change Guidance

- Prefer fixing behavior at the service or analyzer layer before changing the UI.
- When changing token storage, keep both `InMemoryTokenStore` and `PostgresTokenStore` behavior aligned where practical.
- When changing crypto behavior, maintain compatibility with key version lookups and AES-GCM URL-safe encoding.
- When changing language handling, keep `Auto`, `English`, and `Chinese` mode behavior consistent between `language_utils.py`, `app.py`, and `analyzer_factory.py`.

## Validation

- For detection and tokenization changes, run `python analyzer_test.py`.
- For auto-mode changes, run `python -m unittest test_auto_mode.py`.
- For UI changes, run `streamlit run app.py --server.headless true`.
- For recognizer experiments, use `python custom_recognizer.py`, but do not treat that file as the main integration path.