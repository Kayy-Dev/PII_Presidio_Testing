import os

import streamlit as st

from crypto import AesGcmCipher, EnvironmentKeyProvider, FileKeyProvider, LocalKeyProvider
from language_utils import LANGUAGE_OPTIONS, resolve_language
from pii_service import ReversiblePIIService
from token_store import InMemoryTokenStore, PostgresTokenStore


@st.cache_resource
def load_service() -> tuple[ReversiblePIIService, str]:
    database_url = os.getenv("PII_DATABASE_URL")
    key_file_path = os.getenv("PII_KEY_FILE")

    if database_url:
        token_store = PostgresTokenStore(database_url)
        token_store.ensure_schema()
        storage_backend = "Postgres"
    else:
        token_store = InMemoryTokenStore()
        storage_backend = "In-memory"

    try:
        if key_file_path:
            cipher = AesGcmCipher(FileKeyProvider(key_file_path))
            key_backend = f"File key ({key_file_path})"
        else:
            cipher = AesGcmCipher(EnvironmentKeyProvider())
            key_backend = "Environment key"
    except Exception:
        cipher = AesGcmCipher(LocalKeyProvider())
        key_backend = "Local development key"

    service = ReversiblePIIService(token_store=token_store, cipher=cipher)
    return service, f"{storage_backend} + {key_backend}"


def simulate_llm_response(tokenized_text: str) -> str:
    return (
        "AI reply: I can work with the protected prompt safely. "
        f"Original intent preserved -> {tokenized_text}"
    )


service, backend_label = load_service()

st.title("PII Tokenizer")
st.markdown(
    "Paste text below to detect PII, replace it with prompt-safe tokens, "
    "and restore the original values after a simulated AI response."
)
st.caption(f"Storage backend: {backend_label}")

language_label = st.selectbox("Language", list(LANGUAGE_OPTIONS))
selected_language = LANGUAGE_OPTIONS[language_label]

# Text input
input_text = st.text_area(
    "Input Text",
    height=200,
    placeholder=(
        "Paste text with PII here, e.g. My name is Kayy Kayy，我叫王小明。 "
        "Email me at kayy.kayy@company.com 或者拨打 13800138000。"
    ),
)

if st.button("Tokenize For AI") and input_text.strip():
    resolved_language, resolution_source = resolve_language(input_text, selected_language)
    tokenization = service.tokenize(input_text, language=resolved_language)

    if resolution_source == "auto":
        st.caption("Language used: en + zh (auto mode)")
    elif resolution_source == "manual":
        st.caption(f"Language used: {resolved_language} (manual override)")
    else:
        st.caption(f"Language used: {resolved_language}")

    st.subheader("Detected PII Entities")
    if tokenization.detected_entities:
        for entity in tokenization.detected_entities:
            st.markdown(
                f"- **{entity.entity_type}**: `{entity.text}` (confidence: {entity.score:.2f})"
            )
    else:
        st.info("No PII detected.")

    st.subheader("Request ID")
    st.code(tokenization.request_id)

    st.subheader("Tokenized Prompt Sent To AI")
    st.success(tokenization.tokenized_text)

    st.subheader("Token Map")
    if tokenization.tokens:
        for token, original_value in tokenization.tokens.items():
            st.markdown(f"- `{token}` -> `{original_value}`")
    else:
        st.info("No token mappings were created.")

    model_response = simulate_llm_response(tokenization.tokenized_text)
    restored_response = service.detokenize(model_response, tokenization.request_id)

    st.subheader("AI Response With Tokens")
    st.info(model_response)

    st.subheader("Restored Final Response")
    st.success(restored_response)
