import streamlit as st
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

# Words/phrases that spaCy commonly mis-tags as PERSON
FALSE_POSITIVE_PERSONS = {
    "email", "my email", "my email is",
    "phone", "my phone", "my phone is",
    "my name", "name", "address", "my address",
    "the", "is", "at", "number", "my number"
}

# Phrases that spaCy commonly mis-tags as ORGANIZATION
FALSE_POSITIVE_ORGS = {
    "social security number", "my social security number",
    "ssn", "my ssn", "employee id", "my employee id",
    "security number", "my security number",
}

# Real organizations always contain one of these indicator words
ORG_INDICATORS = {
    "inc", "ltd", "llc", "corp", "corporation", "company", "co",
    "association", "foundation", "institute", "university", "college",
    "bank", "group", "department", "agency", "bureau", "ministry",
    "hospital", "clinic", "school", "church", "club",
}


@st.cache_resource
def load_engines():
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()

    # Lower threshold so long non-Western names are more fully captured
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, default_score_threshold=0.35)

    # High-confidence email regex — overrides spaCy's PERSON tag on email strings
    email_pattern = Pattern(
        name="email_pattern",
        regex=r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        score=0.99
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[email_pattern])
    )

    # Street address: e.g. "456 Oak Avenue", "123 N Main St"
    street_pattern = Pattern(
        name="street_address_pattern",
        regex=(
            r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|"
            r"Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Highway|Hwy|"
            r"Terrace|Ter|Circle|Cir|Trail|Trl)\b"
        ),
        score=0.85
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="LOCATION", patterns=[street_pattern])
    )

    # US state + ZIP code: e.g. "IL 60601" or just "60601"
    zip_pattern = Pattern(
        name="us_zip_pattern",
        regex=r"\b(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b",
        score=0.6
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="LOCATION", patterns=[zip_pattern])
    )

    anonymizer = AnonymizerEngine()
    return analyzer, anonymizer


def clean_results(results, text):
    """Remove false-positive detections caused by spaCy's English NER model."""
    email_spans = [
        (r.start, r.end) for r in results if r.entity_type == "EMAIL_ADDRESS"
    ]
    ssn_spans = [
        (r.start, r.end) for r in results if r.entity_type == "US_SSN"
    ]

    cleaned = []
    for r in results:
        matched_text = text[r.start:r.end].lower().strip()

        if r.entity_type == "PERSON":
            # Rule 1: drop PERSON if it overlaps with an EMAIL_ADDRESS span
            overlaps_email = any(r.start < ee and r.end > es for es, ee in email_spans)
            if overlaps_email:
                continue
            # Rule 2: drop PERSON if matched text is a known false-positive phrase
            if matched_text in FALSE_POSITIVE_PERSONS:
                continue
            # Rule 3: drop PERSON if the matched text contains '@' (it's an email)
            if "@" in matched_text:
                continue

        elif r.entity_type == "ORGANIZATION":
            # Rule 4: drop ORG if it overlaps with a US_SSN span
            overlaps_ssn = any(r.start < ee and r.end > es for es, ee in ssn_spans)
            if overlaps_ssn:
                continue

            # Rule 5: drop ORG if matched text is a known false-positive phrase
            if matched_text in FALSE_POSITIVE_ORGS:
                continue

            # Rule 6: if no org indicator words found, check if it's a
            # misclassified personal name (preceded by "I am", "my name is", etc.)
            words = set(matched_text.split())
            has_org_indicator = bool(words & ORG_INDICATORS)
            if not has_org_indicator:
                context_before = text[max(0, r.start - 25):r.start].lower()
                is_personal_context = any(
                    p in context_before
                    for p in ["i am ", "i'm ", "my name is ", "name is ", "call me "]
                )
                if is_personal_context:
                    # Reclassify as PERSON instead of dropping
                    from presidio_analyzer import RecognizerResult
                    cleaned.append(RecognizerResult(
                        entity_type="PERSON",
                        start=r.start,
                        end=r.end,
                        score=r.score
                    ))
                    continue
                # Drop ORG with no org indicators and no personal context —
                # almost always a mis-tag (e.g. foreign words, abbreviations)
                continue

        cleaned.append(r)

    return cleaned


analyzer, anonymizer = load_engines()

st.title("🔍 PII Scrubber")
st.markdown("Paste any text below to detect and anonymize personally identifiable information.")

# Text input
input_text = st.text_area("Input Text", height=200, placeholder="Paste text with PII here...")

if st.button("Analyze & Anonymize") and input_text.strip():

    # Analyze
    results = analyzer.analyze(text=input_text, language="en")

    # Remove false positives
    filtered_results = clean_results(results, input_text)

    # Show detected entities
    st.subheader("Detected PII Entities")
    if filtered_results:
        for r in filtered_results:
            entity_text = input_text[r.start:r.end]
            st.markdown(f"- **{r.entity_type}**: `{entity_text}` (confidence: {r.score:.2f})")
    else:
        st.info("No PII detected.")

    # Anonymize
    anonymized = anonymizer.anonymize(text=input_text, analyzer_results=filtered_results)

    st.subheader("Anonymized Text")
    st.success(anonymized.text)
