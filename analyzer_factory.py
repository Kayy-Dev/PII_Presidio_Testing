from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider


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


@lru_cache(maxsize=1)
def build_analyzer() -> AnalyzerEngine:
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()

    # Lower threshold so long non-Western names are more fully captured.
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, default_score_threshold=0.35)

    email_pattern = Pattern(
        name="email_pattern",
        regex=r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        score=0.99,
    )
    street_pattern = Pattern(
        name="street_address_pattern",
        regex=(
            r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|"
            r"Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Highway|Hwy|"
            r"Terrace|Ter|Circle|Cir|Trail|Trl)\b"
        ),
        score=0.85,
    )
    zip_pattern = Pattern(
        name="us_zip_pattern",
        regex=r"\b(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b",
        score=0.6,
    )
    employee_id_pattern = Pattern(
        name="employee_id_pattern",
        regex=r"\bEMP-\d{5}\b",
        score=0.85,
    )

    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[email_pattern])
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="LOCATION", patterns=[street_pattern])
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="LOCATION", patterns=[zip_pattern])
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="EMPLOYEE_ID", patterns=[employee_id_pattern])
    )

    return analyzer


def clean_results(results: list[RecognizerResult], text: str) -> list[RecognizerResult]:
    """Remove common false positives caused by the English spaCy model."""
    email_spans = [
        (result.start, result.end)
        for result in results
        if result.entity_type == "EMAIL_ADDRESS"
    ]
    ssn_spans = [
        (result.start, result.end)
        for result in results
        if result.entity_type == "US_SSN"
    ]

    cleaned: list[RecognizerResult] = []
    for result in results:
        matched_text = text[result.start:result.end].lower().strip()

        if result.entity_type == "PERSON":
            overlaps_email = any(
                result.start < email_end and result.end > email_start
                for email_start, email_end in email_spans
            )
            if overlaps_email or matched_text in FALSE_POSITIVE_PERSONS or "@" in matched_text:
                continue

        elif result.entity_type == "ORGANIZATION":
            overlaps_ssn = any(
                result.start < ssn_end and result.end > ssn_start
                for ssn_start, ssn_end in ssn_spans
            )
            if overlaps_ssn or matched_text in FALSE_POSITIVE_ORGS:
                continue

            words = set(matched_text.split())
            has_org_indicator = bool(words & ORG_INDICATORS)
            if not has_org_indicator:
                context_before = text[max(0, result.start - 25):result.start].lower()
                is_personal_context = any(
                    phrase in context_before
                    for phrase in ["i am ", "i'm ", "my name is ", "name is ", "call me "]
                )
                if is_personal_context:
                    cleaned.append(
                        RecognizerResult(
                            entity_type="PERSON",
                            start=result.start,
                            end=result.end,
                            score=result.score,
                        )
                    )
                    continue
                continue

        cleaned.append(result)

    return _drop_overlaps(cleaned)


def analyze_text(text: str, language: str = "en") -> list[RecognizerResult]:
    analyzer = build_analyzer()
    results = analyzer.analyze(text=text, language=language)
    return clean_results(results, text)


def _drop_overlaps(results: list[RecognizerResult]) -> list[RecognizerResult]:
    prioritized = sorted(
        results,
        key=lambda result: (-result.score, -(result.end - result.start), result.start),
    )
    accepted: list[RecognizerResult] = []

    for candidate in prioritized:
        overlaps_existing = any(_overlaps(candidate, existing) for existing in accepted)
        if not overlaps_existing:
            accepted.append(candidate)

    return sorted(accepted, key=lambda result: (result.start, result.end))


def _overlaps(left: RecognizerResult, right: RecognizerResult) -> bool:
    return left.start < right.end and left.end > right.start