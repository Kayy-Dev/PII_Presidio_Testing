import re
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider


SUPPORTED_LANGUAGES = ("en", "zh")
AUTO_LANGUAGE = "auto"


# Words/phrases that spaCy commonly mis-tags as PERSON
FALSE_POSITIVE_PERSONS = {
    "en": {
        "email", "my email", "my email is",
        "phone", "my phone", "my phone is",
        "my name", "name", "address", "my address",
        "the", "is", "at", "number", "my number",
    },
    "zh": {
        "邮箱", "我的邮箱", "邮箱是",
        "电话", "我的电话", "手机号", "我的手机号",
        "名字", "我的名字", "地址", "我的地址",
        "号码", "我的号码",
    },
}

# Phrases that spaCy commonly mis-tags as ORGANIZATION
FALSE_POSITIVE_ORGS = {
    "en": {
        "social security number", "my social security number",
        "ssn", "my ssn", "employee id", "my employee id",
        "security number", "my security number",
    },
    "zh": {
        "身份证号", "我的身份证号", "社保号", "我的社保号",
        "员工号", "我的员工号", "工号", "我的工号",
    },
}

# Real organizations always contain one of these indicator words
ORG_INDICATORS = {
    "en": {
        "inc", "ltd", "llc", "corp", "corporation", "company", "co",
        "association", "foundation", "institute", "university", "college",
        "bank", "group", "department", "agency", "bureau", "ministry",
        "hospital", "clinic", "school", "church", "club",
    },
    "zh": {
        "有限公司", "公司", "集团", "银行", "医院", "学校", "大学",
        "学院", "研究所", "中心", "协会", "基金会", "部", "局",
        "厅", "署", "委员会",
    },
}

PERSON_CONTEXT_PHRASES = {
    "en": ["i am ", "i'm ", "my name is ", "name is ", "call me "],
    "zh": ["我是", "我叫", "我的名字是", "名字是", "叫我"],
}

ZH_LOCATION_PREFIXES = (
    "请把包裹寄到",
    "把包裹寄到",
    "请寄到",
    "邮寄到",
    "寄到",
    "寄往",
    "送到",
    "送至",
    "发到",
    "地址是",
    "住在",
    "位于",
    "来自",
    "在",
)
ZH_ADMIN_LOCATION_RE = re.compile(
    r"(?:[\u4e00-\u9fff]{2,12}(?:省|自治区|特别行政区))?"
    r"(?:[\u4e00-\u9fff]{2,12}市)?"
    r"(?:[\u4e00-\u9fff]{2,12}(?:区|县|旗))"
)
ZH_ADMIN_LOCATION_FULL_RE = re.compile(rf"^{ZH_ADMIN_LOCATION_RE.pattern}$")

AUTO_SCRIPT_SENSITIVE_ENTITIES = {"PERSON", "ORGANIZATION", "LOCATION"}
WESTERN_NAME_CONTINUATION_RE = re.compile(
    r"(?:\s+[A-Z][A-Za-z'\-]*)+"
)


@lru_cache(maxsize=1)
def build_analyzer() -> AnalyzerEngine:
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": "en", "model_name": "en_core_web_lg"},
            {"lang_code": "zh", "model_name": "zh_core_web_sm"},
        ],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        default_score_threshold=0.35,
        supported_languages=list(SUPPORTED_LANGUAGES),
    )

    email_pattern = Pattern(
        name="email_pattern",
        regex=(
            r"(?<![A-Za-z0-9._%+\-])"
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
            r"(?![A-Za-z0-9._%+\-])"
        ),
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
    en_unit_pattern = Pattern(
        name="en_unit_pattern",
        regex=(
            r"\b(?:Room|Rm|Suite|Ste|Unit|Apartment|Apt|Building|Bldg|Floor|Fl)"
            r"\s+[A-Z0-9][A-Za-z0-9\-]*\b"
        ),
        score=0.82,
    )
    zip_pattern = Pattern(
        name="us_zip_pattern",
        regex=r"\b(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b",
        score=0.6,
    )
    cn_postal_code_pattern = Pattern(
        name="cn_postal_code_pattern",
        regex=r"(?<!\d)\d{6}(?!\d)",
        score=0.6,
    )
    cn_admin_location_pattern = Pattern(
        name="cn_admin_location_pattern",
        regex=ZH_ADMIN_LOCATION_RE.pattern,
        score=0.9,
    )
    cn_unit_pattern = Pattern(
        name="cn_unit_pattern",
        regex=r"(?<!\d)\d{1,4}(?:室|楼|栋|号楼|单元)(?!\d)",
        score=0.82,
    )
    employee_id_pattern = Pattern(
        name="employee_id_pattern",
        regex=r"\bEMP-\d{5}\b",
        score=0.85,
    )
    cn_phone_pattern = Pattern(
        name="cn_phone_pattern",
        regex=r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)",
        score=0.85,
    )

    for language in SUPPORTED_LANGUAGES:
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="EMAIL_ADDRESS",
                supported_language=language,
                patterns=[email_pattern],
            )
        )
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="EMPLOYEE_ID",
                supported_language=language,
                patterns=[employee_id_pattern],
            )
        )

    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="en",
            patterns=[street_pattern],
        )
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="en",
            patterns=[en_unit_pattern],
        )
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="en",
            patterns=[zip_pattern],
        )
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="zh",
            patterns=[cn_postal_code_pattern],
        )
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="zh",
            patterns=[cn_admin_location_pattern],
        )
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="LOCATION",
            supported_language="zh",
            patterns=[cn_unit_pattern],
        )
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            supported_language="zh",
            patterns=[cn_phone_pattern],
        )
    )

    return analyzer


def clean_results(
    results: list[RecognizerResult],
    text: str,
    language: str = "en",
) -> list[RecognizerResult]:
    """Remove common false positives caused by spaCy NER models."""
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
    false_positive_persons = FALSE_POSITIVE_PERSONS.get(language, FALSE_POSITIVE_PERSONS["en"])
    false_positive_orgs = FALSE_POSITIVE_ORGS.get(language, FALSE_POSITIVE_ORGS["en"])

    cleaned: list[RecognizerResult] = []
    for result in results:
        if result.entity_type == "LOCATION" and language == "zh":
            result = _trim_zh_location_prefix(result, text)

        matched_text = text[result.start:result.end].lower().strip()

        if result.entity_type == "PERSON":
            overlaps_email = any(
                result.start < email_end and result.end > email_start
                for email_start, email_end in email_spans
            )
            if overlaps_email or matched_text in false_positive_persons or "@" in matched_text:
                continue

        elif result.entity_type == "ORGANIZATION":
            overlaps_ssn = any(
                result.start < ssn_end and result.end > ssn_start
                for ssn_start, ssn_end in ssn_spans
            )
            if overlaps_ssn or matched_text in false_positive_orgs:
                continue

            has_org_indicator = _has_org_indicator(matched_text, language)
            if not has_org_indicator:
                context_window = 25 if language == "en" else 15
                context_before = text[max(0, result.start - context_window):result.start].lower()
                is_personal_context = any(
                    phrase in context_before
                    for phrase in PERSON_CONTEXT_PHRASES.get(language, PERSON_CONTEXT_PHRASES["en"])
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

    if language == AUTO_LANGUAGE:
        merged_results: list[RecognizerResult] = []
        for supported_language in SUPPORTED_LANGUAGES:
            language_results = analyzer.analyze(text=text, language=supported_language)
            cleaned_results = clean_results(
                language_results,
                text,
                language=supported_language,
            )
            merged_results.extend(
                _filter_auto_language_results(
                    cleaned_results,
                    text,
                    language=supported_language,
                )
            )
        merged_results = _drop_overlaps(merged_results)
        merged_results = _expand_auto_western_person_names(merged_results, text)
        return _drop_overlaps(merged_results)

    results = analyzer.analyze(text=text, language=language)
    return clean_results(results, text, language=language)


def _has_org_indicator(matched_text: str, language: str) -> bool:
    indicators = ORG_INDICATORS.get(language, ORG_INDICATORS["en"])
    if language == "zh":
        return any(indicator in matched_text for indicator in indicators)

    words = set(matched_text.split())
    return bool(words & indicators)


def _filter_auto_language_results(
    results: list[RecognizerResult],
    text: str,
    language: str,
) -> list[RecognizerResult]:
    filtered: list[RecognizerResult] = []

    for result in results:
        matched_text = text[result.start:result.end]

        if result.entity_type not in AUTO_SCRIPT_SENSITIVE_ENTITIES:
            filtered.append(result)
            continue

        if language == "zh":
            if _contains_cjk(matched_text) or _contains_digit(matched_text):
                filtered.append(result)
            continue

        filtered.append(result)

    return filtered


def _expand_auto_western_person_names(
    results: list[RecognizerResult],
    text: str,
) -> list[RecognizerResult]:
    expanded_results: list[RecognizerResult] = []

    for result in results:
        if result.entity_type != "PERSON":
            expanded_results.append(result)
            continue

        matched_text = text[result.start:result.end]
        if not _is_western_name_token(matched_text):
            expanded_results.append(result)
            continue

        context_before = text[max(0, result.start - 25):result.start].lower()
        has_person_context = any(
            phrase in context_before
            for phrase in PERSON_CONTEXT_PHRASES["en"]
        )
        if not has_person_context:
            expanded_results.append(result)
            continue

        suffix_match = WESTERN_NAME_CONTINUATION_RE.match(text[result.end:])
        if not suffix_match:
            expanded_results.append(result)
            continue

        expanded_results.append(
            RecognizerResult(
                entity_type=result.entity_type,
                start=result.start,
                end=result.end + suffix_match.end(),
                score=result.score,
            )
        )

    return expanded_results


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


def _contains_cjk(text: str) -> bool:
    return any("\u4e00" <= character <= "\u9fff" for character in text)


def _contains_digit(text: str) -> bool:
    return any(character.isdigit() for character in text)


def _is_western_name_token(text: str) -> bool:
    cleaned_text = text.strip()
    if not cleaned_text:
        return False

    return all(
        character.isalpha() or character in {"'", "-", " ", "."}
        for character in cleaned_text
    ) and any("A" <= character.upper() <= "Z" for character in cleaned_text if character.isalpha())


def _trim_zh_location_prefix(result: RecognizerResult, text: str) -> RecognizerResult:
    matched_text = text[result.start:result.end]

    for prefix in ZH_LOCATION_PREFIXES:
        if matched_text.startswith(prefix) and len(matched_text) > len(prefix):
            result = RecognizerResult(
                entity_type=result.entity_type,
                start=result.start + len(prefix),
                end=result.end,
                score=result.score,
            )
            matched_text = text[result.start:result.end]
            break

    if ZH_ADMIN_LOCATION_FULL_RE.fullmatch(matched_text):
        return result

    trimmed_admin_location = _extract_zh_admin_location_suffix(matched_text)
    if trimmed_admin_location and trimmed_admin_location != matched_text:
        start_offset = matched_text.rfind(trimmed_admin_location)
        return RecognizerResult(
            entity_type=result.entity_type,
            start=result.start + start_offset,
            end=result.start + start_offset + len(trimmed_admin_location),
            score=result.score,
        )

    admin_location_match = ZH_ADMIN_LOCATION_RE.search(matched_text)
    if admin_location_match and admin_location_match.group(0) != matched_text:
        return RecognizerResult(
            entity_type=result.entity_type,
            start=result.start + admin_location_match.start(),
            end=result.start + admin_location_match.end(),
            score=result.score,
        )

    return result


def _extract_zh_admin_location_suffix(text: str) -> str | None:
    candidates: list[str] = []

    for start_index in range(len(text)):
        candidate = text[start_index:]
        if not ZH_ADMIN_LOCATION_FULL_RE.fullmatch(candidate):
            continue

        if candidate.startswith(("市", "省", "区", "县", "旗")):
            continue

        if "市" in candidate or "省" in candidate or "自治区" in candidate or "特别行政区" in candidate:
            candidates.append(candidate)

    if candidates:
        return min(candidates, key=len)

    return None