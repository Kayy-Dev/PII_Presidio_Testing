from langdetect import LangDetectException, detect


LANGUAGE_OPTIONS = {
    "Auto": "auto",
    "English": "en",
    "Chinese": "zh",
}


def resolve_language(text: str, selected_language: str) -> tuple[str, str]:
    if selected_language != "auto":
        return selected_language, "manual"

    try:
        detected_language = detect(text).lower()
    except LangDetectException:
        return "en", "fallback"

    if detected_language.startswith("zh"):
        return "zh", "auto"
    if detected_language.startswith("en"):
        return "en", "auto"
    return "en", "fallback"