LANGUAGE_OPTIONS = {
    "Auto": "auto",
    "English": "en",
    "Chinese": "zh",
}


def resolve_language(text: str, selected_language: str) -> tuple[str, str]:
    if selected_language != "auto":
        return selected_language, "manual"

    return "auto", "auto"