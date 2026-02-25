from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

# Define a custom regex pattern
employee_id_pattern = Pattern(
    name="employee_id_pattern",
    regex=r"\bEMP-\d{5}\b",
    score=0.85
)

employee_recognizer = PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[employee_id_pattern]
)

# Add it to the engine
analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(employee_recognizer)

text = "Employee EMP-00123 submitted a request from john.doe@company.com"

results = analyzer.analyze(text=text, language="en")

print("=== Detected Entities (with custom recognizer) ===")
for result in results:
    print(f"Type: {result.entity_type} | Text: '{text[result.start:result.end]}'")
