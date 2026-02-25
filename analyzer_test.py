from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

# Initialize engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Sample text with PII
text = """
Hi, my name is Sarah Johnson. I live at 456 Oak Avenue, Chicago, IL 60601.
You can reach me at sarah.johnson@gmail.com or call me at (312) 555-9876.
My Social Security Number is 456-78-9012.
"""

# Step 1: Analyze - detect PII entities
results = analyzer.analyze(text=text, language="en")

print("=== Detected PII Entities ===")
for result in results:
    print(f"Type: {result.entity_type} | Text: '{text[result.start:result.end]}' | Score: {result.score:.2f}")

# Step 2: Anonymize - replace PII with placeholders
anonymized = anonymizer.anonymize(text=text, analyzer_results=results)

print("\n=== Anonymized Text ===")
print(anonymized.text)
