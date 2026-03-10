from crypto import AesGcmCipher, LocalKeyProvider
from pii_service import ReversiblePIIService
from token_store import InMemoryTokenStore


def simulated_llm(tokenized_prompt: str) -> str:
    return f"Draft response for the protected prompt: {tokenized_prompt}"


service = ReversiblePIIService(
    token_store=InMemoryTokenStore(),
    cipher=AesGcmCipher(LocalKeyProvider()),
)

text = """
Hi, my name is Kayy Kayy. I live at 456 Oak Avenue, Chicago, IL 60601.
You can reach me at kayy.kayy@company.com and my employee id is EMP-00123.
"""

tokenization = service.tokenize(text)

print("=== Detected PII Entities ===")
for entity in tokenization.detected_entities:
    print(
        f"Type: {entity.entity_type} | Text: '{entity.text}' | Score: {entity.score:.2f}"
    )

print("\n=== Tokenized Prompt ===")
print(tokenization.tokenized_text)

print("\n=== Stored Token Map ===")
for token, original_value in tokenization.tokens.items():
    print(f"{token} -> {original_value}")

model_response = simulated_llm(tokenization.tokenized_text)
restored_response = service.detokenize(model_response, tokenization.request_id)

print("\n=== AI Response With Tokens ===")
print(model_response)

print("\n=== Restored Final Response ===")
print(restored_response)
