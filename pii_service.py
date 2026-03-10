from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from analyzer_factory import analyze_text
from crypto import AesGcmCipher
from token_store import TokenRecord, TokenStore


@dataclass(frozen=True)
class DetectedEntity:
    entity_type: str
    start: int
    end: int
    score: float
    text: str


@dataclass(frozen=True)
class TokenizationResult:
    request_id: str
    tokenized_text: str
    detected_entities: list[DetectedEntity]
    tokens: dict[str, str]
    expires_at: datetime


@dataclass(frozen=True)
class RoundTripResult:
    request_id: str
    tokenized_prompt: str
    model_response: str
    restored_response: str
    detected_entities: list[DetectedEntity]


class ReversiblePIIService:
    def __init__(self, token_store: TokenStore, cipher: AesGcmCipher):
        self.token_store = token_store
        self.cipher = cipher

    def detect(self, text: str, language: str = "en") -> list[DetectedEntity]:
        results = analyze_text(text=text, language=language)
        return [
            DetectedEntity(
                entity_type=result.entity_type,
                start=result.start,
                end=result.end,
                score=result.score,
                text=text[result.start:result.end],
            )
            for result in results
        ]

    def tokenize(
        self,
        text: str,
        language: str = "en",
        request_id: str | None = None,
        ttl_seconds: int = 1800,
    ) -> TokenizationResult:
        request_id = request_id or str(uuid4())
        detected_entities = self.detect(text=text, language=language)
        counters: dict[str, int] = defaultdict(int)
        tokenized_text = text
        token_map: dict[str, str] = {}
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(seconds=ttl_seconds)
        records: list[TokenRecord] = []
        planned_tokens: list[tuple[DetectedEntity, str]] = []

        for entity in detected_entities:
            counters[entity.entity_type] += 1
            token = f"{{{{{entity.entity_type}_{counters[entity.entity_type]}}}}}"
            encrypted_value = self.cipher.encrypt(entity.text)
            planned_tokens.append((entity, token))
            token_map[token] = entity.text
            records.append(
                TokenRecord(
                    request_id=request_id,
                    token=token,
                    entity_type=entity.entity_type,
                    ciphertext=encrypted_value.ciphertext,
                    nonce=encrypted_value.nonce,
                    key_version=encrypted_value.key_version,
                    created_at=created_at,
                    expires_at=expires_at,
                    score=entity.score,
                )
            )

        for entity, token in sorted(
            planned_tokens,
            key=lambda item: (item[0].start, item[0].end),
            reverse=True,
        ):
            tokenized_text = (
                tokenized_text[:entity.start]
                + token
                + tokenized_text[entity.end:]
            )

        self.token_store.save_records(records)

        return TokenizationResult(
            request_id=request_id,
            tokenized_text=tokenized_text,
            detected_entities=detected_entities,
            tokens=dict(sorted(token_map.items())),
            expires_at=expires_at,
        )

    def detokenize(self, text: str, request_id: str, delete_after: bool = False) -> str:
        records = self.token_store.get_records(request_id)
        if not records:
            raise ValueError(f"No token mappings found for request_id={request_id}")

        restored_text = text
        for record in sorted(records, key=lambda item: len(item.token), reverse=True):
            original_value = self.cipher.decrypt(
                ciphertext=record.ciphertext,
                nonce=record.nonce,
                key_version=record.key_version,
            )
            restored_text = restored_text.replace(record.token, original_value)

        if delete_after:
            self.token_store.delete_records(request_id)

        return restored_text

    def round_trip(
        self,
        text: str,
        model_callable,
        language: str = "en",
        ttl_seconds: int = 1800,
        delete_after: bool = False,
    ) -> RoundTripResult:
        tokenization = self.tokenize(
            text=text,
            language=language,
            ttl_seconds=ttl_seconds,
        )
        model_response = model_callable(tokenization.tokenized_text)
        restored_response = self.detokenize(
            text=model_response,
            request_id=tokenization.request_id,
            delete_after=delete_after,
        )

        return RoundTripResult(
            request_id=tokenization.request_id,
            tokenized_prompt=tokenization.tokenized_text,
            model_response=model_response,
            restored_response=restored_response,
            detected_entities=tokenization.detected_entities,
        )