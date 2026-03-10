from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class TokenRecord:
    request_id: str
    token: str
    entity_type: str
    ciphertext: str
    nonce: str
    key_version: str
    created_at: datetime
    expires_at: datetime
    score: float | None = None


class TokenStore(ABC):
    @abstractmethod
    def save_records(self, records: list[TokenRecord]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_records(self, request_id: str) -> list[TokenRecord]:
        raise NotImplementedError

    @abstractmethod
    def delete_records(self, request_id: str) -> None:
        raise NotImplementedError


class InMemoryTokenStore(TokenStore):
    def __init__(self):
        self._records: dict[str, dict[str, TokenRecord]] = {}

    def save_records(self, records: list[TokenRecord]) -> None:
        for record in records:
            request_records = self._records.setdefault(record.request_id, {})
            request_records[record.token] = record

    def get_records(self, request_id: str) -> list[TokenRecord]:
        self._purge_expired()
        request_records = self._records.get(request_id, {})
        return sorted(request_records.values(), key=lambda record: record.token)

    def delete_records(self, request_id: str) -> None:
        self._records.pop(request_id, None)

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired_request_ids = []

        for request_id, request_records in self._records.items():
            active_records = {
                token: record
                for token, record in request_records.items()
                if record.expires_at > now
            }
            if active_records:
                self._records[request_id] = active_records
            else:
                expired_request_ids.append(request_id)

        for request_id in expired_request_ids:
            self._records.pop(request_id, None)


class PostgresTokenStore(TokenStore):
    def __init__(self, conninfo: str, table_name: str = "pii_token_map"):
        self.conninfo = conninfo
        self.table_name = table_name

    def ensure_schema(self) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    request_id TEXT NOT NULL,
                    token TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    key_version TEXT NOT NULL,
                    score DOUBLE PRECISION NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (request_id, token)
                )
                """
            )
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS {self.table_name}_request_idx "
                f"ON {self.table_name} (request_id)"
            )
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS {self.table_name}_expires_idx "
                f"ON {self.table_name} (expires_at)"
            )
            conn.commit()

    def save_records(self, records: list[TokenRecord]) -> None:
        if not records:
            return

        query = (
            f"INSERT INTO {self.table_name} "
            "(request_id, token, entity_type, ciphertext, nonce, key_version, score, created_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (request_id, token) DO UPDATE SET "
            "entity_type = EXCLUDED.entity_type, "
            "ciphertext = EXCLUDED.ciphertext, "
            "nonce = EXCLUDED.nonce, "
            "key_version = EXCLUDED.key_version, "
            "score = EXCLUDED.score, "
            "created_at = EXCLUDED.created_at, "
            "expires_at = EXCLUDED.expires_at"
        )

        params = [
            (
                record.request_id,
                record.token,
                record.entity_type,
                record.ciphertext,
                record.nonce,
                record.key_version,
                record.score,
                record.created_at,
                record.expires_at,
            )
            for record in records
        ]

        with self._connect() as conn, conn.cursor() as cur:
            cur.executemany(query, params)
            conn.commit()

    def get_records(self, request_id: str) -> list[TokenRecord]:
        query = (
            f"SELECT request_id, token, entity_type, ciphertext, nonce, key_version, score, created_at, expires_at "
            f"FROM {self.table_name} WHERE request_id = %s AND expires_at > NOW() ORDER BY token"
        )

        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(query, (request_id,))
            rows = cur.fetchall()

        return [TokenRecord(*row) for row in rows]

    def delete_records(self, request_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"DELETE FROM {self.table_name} WHERE request_id = %s", (request_id,))
            conn.commit()

    def delete_expired(self) -> int:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"DELETE FROM {self.table_name} WHERE expires_at <= NOW()")
            deleted_rows = cur.rowcount
            conn.commit()
        return deleted_rows

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional dependency guard
            raise RuntimeError(
                "psycopg is required for PostgresTokenStore. Install requirements first."
            ) from exc

        return psycopg.connect(self.conninfo)