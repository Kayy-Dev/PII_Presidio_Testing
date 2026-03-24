import unittest

from analyzer_factory import analyze_text
from crypto import AesGcmCipher, LocalKeyProvider
from pii_service import ReversiblePIIService
from token_store import InMemoryTokenStore


MIXED_TEXT = (
    "My name is Kayy Kayy，我叫王小明。\n"
    "I live in 北京市朝阳区。Email me at kayy.kayy@company.com 或者拨打 13800138000。"
)

CHINESE_TEXT = (
    "你好，我叫王小明，住在北京市朝阳区，邮编100000。\n"
    "你可以通过13800138000或者xiaoming.wang@example.com联系我。"
)

UNIT_TEXT = (
    "Please send the package to Room 502, Building 3, Beijing Chaoyang District, "
    "and contact me at foo@example.com.\n"
    "请把包裹寄到北京市朝阳区502室，bar@example.com 联系我。"
)


class AutoModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = ReversiblePIIService(
            token_store=InMemoryTokenStore(),
            cipher=AesGcmCipher(LocalKeyProvider()),
        )

    def test_auto_mode_detects_mixed_language_entities(self) -> None:
        results = analyze_text(MIXED_TEXT, language="auto")

        persons = [
            MIXED_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "PERSON"
        ]
        emails = [
            MIXED_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "EMAIL_ADDRESS"
        ]
        phone_numbers = [
            MIXED_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "PHONE_NUMBER"
        ]

        self.assertIn("Kayy Kayy", persons)
        self.assertIn("王小明", persons)
        self.assertIn("kayy.kayy@company.com", emails)
        self.assertIn("13800138000", phone_numbers)

        locations = [
            MIXED_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "LOCATION"
        ]
        self.assertIn("北京市朝阳区", locations)

    def test_auto_mode_avoids_name_false_positive_location(self) -> None:
        results = analyze_text(MIXED_TEXT, language="auto")

        locations = [
            MIXED_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "LOCATION"
        ]

        self.assertNotIn("name", locations)

    def test_auto_mode_round_trip_restores_original_text(self) -> None:
        tokenization = self.service.tokenize(MIXED_TEXT, language="auto")
        restored_text = self.service.detokenize(
            tokenization.tokenized_text,
            tokenization.request_id,
        )

        self.assertEqual(restored_text, MIXED_TEXT)

    def test_chinese_mode_detects_admin_location(self) -> None:
        results = analyze_text(CHINESE_TEXT, language="zh")

        locations = [
            CHINESE_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "LOCATION"
        ]

        self.assertIn("北京市朝阳区", locations)
        self.assertIn("100000", locations)

    def test_auto_mode_detects_room_and_building_units(self) -> None:
        results = analyze_text(UNIT_TEXT, language="auto")

        locations = [
            UNIT_TEXT[result.start:result.end]
            for result in results
            if result.entity_type == "LOCATION"
        ]

        self.assertIn("Room 502", locations)
        self.assertIn("Building 3", locations)
        self.assertIn("北京市朝阳区", locations)
        self.assertIn("502室", locations)


if __name__ == "__main__":
    unittest.main()