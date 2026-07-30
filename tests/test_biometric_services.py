from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from biometric_app.services.face_service import FaceRecognitionService
from biometric_app.services.fingerprint_service import FingerprintService


class FaceServiceTests(unittest.TestCase):
    def test_official_models_load(self) -> None:
        service = FaceRecognitionService()
        self.assertEqual(service.ALGORITHM_NAME, "OpenCV SFace")
        if not hasattr(service, "detector"):
            self.skipTest("OpenCV face runtime is not available in this test interpreter.")
        self.assertIsNotNone(service.detector)
        self.assertIsNotNone(service.recognizer)


class FingerprintServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = FingerprintService()
        self.template_payload = {
            "success": True,
            "version": 4,
            "algorithm": "Futronic FTRAPI minutiae",
            "sdk_version": "4.2.2029.176",
            "sample_count": 3,
            "quality_score": 8,
            "template_base64": base64.b64encode(bytes(range(150)) * 2).decode("ascii"),
        }

    def test_enrollment_stores_only_official_template_metadata(self) -> None:
        with patch.object(
            self.service,
            "_run_helper",
            return_value={
                "success": True,
                "stdout": json.dumps(self.template_payload),
                "message": "",
            },
        ):
            stored = self.service.enroll_template()

        payload = json.loads(stored)
        self.assertEqual(payload["version"], 4)
        self.assertEqual(payload["algorithm"], "Futronic FTRAPI minutiae")
        self.assertEqual(payload["sample_count"], 3)
        self.assertNotIn("ImageHex", payload)

    def test_legacy_template_is_rejected_without_capture(self) -> None:
        with patch.object(self.service, "_run_helper") as helper:
            result = self.service.verify_against_database(
                [
                    {
                        "id": 1,
                        "full_name": "Legacy User",
                        "fingerprint_template": json.dumps(
                            {"version": 3, "samples": ["old"]}
                        ).encode("utf-8"),
                    }
                ]
            )

        self.assertFalse(result.success)
        self.assertIn("Re-enroll", result.message)
        helper.assert_not_called()

    def test_official_identification_returns_database_identity(self) -> None:
        stored = json.dumps(self.template_payload).encode("utf-8")
        with patch.object(
            self.service,
            "_run_helper",
            return_value={
                "success": True,
                "stdout": json.dumps(
                    {"success": True, "quality_score": 7, "matches": [{"id": 8, "far": 120}]}
                ),
                "message": "",
            },
        ) as helper:
            result = self.service.verify_against_database(
                [{"id": 8, "full_name": "Test User", "fingerprint_template": stored}]
            )

        self.assertTrue(result.success, result.message)
        self.assertEqual(result.matched_user_id, 8)
        request = json.loads(helper.call_args.kwargs["input_text"])
        self.assertEqual(request["candidates"][0]["id"], 8)

    def test_no_sdk_match_denies_access(self) -> None:
        stored = json.dumps(self.template_payload).encode("utf-8")
        with patch.object(
            self.service,
            "_run_helper",
            return_value={
                "success": True,
                "stdout": json.dumps(
                    {"success": True, "quality_score": 6, "matches": []}
                ),
                "message": "",
            },
        ):
            result = self.service.verify_against_database(
                [{"id": 4, "full_name": "No Match", "fingerprint_template": stored}]
            )

        self.assertFalse(result.success)
        self.assertIn("not recognized", result.message)


if __name__ == "__main__":
    unittest.main()
