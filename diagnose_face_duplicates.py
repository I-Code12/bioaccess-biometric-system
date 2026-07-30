from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
VENDORLIBS = ROOT / "vendorlibs"
if VENDORLIBS.exists():
    sys.path.insert(0, str(VENDORLIBS))

from biometric_app.env_loader import load_env_file

load_env_file(ROOT)

import numpy as np

from biometric_app.services.db_service import DatabaseService
from biometric_app.services.encryption_service import EncryptionService
from biometric_app.services.face_service import FaceRecognitionService


def main() -> int:
    db = DatabaseService(encryption_service=EncryptionService())
    db.initialize()
    users = db.get_user_biometrics(require_face=True, require_fingerprint=False)
    face_service = FaceRecognitionService()

    print(f"Loaded {len(users)} usable face record(s).")
    if len(users) < 2:
        return 0

    pairs = []
    for left_index, left_user in enumerate(users):
        for right_user in users[left_index + 1:]:
            distance = face_service._cosine_distance(
                np.asarray(left_user["face_embedding"], dtype=np.float32),
                np.asarray(right_user["face_embedding"], dtype=np.float32),
            )
            pairs.append((distance, left_user, right_user))

    print("Closest stored face-template pairs:")
    for distance, left_user, right_user in sorted(pairs, key=lambda item: item[0])[:10]:
        if distance < 0.01:
            status = "POSSIBLE DUPLICATE"
        elif distance < FaceRecognitionService.EXIT_FACE_DISTANCE_THRESHOLD:
            status = "TOO CLOSE FOR FACE-ONLY EXIT"
        else:
            status = "OK"
        print(
            f"{distance:.4f} | "
            f"{status} | "
            f"{left_user['full_name']} ({left_user['student_id']}) <-> "
            f"{right_user['full_name']} ({right_user['student_id']})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
