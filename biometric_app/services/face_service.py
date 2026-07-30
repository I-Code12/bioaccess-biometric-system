from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None

from biometric_app.config import FACE_EMBEDDING_SIZE
from biometric_app.models import VerificationResult


@dataclass(slots=True)
class DetectedFace:
    image: np.ndarray
    bounds: tuple[int, int, int, int]


class FaceRecognitionService:
    TEMPLATE_VERSION = 2
    ALGORITHM_NAME = "OpenCV SFace"
    ENROLLMENT_SAMPLE_COUNT = 3
    FACE_DISTANCE_THRESHOLD = 0.55
    EXIT_FACE_DISTANCE_THRESHOLD = 0.50
    FACE_AMBIGUITY_MARGIN = 0.08
    ENROLLMENT_CONSISTENCY_THRESHOLD = 0.45

    def __init__(self) -> None:
        if cv2 is None or np is None or not hasattr(cv2, "CascadeClassifier"):
            self.face_cascade = None
            self.profile_cascade = None
            self.hog = None
            return

        model_dir = Path(__file__).resolve().parents[1] / "models"
        detector_path = model_dir / "face_detection_yunet_2023mar.onnx"
        recognizer_path = model_dir / "face_recognition_sface_2021dec.onnx"
        if not detector_path.exists() or not recognizer_path.exists():
            raise RuntimeError(
                "OpenCV face models are missing. Restore the YuNet and SFace model files."
            )
        if not hasattr(cv2, "FaceDetectorYN_create") or not hasattr(cv2, "FaceRecognizerSF_create"):
            raise RuntimeError("This OpenCV installation does not support YuNet/SFace.")
        self.detector = cv2.FaceDetectorYN_create(
            str(detector_path), "", (320, 320), 0.85, 0.3, 5000
        )
        self.recognizer = cv2.FaceRecognizerSF_create(str(recognizer_path), "")
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        self.face_cascade = cv2.CascadeClassifier(cascade_path)
        self.profile_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_profileface.xml"
        )
        self.hog = cv2.HOGDescriptor(
            _winSize=(64, 64),
            _blockSize=(16, 16),
            _blockStride=(8, 8),
            _cellSize=(8, 8),
            _nbins=9,
        )

    def capture_face_frame(self) -> bytes:
        self._require_dependencies()
        last_frame: np.ndarray | None = None
        attempted_cameras: list[str] = []
        opened_cameras: list[str] = []
        failed_reads: list[str] = []

        for camera_index, backend_name, backend in self._camera_candidates():
            camera_label = f"camera {camera_index} ({backend_name})"
            attempted_cameras.append(camera_label)
            camera = cv2.VideoCapture(camera_index, backend)
            if not camera.isOpened():
                camera.release()
                continue

            try:
                opened_cameras.append(camera_label)
                self._prepare_camera(camera)
                read_successes = 0

                for _ in range(75):
                    success, frame = camera.read()
                    if not success or frame is None or frame.size == 0:
                        time.sleep(0.03)
                        continue

                    if self._is_blank_frame(frame):
                        time.sleep(0.03)
                        continue

                    read_successes += 1
                    last_frame = frame
                    success, encoded = cv2.imencode(".jpg", frame)
                    if not success:
                        raise RuntimeError("Unable to encode captured face image.")
                    return encoded.tobytes()

                if read_successes == 0:
                    failed_reads.append(camera_label)
            finally:
                camera.release()

        if last_frame is not None:
            success, encoded = cv2.imencode(".jpg", last_frame)
            if success:
                return encoded.tobytes()

        if opened_cameras:
            detail = ", ".join(opened_cameras)
            if failed_reads:
                detail = f"{detail}. No readable frames from: {', '.join(failed_reads)}"
            raise RuntimeError(
                "The webcam opened, but BioAccess could not read a clear frame. "
                "Close other camera apps, allow camera access in Windows Privacy settings, "
                "and try again with good lighting. "
                f"Checked: {detail}."
            )

        raise RuntimeError(
            "BioAccess could not open a webcam. Confirm the camera works in the Windows Camera app, "
            "close Teams/Zoom/browser camera tabs, then try again. "
            f"Checked: {', '.join(attempted_cameras)}."
        )

    def create_embedding(self, image_bytes: bytes) -> dict:
        self._require_dependencies()
        frame = self._decode_image(image_bytes)
        face_rows = self._detect_sface_rows(frame)
        if not face_rows:
            raise RuntimeError(
                "No face detected. Face the camera directly, improve lighting, and keep the face close to the center of the frame."
            )
        if len(face_rows) != 1:
            raise RuntimeError("Exactly one face must be visible during enrollment or verification.")
        face_row = face_rows[0]
        x, y, width, height = (int(value) for value in face_row[:4])
        if width < 90 or height < 90:
            raise RuntimeError("Move closer to the camera; the detected face is too small.")
        crop = frame[max(y, 0):max(y, 0) + height, max(x, 0):max(x, 0) + width]
        if crop.size == 0 or float(cv2.Laplacian(crop, cv2.CV_64F).var()) < 45.0:
            raise RuntimeError("The face image is too blurry. Hold still and capture again.")
        gray_mean = float(cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY).mean())
        if gray_mean < 45.0 or gray_mean > 220.0:
            raise RuntimeError("Face lighting is unsuitable. Avoid very dark or overexposed lighting.")
        aligned = self.recognizer.alignCrop(frame, face_row)
        feature = self.recognizer.feature(aligned).flatten().astype(np.float32)
        feature = self._normalize_vector(feature)
        return {
            "version": self.TEMPLATE_VERSION,
            "algorithm": self.ALGORITHM_NAME,
            "sample_count": 1,
            "template": feature.tolist(),
        }

    def combine_enrollment_embeddings(self, samples: list[dict]) -> dict:
        if len(samples) < self.ENROLLMENT_SAMPLE_COUNT:
            raise ValueError(f"Face enrollment requires {self.ENROLLMENT_SAMPLE_COUNT} samples.")
        vectors = [self._template_vector(sample) for sample in samples]
        similarities = [
            float(np.dot(vectors[left], vectors[right]))
            for left in range(len(vectors))
            for right in range(left + 1, len(vectors))
        ]
        minimum_similarity = min(similarities)
        if minimum_similarity < self.ENROLLMENT_CONSISTENCY_THRESHOLD:
            raise RuntimeError(
                "Face samples are inconsistent. Ensure the same person is visible and capture again."
            )
        combined = self._normalize_vector(np.mean(np.stack(vectors), axis=0))
        return {
            "version": self.TEMPLATE_VERSION,
            "algorithm": self.ALGORITHM_NAME,
            "sample_count": len(samples),
            "minimum_sample_similarity": minimum_similarity,
            "template": combined.tolist(),
        }

    def verify_against_database(
        self,
        image_bytes: bytes,
        enrolled_users: list[dict],
        threshold: float | None = None,
        allow_fingerprint_disambiguation: bool = True,
    ) -> VerificationResult:
        self._require_dependencies()
        threshold = self.FACE_DISTANCE_THRESHOLD if threshold is None else threshold
        candidate_embedding = self._template_vector(self.create_embedding(image_bytes))
        best_user = None
        best_score = None
        second_best_score = None
        scored_users: list[tuple[float, dict]] = []
        skipped_legacy_templates = 0

        for user in enrolled_users:
            stored_embedding = user.get("face_embedding")
            if not stored_embedding:
                continue
            if not isinstance(stored_embedding, dict) or int(stored_embedding.get("version", 1)) < self.TEMPLATE_VERSION:
                skipped_legacy_templates += 1
                continue
            stored_vector = self._template_vector(stored_embedding)
            score = self._cosine_distance(candidate_embedding, stored_vector)
            scored_users.append((score, user))
            if best_score is None or score < best_score:
                second_best_score = best_score
                best_score = score
                best_user = user
            elif second_best_score is None or score < second_best_score:
                second_best_score = score

        if best_score is None or best_user is None:
            if skipped_legacy_templates:
                return VerificationResult(
                    False,
                    "Only legacy face templates were found. Re-enroll the user's face with SFace before verification.",
                )
            return VerificationResult(False, "No registered face embeddings found.")

        if second_best_score is not None and (second_best_score - best_score) < self.FACE_AMBIGUITY_MARGIN:
            close_candidate_ids = tuple(
                int(user["id"])
                for score, user in sorted(scored_users, key=lambda item: item[0])
                if score <= threshold
            )
            if not close_candidate_ids:
                return VerificationResult(
                    False,
                    (
                        "Face not recognized. "
                        f"Best distance: {best_score:.3f}; second-best distance: {second_best_score:.3f}. "
                        f"Required distance: {threshold:.3f} or lower."
                    ),
                )
            if not allow_fingerprint_disambiguation:
                return VerificationResult(
                    False,
                    (
                        "Face verification is ambiguous. "
                        f"Best distance: {best_score:.3f}; second-best distance: {second_best_score:.3f}. "
                        "Exit verification is face-only, so access is denied because the face matched multiple close candidates. "
                        "Re-enroll the student's face or remove duplicate/old test records."
                    ),
                    matched_user_id=best_user["id"],
                    candidate_user_ids=close_candidate_ids,
                )
            return VerificationResult(
                False,
                (
                    "Face verification is ambiguous. "
                    f"Best distance: {best_score:.3f}; second-best distance: {second_best_score:.3f}. "
                    "Fingerprint verification will be used to disambiguate the close face candidates."
                ),
                matched_user_id=best_user["id"],
                candidate_user_ids=close_candidate_ids,
            )

        if best_score <= threshold:
            return VerificationResult(
                True,
                f"Face matched for {best_user['full_name']} with score {best_score:.3f}.",
                matched_user_id=best_user["id"],
                candidate_user_ids=(best_user["id"],),
            )

        return VerificationResult(
            False,
            (
                "Face not recognized. "
                f"Best similarity distance: {best_score:.3f}. "
                f"Required distance: {threshold:.3f} or lower."
            ),
        )

    def _decode_image(self, image_bytes: bytes) -> np.ndarray:
        self._require_dependencies()
        image_array = np.frombuffer(image_bytes, dtype=np.uint8)
        frame = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        if frame is None:
            raise RuntimeError("Unable to decode captured face image.")
        return frame

    def _detect_sface_rows(self, frame: np.ndarray) -> list[np.ndarray]:
        height, width = frame.shape[:2]
        self.detector.setInputSize((width, height))
        _, faces = self.detector.detect(frame)
        if faces is None:
            return []
        return [row for row in faces if float(row[-1]) >= 0.85]

    def _template_vector(self, payload: dict) -> np.ndarray:
        if payload.get("algorithm") != self.ALGORITHM_NAME:
            raise RuntimeError("Stored face template uses an incompatible algorithm.")
        vector = np.asarray(payload.get("template", []), dtype=np.float32)
        if vector.ndim != 1 or vector.size == 0:
            raise RuntimeError("Stored face template is invalid.")
        return self._normalize_vector(vector)

    def _detect_largest_face(self, frame: np.ndarray) -> DetectedFace | None:
        self._require_dependencies()
        grayscale = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        equalized = cv2.equalizeHist(grayscale)

        detection_sets = [
            self.face_cascade.detectMultiScale(
                grayscale,
                scaleFactor=1.1,
                minNeighbors=4,
                minSize=(60, 60),
            ),
            self.face_cascade.detectMultiScale(
                equalized,
                scaleFactor=1.1,
                minNeighbors=4,
                minSize=(60, 60),
            ),
            self.profile_cascade.detectMultiScale(
                equalized,
                scaleFactor=1.1,
                minNeighbors=4,
                minSize=(60, 60),
            ),
        ]
        detected_faces = [face for faces in detection_sets for face in faces]
        if len(detected_faces) == 0:
            return None

        x, y, width, height = max(detected_faces, key=lambda rect: rect[2] * rect[3])
        padding = 18
        x0 = max(int(x) - padding, 0)
        y0 = max(int(y) - padding, 0)
        x1 = min(int(x + width) + padding, frame.shape[1])
        y1 = min(int(y + height) + padding, frame.shape[0])
        face_crop = frame[y0:y1, x0:x1]
        return DetectedFace(image=face_crop, bounds=(x0, y0, x1 - x0, y1 - y0))

    def _preprocess_face(self, face_crop: np.ndarray) -> np.ndarray:
        self._require_dependencies()
        grayscale = cv2.cvtColor(face_crop, cv2.COLOR_BGR2GRAY)
        equalized = cv2.equalizeHist(grayscale)
        resized = cv2.resize(equalized, (64, 64), interpolation=cv2.INTER_AREA)
        return resized

    def _camera_candidates(self) -> list[tuple[int, str, int]]:
        self._require_dependencies()
        backends: list[tuple[str, int]] = []
        if hasattr(cv2, "CAP_DSHOW"):
            backends.append(("DirectShow", cv2.CAP_DSHOW))
        else:
            backends.append(("Default", cv2.CAP_ANY))
        return [
            (camera_index, backend_name, backend)
            for camera_index in range(4)
            for backend_name, backend in backends
        ]

    def _prepare_camera(self, camera) -> None:
        if hasattr(cv2, "CAP_PROP_FRAME_WIDTH"):
            camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        if hasattr(cv2, "CAP_PROP_FRAME_HEIGHT"):
            camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        if hasattr(cv2, "CAP_PROP_BUFFERSIZE"):
            camera.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        time.sleep(0.2)

    def _is_blank_frame(self, frame: np.ndarray) -> bool:
        if frame is None or frame.size == 0:
            return True
        return float(frame.std()) < 2.0

    def _compress_features(self, features: np.ndarray, target_size: int) -> np.ndarray:
        self._require_dependencies()
        if features.size == 0:
            raise RuntimeError("Unable to extract face features from the captured image.")

        if features.size < target_size:
            padded = np.pad(features, (0, target_size - features.size))
            return self._normalize_vector(padded)

        chunk_edges = np.linspace(0, features.size, target_size + 1, dtype=int)
        compressed = np.empty(target_size, dtype=np.float32)
        for index in range(target_size):
            start = chunk_edges[index]
            end = chunk_edges[index + 1]
            segment = features[start:end]
            compressed[index] = float(segment.mean()) if segment.size else 0.0
        return self._normalize_vector(compressed)

    def _normalize_vector(self, vector: np.ndarray) -> np.ndarray:
        self._require_dependencies()
        norm = np.linalg.norm(vector)
        if norm == 0:
            return vector.astype(np.float32)
        return (vector / norm).astype(np.float32)

    def _cosine_distance(self, left: np.ndarray, right: np.ndarray) -> float:
        self._require_dependencies()
        left_normalized = self._normalize_vector(left)
        right_normalized = self._normalize_vector(right)
        similarity = float(np.clip(np.dot(left_normalized, right_normalized), -1.0, 1.0))
        return 1.0 - similarity

    def _require_dependencies(self) -> None:
        if cv2 is None or np is None:
            raise RuntimeError(
                "OpenCV/NumPy dependencies are not available for this Python runtime. "
                "Repair the virtual environment or install opencv-python before using face capture."
            )
