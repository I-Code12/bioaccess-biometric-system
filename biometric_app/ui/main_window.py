from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from biometric_app.services.db_service import DatabaseService
from biometric_app.services.face_service import FaceRecognitionService
from biometric_app.services.fingerprint_service import FingerprintService
from biometric_app.models import AccountRecord
from biometric_app.rbac import (
    ENROL_BIOMETRICS,
    MANAGE_ACCOUNTS,
    MANAGE_STUDENTS,
    REGISTER_STUDENTS,
    VERIFY_STUDENTS,
    VIEW_STUDENTS,
    has_all_permissions,
    has_any_permission,
    has_permission,
    role_summary,
)
from biometric_app.ui.access_control_page import AccessControlPage
from biometric_app.ui.dashboard_page import DashboardPage
from biometric_app.ui.register_page import RegisterPage
from biometric_app.ui.verify_page import VerifyPage


class FingerprintEnrollmentWorker(QObject):
    completed = Signal(bytes)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, fingerprint_service: FingerprintService) -> None:
        super().__init__()
        self.fingerprint_service = fingerprint_service

    @Slot()
    def run(self) -> None:
        try:
            self.progress.emit("Starting the Futronic scanner...")
            self.completed.emit(
                self.fingerprint_service.enroll_template(self.progress.emit)
            )
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(
        self,
        db_service: DatabaseService,
        face_service: FaceRecognitionService,
        fingerprint_service: FingerprintService,
        account: AccountRecord,
    ) -> None:
        super().__init__()
        self.db_service = db_service
        self.face_service = face_service
        self.fingerprint_service = fingerprint_service
        self.account = account
        self._fingerprint_thread: QThread | None = None
        self._fingerprint_worker: FingerprintEnrollmentWorker | None = None
        self._fingerprint_progress: QProgressDialog | None = None
        self._fingerprint_reenroll_user_id: int | None = None
        self._fingerprint_reenroll_user_name = ""

        self.setWindowTitle("Biometric Desktop App")
        self.resize(1240, 760)
        self._apply_styles()

        self.page_title_label = QLabel("Control Center")
        self.page_title_label.setObjectName("shellTitle")
        self.page_subtitle_label = QLabel("Manage enrollment, verification, and scanner readiness.")
        self.page_subtitle_label.setObjectName("shellSubtitle")
        self.device_status_label = QLabel()
        self.device_status_label.setObjectName("deviceStatus")

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("navList")
        self.sidebar.setSpacing(6)
        for label in ("Dashboard", "Register", "Verify", "Access Control"):
            QListWidgetItem(label, self.sidebar)

        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage()
        self.register_page = RegisterPage()
        self.verify_page = VerifyPage()
        self.access_control_page = AccessControlPage()

        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.register_page)
        self.stack.addWidget(self.verify_page)
        self.stack.addWidget(self.access_control_page)

        self._build_shell()
        self._connect_signals()
        self.sidebar.setCurrentRow(0)
        self._set_active_page(0)
        self._show_sdk_status()
        self._apply_access_controls()
        self.refresh_dashboard()

    def _has_permission(self, permission: str) -> bool:
        return has_permission(self.account, permission)

    def _apply_access_controls(self) -> None:
        can_register = has_all_permissions(
            self.account, (REGISTER_STUDENTS, ENROL_BIOMETRICS)
        )
        can_verify = self._has_permission(VERIFY_STUDENTS)
        can_view_students = has_any_permission(
            self.account,
            (
                VIEW_STUDENTS,
                REGISTER_STUDENTS,
                ENROL_BIOMETRICS,
                MANAGE_STUDENTS,
                MANAGE_ACCOUNTS,
            ),
        )
        can_manage_accounts = self._has_permission(MANAGE_ACCOUNTS)
        self.sidebar.item(1).setHidden(not can_register)
        self.sidebar.item(2).setHidden(not can_verify)
        self.sidebar.item(3).setHidden(not can_manage_accounts)
        self.dashboard_page.set_student_records_visible(can_view_students)
        self.dashboard_page.delete_button.setVisible(
            self._has_permission(MANAGE_STUDENTS)
        )
        self.dashboard_page.reenroll_fingerprint_button.setVisible(
            can_view_students and self._has_permission(ENROL_BIOMETRICS)
        )
        self.dashboard_page.reenroll_face_button.setVisible(
            can_view_students and self._has_permission(ENROL_BIOMETRICS)
        )
        self.statusBar().showMessage(
            f"Signed in as {self.account.display_name} | {role_summary(self.account)}"
        )
        if can_manage_accounts:
            self.refresh_access_control()

    def _build_shell(self) -> None:
        container = QWidget()
        outer_layout = QHBoxLayout(container)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        sidebar_shell = QFrame()
        sidebar_shell.setObjectName("sidebarShell")
        sidebar_layout = QVBoxLayout(sidebar_shell)
        sidebar_layout.setContentsMargins(22, 22, 22, 22)
        sidebar_layout.setSpacing(16)

        brand_title = QLabel("BioAccess")
        brand_title.setObjectName("brandTitle")
        brand_tagline = QLabel("Face and fingerprint identity console")
        brand_tagline.setObjectName("brandTagline")

        sidebar_layout.addWidget(brand_title)
        sidebar_layout.addWidget(brand_tagline)
        sidebar_layout.addWidget(self.sidebar)
        sidebar_layout.addStretch(1)

        content_shell = QFrame()
        content_shell.setObjectName("contentShell")
        content_layout = QVBoxLayout(content_shell)
        content_layout.setContentsMargins(28, 24, 28, 24)
        content_layout.setSpacing(18)

        header = QFrame()
        header.setObjectName("headerCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(22, 18, 22, 18)
        header_layout.setSpacing(8)
        header_layout.addWidget(self.page_title_label)
        header_layout.addWidget(self.page_subtitle_label)
        header_layout.addWidget(self.device_status_label, alignment=Qt.AlignLeft)

        content_layout.addWidget(header)
        content_layout.addWidget(self.stack)

        outer_layout.addWidget(sidebar_shell, 1)
        outer_layout.addWidget(content_shell, 4)
        self.setCentralWidget(container)

    def _connect_signals(self) -> None:
        self.register_page.register_requested.connect(self.register_user)
        self.verify_page.verify_requested.connect(self.verify_user)
        self.dashboard_page.delete_requested.connect(self.delete_user)
        self.dashboard_page.reenroll_fingerprint_requested.connect(self.reenroll_fingerprint)
        self.dashboard_page.reenroll_face_requested.connect(self.reenroll_face)
        self.access_control_page.create_account_requested.connect(
            self.create_operator_account
        )
        self.access_control_page.role_change_requested.connect(
            self.change_operator_role
        )
        self.access_control_page.status_change_requested.connect(
            self.change_operator_status
        )
        self.access_control_page.refresh_requested.connect(
            self.refresh_access_control
        )
        self.sidebar.currentRowChanged.connect(self._set_active_page)

    def _show_sdk_status(self) -> None:
        if self.fingerprint_service.is_sdk_available():
            message = "Fingerprint scanner detected and ready."
        else:
            message = (
                "Futronic FS80 unavailable. Reconnect its USB cable and close any other "
                "fingerprint software that may be using it."
            )
        self.statusBar().showMessage(message)
        self.device_status_label.setText(message)

    def refresh_dashboard(self) -> None:
        can_view_students = has_any_permission(
            self.account,
            (
                VIEW_STUDENTS,
                REGISTER_STUDENTS,
                ENROL_BIOMETRICS,
                MANAGE_STUDENTS,
                MANAGE_ACCOUNTS,
            ),
        )
        self.dashboard_page.populate(
            users=self.db_service.get_users() if can_view_students else [],
            log_count=self.db_service.get_verification_log_count(),
            sdk_available=self.fingerprint_service.is_sdk_available(),
            inside_count=self.db_service.get_inside_count(),
        )
        self.dashboard_page.set_student_records_visible(can_view_students)

    def refresh_access_control(self) -> None:
        if not self._has_permission(MANAGE_ACCOUNTS):
            return
        try:
            self.access_control_page.set_roles(
                self.db_service.get_available_roles()
            )
            self.access_control_page.populate_accounts(
                self.db_service.get_operator_accounts()
            )
        except Exception as exc:
            self._warn(str(exc))

    def create_operator_account(self, details: dict) -> None:
        if not self._has_permission(MANAGE_ACCOUNTS):
            self._warn(
                "Only an administrator can create staff accounts and assign roles."
            )
            return
        try:
            account_id = self.db_service.create_operator_account(
                display_name=details.get("display_name", ""),
                username=details.get("username", ""),
                password=details.get("password", ""),
                role_name=details.get("role_name", ""),
            )
        except Exception as exc:
            self._warn(str(exc))
            return
        self.access_control_page.clear_new_account_form()
        self.refresh_access_control()
        self.statusBar().showMessage(
            f"Staff account created successfully with ID {account_id}."
        )

    def change_operator_role(self, account_id: int, role_name: str) -> None:
        if not self._has_permission(MANAGE_ACCOUNTS):
            self._warn("Only an administrator can change staff roles.")
            return
        answer = QMessageBox.question(
            self,
            "Change Staff Role",
            (
                "Replace the selected staff member's current role with "
                f"{role_name.replace('_', ' ').title()}?\n\n"
                "The new permissions take effect the next time that staff member signs in."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            self.db_service.replace_operator_role(account_id, role_name)
        except Exception as exc:
            self._warn(str(exc))
            return
        self.refresh_access_control()
        self.statusBar().showMessage("Staff role updated.")

    def change_operator_status(self, account_id: int, status: str) -> None:
        if not self._has_permission(MANAGE_ACCOUNTS):
            self._warn("Only an administrator can change staff account access.")
            return
        action = "activate and unlock" if status == "active" else "disable"
        answer = QMessageBox.question(
            self,
            "Change Staff Access",
            f"Do you want to {action} the selected staff account?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            self.db_service.set_operator_status(account_id, status)
        except Exception as exc:
            self._warn(str(exc))
            return
        self.refresh_access_control()
        self.statusBar().showMessage("Staff account access updated.")

    def register_user(self, registration: dict) -> None:
        if not (self._has_permission("register_students") and self._has_permission("enrol_biometrics")):
            self._warn("Your account does not have permission to register students and biometrics.")
            return
        full_name = registration.get("full_name", "").strip()
        student_id = registration.get("student_id", "").strip()
        if not full_name or not student_id or not registration.get("programme"):
            self._warn("Registration requires full name, student ID, and programme.")
            return

        self.register_page.clear_status()
        self.page_title_label.setText("User Enrollment")
        self.page_subtitle_label.setText("Capturing biometric data for a new record.")

        if not self.fingerprint_service.is_sdk_available():
            message = (
                "Fingerprint enrollment is required, but the Futronic scanner could not be opened. "
                "Connect the device, confirm its driver in Device Manager, and try again."
            )
            self.register_page.append_status(message)
            self._warn(message)
            return

        try:
            face_samples = []
            for sample_number in range(1, self.face_service.ENROLLMENT_SAMPLE_COUNT + 1):
                self._info(
                    f"Face Capture {sample_number}/{self.face_service.ENROLLMENT_SAMPLE_COUNT}",
                    "Keep exactly one face visible. Look forward and vary the head angle slightly between captures.",
                )
                self.register_page.append_status(
                    f"Capturing face sample {sample_number}/{self.face_service.ENROLLMENT_SAMPLE_COUNT}..."
                )
                face_bytes = self.face_service.capture_face_frame()
                face_samples.append(self.face_service.create_embedding(face_bytes))
                del face_bytes
            face_embedding = self.face_service.combine_enrollment_embeddings(face_samples)
            face_samples.clear()

            self._info(
                "Official Futronic Fingerprint Enrollment",
                (
                    "Use the same finger for all three scans. Place it flat when the scanner "
                    "lights, hold still, then lift it fully before the next scan."
                ),
            )
            self.register_page.append_status(
                "Starting official Futronic three-scan fingerprint enrollment..."
            )
            fingerprint_template = self.fingerprint_service.enroll_template()
            self.register_page.append_status(
                "Official Futronic fingerprint template enrolled successfully."
            )

            user_id = self.db_service.add_user(
                full_name=full_name,
                student_id=student_id,
                face_embedding=face_embedding,
                fingerprint_template=fingerprint_template,
                programme=registration["programme"],
                department=registration.get("department"),
                level=registration.get("level"),
                email=registration.get("email"),
                phone=registration.get("phone"),
            )
            del face_embedding, fingerprint_template
        except ValueError as exc:
            self.register_page.append_status(f"Registration failed: {exc}")
            self._warn(str(exc))
            return
        except Exception as exc:
            self.register_page.append_status(f"Registration failed: {exc}")
            self._warn(str(exc))
            return

        self.register_page.append_status(f"User enrolled successfully with ID {user_id}.")
        self.register_page.clear_inputs()
        self.page_subtitle_label.setText("Biometric record stored successfully.")
        self.refresh_dashboard()

    def verify_user(self) -> None:
        if not self._has_permission("verify_students"):
            self._warn("Your account does not have permission to verify students.")
            return

        self.verify_page.clear_results()
        self.verify_page.set_banner("Verification in progress", success=None)
        selected_mode = self.verify_page.selected_verification_mode()
        enrolled_users = self.db_service.get_user_biometrics(
            require_face=selected_mode in {"EXIT", "VERIFY"},
            require_fingerprint=selected_mode in {"ENTRY", "VERIFY"},
        )
        if not enrolled_users:
            self._warn("No usable biometric records were found for the selected verification mode.")
            return
        self.verify_page.append_result(
            f"Loaded {len(enrolled_users)} usable biometric candidate(s) for {selected_mode}."
        )

        mode_labels = {
            "ENTRY": "Examination Entry",
            "EXIT": "Examination Exit",
            "VERIFY": "Identity Verification",
        }
        self.page_title_label.setText(mode_labels.get(selected_mode, "Identity Verification"))
        self.page_subtitle_label.setText("Running the selected biometric workflow.")

        try:
            if selected_mode == "ENTRY":
                if not self.fingerprint_service.is_sdk_available():
                    message = (
                        "Entry verification requires the Futronic fingerprint scanner. "
                        "Connect the device and try again."
                    )
                    self.verify_page.append_result(message)
                    self.verify_page.set_banner("Entry denied", success=False)
                    self._warn(message)
                    return

                self._info(
                    "Examination Entry",
                    "Place the enrolled finger on the Futronic scanner for entry verification.",
                )
                self.verify_page.append_result(
                    "Capturing and checking entry fingerprint with the official Futronic matcher..."
                )
                fingerprint_result = self.fingerprint_service.verify_against_database(
                    enrolled_users,
                )
                self.db_service.record_result("FINGERPRINT", fingerprint_result)
                self.verify_page.append_result(fingerprint_result.message)
                access_success, access_message = self.db_service.record_access_event(
                    access_type="ENTRY",
                    biometric_success=fingerprint_result.success,
                    matched_user_id=fingerprint_result.matched_user_id if fingerprint_result.success else None,
                    details=f"Fingerprint: {fingerprint_result.message}",
                )
                self.verify_page.append_result(access_message)
                self.verify_page.set_banner(
                    "Entry granted" if access_success else "Entry denied",
                    success=access_success,
                )
                self.refresh_dashboard()
                return

            if selected_mode == "EXIT":
                self._info(
                    "Examination Exit",
                    "The camera will open now. Ask the student to look at the camera for exit verification.",
                )
                self.verify_page.append_result("Capturing exit face...")
                face_bytes = self.face_service.capture_face_frame()
                face_result = self.face_service.verify_against_database(
                    face_bytes,
                    enrolled_users,
                    threshold=self.face_service.EXIT_FACE_DISTANCE_THRESHOLD,
                    allow_fingerprint_disambiguation=False,
                )
                del face_bytes
                self.db_service.record_result("FACE", face_result)
                self.verify_page.append_result(face_result.message)
                access_success, access_message = self.db_service.record_access_event(
                    access_type="EXIT",
                    biometric_success=face_result.success,
                    matched_user_id=face_result.matched_user_id if face_result.success else None,
                    details=f"Face: {face_result.message}",
                )
                self.verify_page.append_result(access_message)
                self.verify_page.set_banner(
                    "Exit granted" if access_success else "Exit denied",
                    success=access_success,
                )
                self.refresh_dashboard()
                return

            if not self.fingerprint_service.is_sdk_available():
                message = (
                    "Combined identity verification requires the Futronic fingerprint scanner. "
                    "Connect the device and try again."
                )
                self.verify_page.append_result(message)
                self.verify_page.set_banner("Identity rejected", success=False)
                self._warn(message)
                return

            self._info(
                "Identity Verification",
                "The camera will open now for the face check. Fingerprint verification will follow if the face is confirmed.",
            )
            self.verify_page.append_result("Capturing live face...")
            face_bytes = self.face_service.capture_face_frame()
            face_result = self.face_service.verify_against_database(face_bytes, enrolled_users)
            del face_bytes
            self.db_service.record_result("FACE", face_result)
            self.verify_page.append_result(face_result.message)
            face_candidate_ids = set(face_result.candidate_user_ids)
            can_disambiguate_with_fingerprint = (
                bool(face_candidate_ids)
                and face_result.matched_user_id is not None
            )
            if (
                (not face_result.success or face_result.matched_user_id is None)
                and not can_disambiguate_with_fingerprint
            ):
                self.verify_page.append_result("Combined verification failed because the face was not confirmed.")
                self.verify_page.set_banner("Identity rejected", success=False)
                self.refresh_dashboard()
                return

            self._info(
                "Fingerprint Verification",
                "Place the enrolled finger on the Futronic scanner to complete verification.",
            )
            self.verify_page.append_result(
                "Capturing and checking the live fingerprint with the official Futronic matcher..."
            )
            fingerprint_candidates = enrolled_users
            if face_candidate_ids:
                fingerprint_candidates = [
                    user for user in enrolled_users if user.get("id") in face_candidate_ids
                ]
            elif face_result.success and face_result.matched_user_id is not None:
                fingerprint_candidates = [
                    user for user in enrolled_users if user.get("id") == face_result.matched_user_id
                ]
            fingerprint_result = self.fingerprint_service.verify_against_database(
                fingerprint_candidates,
            )
            self.db_service.record_result("FINGERPRINT", fingerprint_result)
            self.verify_page.append_result(fingerprint_result.message)

            same_identity = (
                face_result.matched_user_id is not None
                and fingerprint_result.matched_user_id is not None
                and (
                    face_result.matched_user_id == fingerprint_result.matched_user_id
                    or fingerprint_result.matched_user_id in face_candidate_ids
                )
            )
            face_confirmed = face_result.success or can_disambiguate_with_fingerprint
            overall_success = face_confirmed and fingerprint_result.success and same_identity
            if overall_success:
                if not face_result.success and can_disambiguate_with_fingerprint:
                    self.verify_page.append_result(
                        "Face was ambiguous, but fingerprint confirmed one of the close face candidates."
                    )
                self.verify_page.append_result("Combined face and fingerprint verification passed.")
            elif face_result.success and fingerprint_result.success and not same_identity:
                self.verify_page.append_result(
                    "Combined verification failed because the face and fingerprint matched different records."
                )
            else:
                self.verify_page.append_result("Combined verification failed.")

            self.verify_page.set_banner(
                "Identity confirmed" if overall_success else "Identity rejected",
                success=overall_success,
            )
            self.refresh_dashboard()
        except Exception as exc:
            self.verify_page.append_result(f"Verification failed: {exc}")
            self.verify_page.set_banner("Verification error", success=False)
            self._warn(str(exc))
        finally:
            enrolled_users.clear()

    def delete_user(self, user_id: int) -> None:
        if not self._has_permission("manage_users"):
            self._warn("Your account does not have permission to deactivate student records.")
            return
        user = next((item for item in self.db_service.get_users() if item.id == user_id), None)
        if user is None:
            self._warn("The selected user could not be found.")
            return

        answer = QMessageBox.question(
            self,
            "Deactivate Student",
            (
                f"Deactivate {user.full_name} ({user.student_id})?\n\n"
                "The record and its audit history will be retained."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        try:
            self.db_service.delete_user(user_id)
        except Exception as exc:
            self._warn(str(exc))
            return

        self.statusBar().showMessage(f"Deactivated student {user.full_name}.")
        self.refresh_dashboard()

    def reenroll_fingerprint(self, user_id: int) -> None:
        if not self._has_permission("enrol_biometrics"):
            self._warn("Your account does not have permission to re-enroll fingerprints.")
            return
        user = next((item for item in self.db_service.get_users() if item.id == user_id), None)
        if user is None:
            self._warn("The selected user could not be found.")
            return
        if not self.fingerprint_service.is_sdk_available():
            self._warn(
                "Fingerprint re-enrollment requires the Futronic scanner. Connect the scanner and try again."
            )
            return

        answer = QMessageBox.question(
            self,
            "Re-enroll Fingerprint",
            (
                f"Replace the fingerprint template for {user.full_name} ({user.student_id})?\n\n"
                "Use the correct enrolled finger and scan it three times."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        self._info(
            "Official Futronic Fingerprint Re-enrollment",
            (
                "Use the correct same finger for all three scans. Place it flat, hold "
                "still, and lift it fully between scans."
            ),
        )
        self._start_fingerprint_reenrollment(user_id, user.full_name)

    def _start_fingerprint_reenrollment(self, user_id: int, user_name: str) -> None:
        if self._fingerprint_thread is not None:
            self._warn("A fingerprint operation is already running.")
            return

        self._fingerprint_reenroll_user_id = user_id
        self._fingerprint_reenroll_user_name = user_name
        self._set_biometric_busy(True)

        progress = QProgressDialog(self)
        progress.setWindowTitle("Fingerprint Re-enrollment")
        progress.setLabelText(
            "Waiting for the official Futronic three-scan enrollment.\n\n"
            "Use the same finger. Follow the scanner lights and lift fully between scans."
        )
        progress.setRange(0, 0)
        progress.setCancelButton(None)
        progress.setMinimumDuration(0)
        progress.setWindowModality(Qt.NonModal)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.show()
        self._fingerprint_progress = progress

        thread = QThread(self)
        worker = FingerprintEnrollmentWorker(self.fingerprint_service)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._complete_fingerprint_reenrollment)
        worker.failed.connect(self._fail_fingerprint_reenrollment)
        worker.progress.connect(self._update_fingerprint_progress)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(self._cleanup_fingerprint_thread)
        self._fingerprint_thread = thread
        self._fingerprint_worker = worker

        self.statusBar().showMessage(
            f"Official fingerprint re-enrollment is running for {user_name}..."
        )
        thread.start()

    @Slot(str)
    def _update_fingerprint_progress(self, message: str) -> None:
        if self._fingerprint_progress is not None:
            self._fingerprint_progress.setLabelText(
                f"{message}\n\nUse the same finger for all three scans."
            )
        self.statusBar().showMessage(message)

    @Slot(bytes)
    def _complete_fingerprint_reenrollment(self, fingerprint_template: bytes) -> None:
        user_id = self._fingerprint_reenroll_user_id
        user_name = self._fingerprint_reenroll_user_name
        try:
            if user_id is None:
                raise RuntimeError("The selected fingerprint record is no longer available.")
            self.db_service.update_user_fingerprint(user_id, fingerprint_template)
        except Exception as exc:
            self._finish_fingerprint_progress()
            self._set_biometric_busy(False)
            self._warn(str(exc))
            return
        finally:
            del fingerprint_template

        self._finish_fingerprint_progress()
        self._set_biometric_busy(False)
        self.statusBar().showMessage(f"Fingerprint re-enrolled for {user_name}.")
        self.refresh_dashboard()
        self._info(
            "Fingerprint Re-enrollment Complete",
            f"The official Futronic template for {user_name} was encrypted and saved.",
        )

    @Slot(str)
    def _fail_fingerprint_reenrollment(self, message: str) -> None:
        self._finish_fingerprint_progress()
        self._set_biometric_busy(False)
        self.statusBar().showMessage("Fingerprint re-enrollment failed.")
        self._warn(message)

    @Slot()
    def _cleanup_fingerprint_thread(self) -> None:
        thread = self._fingerprint_thread
        self._fingerprint_thread = None
        self._fingerprint_worker = None
        self._fingerprint_reenroll_user_id = None
        self._fingerprint_reenroll_user_name = ""
        if thread is not None:
            thread.deleteLater()

    def _finish_fingerprint_progress(self) -> None:
        if self._fingerprint_progress is not None:
            self._fingerprint_progress.close()
            self._fingerprint_progress.deleteLater()
            self._fingerprint_progress = None

    def _set_biometric_busy(self, busy: bool) -> None:
        enabled = not busy
        self.dashboard_page.reenroll_fingerprint_button.setEnabled(enabled)
        self.dashboard_page.reenroll_face_button.setEnabled(enabled)
        self.dashboard_page.delete_button.setEnabled(enabled)
        self.register_page.capture_button.setEnabled(enabled)
        self.verify_page.verify_button.setEnabled(enabled)
        self.device_status_label.setText(
            "Fingerprint enrollment in progress—follow the FS80 lights."
            if busy
            else "Fingerprint scanner detected and ready."
        )

    def closeEvent(self, event) -> None:
        if self._fingerprint_thread is not None and self._fingerprint_thread.isRunning():
            self._warn(
                "Fingerprint enrollment is still running. Complete the scans or wait for "
                "the timeout before closing BioAccess."
            )
            event.ignore()
            return
        super().closeEvent(event)

    def reenroll_face(self, user_id: int) -> None:
        if not self._has_permission("enrol_biometrics"):
            self._warn("Your account does not have permission to re-enroll face templates.")
            return
        user = next((item for item in self.db_service.get_users() if item.id == user_id), None)
        if user is None:
            self._warn("The selected user could not be found.")
            return

        answer = QMessageBox.question(
            self,
            "Re-enroll Face",
            (
                f"Replace the face template for {user.full_name} ({user.student_id})?\n\n"
                "Use bright front lighting, center the face, and look directly at the camera."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        try:
            self._info(
                "Face Re-enrollment",
                "The camera will open now. Center the face clearly, use good lighting, and look directly at the camera.",
            )
            face_samples = []
            for sample_number in range(1, self.face_service.ENROLLMENT_SAMPLE_COUNT + 1):
                self._info(
                    f"Face Re-enrollment {sample_number}/{self.face_service.ENROLLMENT_SAMPLE_COUNT}",
                    "Keep exactly one face visible and vary the head angle slightly between captures.",
                )
                face_bytes = self.face_service.capture_face_frame()
                face_samples.append(self.face_service.create_embedding(face_bytes))
                del face_bytes
            face_embedding = self.face_service.combine_enrollment_embeddings(face_samples)
            face_samples.clear()
            self.db_service.update_user_face(user_id, face_embedding)
            del face_embedding
        except Exception as exc:
            self._warn(str(exc))
            return

        self.statusBar().showMessage(f"Face re-enrolled for {user.full_name}.")
        self.refresh_dashboard()

    def _warn(self, message: str) -> None:
        QMessageBox.warning(self, "Biometric Desktop App", message)

    def _info(self, title: str, message: str) -> None:
        QMessageBox.information(self, title, message)

    def _set_active_page(self, index: int) -> None:
        if index < 0:
            return

        page_permissions = {
            1: (REGISTER_STUDENTS, ENROL_BIOMETRICS),
            2: (VERIFY_STUDENTS,),
            3: (MANAGE_ACCOUNTS,),
        }
        required = page_permissions.get(index, ())
        if required and not has_all_permissions(self.account, required):
            self.sidebar.blockSignals(True)
            self.sidebar.setCurrentRow(0)
            self.sidebar.blockSignals(False)
            self.stack.setCurrentIndex(0)
            self._warn("Your assigned role cannot open that section.")
            index = 0

        self.stack.setCurrentIndex(index)
        page_meta = {
            0: ("Control Center", "Track enrollment totals, verification volume, and scanner readiness."),
            1: ("User Enrollment", "Capture face and fingerprint data for a new subject."),
            2: ("Identity Verification", "Run a live biometric check against stored records."),
            3: (
                "Role-Based Access Control",
                "Manage staff accounts, operational roles, and sign-in access.",
            ),
        }
        title, subtitle = page_meta.get(index, ("Biometric Desktop App", ""))
        self.page_title_label.setText(title)
        self.page_subtitle_label.setText(subtitle)

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background: #f3f7f8;
                color: #132a2a;
            }
            #sidebarShell {
                background: #12383c;
                min-width: 220px;
                max-width: 260px;
            }
            #contentShell {
                background: #f3f7f8;
            }
            #brandTitle {
                color: #f5fffd;
                font-size: 28px;
                font-weight: 700;
            }
            #brandTagline {
                color: #c2d9d4;
                font-size: 13px;
            }
            #navList {
                background: transparent;
                border: none;
                color: #f2faf8;
                outline: 0;
            }
            #navList::item {
                border-radius: 8px;
                padding: 12px 14px;
                margin: 2px 0;
            }
            #navList::item:selected {
                background: #2f8f7b;
                color: #ffffff;
            }
            #navList::item:hover {
                background: #1b555b;
            }
            #headerCard, #panelCard {
                background: #ffffff;
                border: 1px solid #d7e5e1;
                border-radius: 8px;
            }
            #shellTitle, #pageTitle {
                color: #143336;
                font-size: 26px;
                font-weight: 700;
            }
            #shellSubtitle, #pageSubtitle {
                color: #4f6969;
                font-size: 14px;
            }
            #deviceStatus {
                background: #e7f2ec;
                color: #235b45;
                border-radius: 8px;
                padding: 8px 12px;
                font-size: 13px;
                font-weight: 600;
            }
            #metricValue {
                color: #143336;
                font-size: 28px;
                font-weight: 700;
            }
            #metricLabel, #infoText {
                color: #587070;
                font-size: 13px;
            }
            #sectionTitle {
                color: #143336;
                font-size: 16px;
                font-weight: 600;
            }
            #primaryButton {
                background: #da5a38;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 18px;
                font-size: 14px;
                font-weight: 600;
                min-width: 160px;
            }
            #secondaryButton {
                background: #ffffff;
                color: #143336;
                border: 1px solid #c8d9d5;
                border-radius: 8px;
                padding: 10px 18px;
                font-size: 14px;
                font-weight: 600;
                min-width: 180px;
            }
            #secondaryButton:hover {
                background: #edf5f3;
            }
            #primaryButton:hover {
                background: #c94d2c;
            }
            QLineEdit, QTextEdit, QTableWidget {
                background: #fbfdfd;
                border: 1px solid #ccd9d7;
                border-radius: 8px;
                padding: 8px;
                color: #132a2a;
            }
            QLineEdit::placeholder, QTextEdit::placeholder {
                color: #7a8f8f;
            }
            QHeaderView::section {
                background: #e8f0ef;
                color: #294646;
                border: none;
                padding: 8px;
                font-weight: 600;
            }
            #resultBanner {
                border-radius: 8px;
                padding: 10px 12px;
                background: #edf2f2;
                color: #365151;
                font-weight: 600;
            }
            #resultBanner[state="success"] {
                background: #e7f4ea;
                color: #23613b;
            }
            #resultBanner[state="failure"] {
                background: #fdeceb;
                color: #943b2d;
            }
            #resultBanner[state="neutral"] {
                background: #edf2f2;
                color: #365151;
            }
            """
        )
