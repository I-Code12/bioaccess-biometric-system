from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class RegisterPage(QWidget):
    register_requested = Signal(dict)

    def __init__(self) -> None:
        super().__init__()

        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText("Enter full name")
        self.student_id_input = QLineEdit()
        self.student_id_input.setPlaceholderText("Enter student or staff ID (alphanumeric)")
        self.programme_input = QLineEdit()
        self.programme_input.setPlaceholderText("e.g. BSc Information Technology")
        self.department_input = QLineEdit()
        self.department_input.setPlaceholderText("e.g. Computer Science")
        self.level_input = QComboBox()
        self.level_input.addItems(["Select level", "100", "200", "300", "400", "500", "Postgraduate"])
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("e.g. student@university.edu")
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("e.g. +233 20 000 0000")
        self.status_output = QTextEdit()
        self.status_output.setReadOnly(True)
        self.status_output.setPlaceholderText("Enrollment progress and device messages will appear here.")

        title = QLabel("User Enrollment")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Create a new record using three face samples and official Futronic three-scan fingerprint enrollment."
        )
        subtitle.setObjectName("pageSubtitle")

        form_layout = QFormLayout()
        form_layout.setSpacing(14)
        form_layout.addRow("Full name", self.full_name_input)
        form_layout.addRow("Student ID", self.student_id_input)
        form_layout.addRow("Programme", self.programme_input)
        form_layout.addRow("Department", self.department_input)
        form_layout.addRow("Level", self.level_input)
        form_layout.addRow("Email", self.email_input)
        form_layout.addRow("Phone", self.phone_input)

        self.capture_button = QPushButton("Capture Biometrics and Register")
        self.capture_button.setObjectName("primaryButton")
        self.capture_button.clicked.connect(self._emit_register_request)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(self.capture_button)

        guidance = QLabel(
            "Prepare the subject for three face captures. For the FS80, use the same finger for all three official SDK scans, keep the sensor clean, and lift fully between scans."
        )
        guidance.setObjectName("infoText")
        guidance.setWordWrap(True)

        form_card = QFrame()
        form_card.setObjectName("panelCard")
        form_card_layout = QVBoxLayout(form_card)
        form_card_layout.setSpacing(16)
        form_header = QLabel("Enrollment details")
        form_header.setObjectName("sectionTitle")
        form_card_layout.addWidget(form_header)
        form_card_layout.addLayout(form_layout)
        form_card_layout.addWidget(guidance)
        form_card_layout.addLayout(button_row)

        status_card = QFrame()
        status_card.setObjectName("panelCard")
        status_layout = QVBoxLayout(status_card)
        status_layout.setSpacing(12)
        status_header = QLabel("Capture status")
        status_header.setObjectName("sectionTitle")
        status_layout.addWidget(status_header)
        status_layout.addWidget(self.status_output)

        layout = QVBoxLayout(self)
        layout.setSpacing(18)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(form_card)
        layout.addWidget(status_card)

    def _emit_register_request(self) -> None:
        full_name = self.full_name_input.text().strip()
        student_id = self.student_id_input.text().strip()
        programme = self.programme_input.text().strip()
        department = self.department_input.text().strip()
        level = self.level_input.currentText() if self.level_input.currentIndex() > 0 else ""
        email = self.email_input.text().strip().lower()
        phone = self.phone_input.text().strip()

        # Basic validation
        if not full_name:
            self.append_status("Error: Full name cannot be empty")
            return
        if not student_id:
            self.append_status("Error: Student ID cannot be empty")
            return
        if len(student_id) < 2:
            self.append_status("Error: Student ID must be at least 2 characters long")
            return
        if not programme:
            self.append_status("Error: Programme cannot be empty")
            return
        if not department:
            self.append_status("Error: Department cannot be empty")
            return
        if not level:
            self.append_status("Error: Select the student's level")
            return
        if email and ("@" not in email or "." not in email.split("@")[-1]):
            self.append_status("Error: Enter a valid email address")
            return

        self.register_requested.emit({
            "full_name": full_name,
            "student_id": student_id,
            "programme": programme,
            "department": department,
            "level": level,
            "email": email,
            "phone": phone,
        })

    def append_status(self, message: str) -> None:
        self.status_output.append(message)

    def clear_inputs(self) -> None:
        self.full_name_input.clear()
        self.student_id_input.clear()
        self.programme_input.clear()
        self.department_input.clear()
        self.level_input.setCurrentIndex(0)
        self.email_input.clear()
        self.phone_input.clear()

    def clear_status(self) -> None:
        self.status_output.clear()
