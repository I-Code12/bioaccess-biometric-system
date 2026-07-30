from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class VerifyPage(QWidget):
    verify_requested = Signal()

    def __init__(self) -> None:
        super().__init__()

        title = QLabel("Identity Verification")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Run exam entry, exam exit, or a separate combined identity verification.")
        subtitle.setObjectName("pageSubtitle")

        self.verify_button = QPushButton("Run Verification")
        self.verify_button.setObjectName("primaryButton")
        self.verify_button.clicked.connect(self.verify_requested.emit)

        self.access_mode_selector = QComboBox()
        self.access_mode_selector.addItem("Examination Entry - Fingerprint only", "ENTRY")
        self.access_mode_selector.addItem("Examination Exit - Face only", "EXIT")
        self.access_mode_selector.addItem("Identity Verification - Face + Fingerprint", "VERIFY")

        self.result_banner = QLabel("Awaiting verification request")
        self.result_banner.setObjectName("resultBanner")
        self.result_banner.setProperty("state", "neutral")

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText("Verification progress and decisions will appear here.")

        instruction_card = QFrame()
        instruction_card.setObjectName("panelCard")
        instruction_layout = QVBoxLayout(instruction_card)
        instruction_layout.setSpacing(12)
        instruction_header = QLabel("Verification checklist")
        instruction_header.setObjectName("sectionTitle")
        instruction_layout.addWidget(instruction_header)

        steps = QLabel(
            "1. Align the subject with the webcam.\n"
            "2. Choose Entry, Exit, or separate Identity Verification.\n"
            "3. Use the requested biometric device when prompted.\n"
            "4. Review the final decision banner and event log."
        )
        steps.setObjectName("infoText")
        steps.setWordWrap(True)
        instruction_layout.addWidget(steps)

        button_row = QHBoxLayout()
        button_row.addWidget(QLabel("Access mode"))
        button_row.addWidget(self.access_mode_selector)
        button_row.addStretch(1)
        button_row.addWidget(self.verify_button)
        instruction_layout.addLayout(button_row)

        result_card = QFrame()
        result_card.setObjectName("panelCard")
        result_layout = QVBoxLayout(result_card)
        result_layout.setSpacing(12)
        result_header = QLabel("Verification status")
        result_header.setObjectName("sectionTitle")
        result_layout.addWidget(result_header)
        result_layout.addWidget(self.result_banner)
        result_layout.addWidget(self.result_output)

        layout = QVBoxLayout(self)
        layout.setSpacing(18)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(instruction_card)
        layout.addWidget(result_card)

    def append_result(self, message: str) -> None:
        self.result_output.append(message)

    def clear_results(self) -> None:
        self.result_output.clear()
        self.set_banner("Awaiting verification request", success=None)

    def set_banner(self, message: str, success: bool | None = None) -> None:
        state = "neutral"
        if success is True:
            state = "success"
        elif success is False:
            state = "failure"

        self.result_banner.setProperty("state", state)
        self.result_banner.style().unpolish(self.result_banner)
        self.result_banner.style().polish(self.result_banner)
        self.result_banner.setText(message)

    def selected_verification_mode(self) -> str:
        return str(self.access_mode_selector.currentData() or "ENTRY")

    def selected_access_mode(self) -> str:
        return self.selected_verification_mode()
