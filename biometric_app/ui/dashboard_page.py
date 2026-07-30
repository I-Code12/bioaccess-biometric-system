from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class DashboardPage(QWidget):
    delete_requested = Signal(int)
    reenroll_fingerprint_requested = Signal(int)
    reenroll_face_requested = Signal(int)

    def __init__(self) -> None:
        super().__init__()

        title = QLabel("Control Center")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Track enrollment totals, verification activity, and scanner readiness.")
        subtitle.setObjectName("pageSubtitle")

        self.user_count_value = QLabel("0")
        self.user_count_value.setObjectName("metricValue")
        self.user_count_label = QLabel("Registered users")
        self.user_count_label.setObjectName("metricLabel")

        self.log_count_value = QLabel("0")
        self.log_count_value.setObjectName("metricValue")
        self.log_count_label = QLabel("Verification events")
        self.log_count_label.setObjectName("metricLabel")

        self.status_value = QLabel("Pending")
        self.status_value.setObjectName("metricValue")
        self.status_label = QLabel("FS80 status")
        self.status_label.setObjectName("metricLabel")

        self.inside_count_value = QLabel("0")
        self.inside_count_value.setObjectName("metricValue")
        self.inside_count_label = QLabel("Currently inside")
        self.inside_count_label.setObjectName("metricLabel")

        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(16)
        metrics_row.addWidget(self._build_metric_card(self.user_count_value, self.user_count_label))
        metrics_row.addWidget(self._build_metric_card(self.log_count_value, self.log_count_label))
        metrics_row.addWidget(self._build_metric_card(self.inside_count_value, self.inside_count_label))
        metrics_row.addWidget(self._build_metric_card(self.status_value, self.status_label))

        self.section_title = QLabel("Registered users")
        self.section_title.setObjectName("sectionTitle")

        self.user_table = QTableWidget(0, 3)
        self.user_table.setHorizontalHeaderLabels(["ID", "Full Name", "Student ID"])
        self.user_table.horizontalHeader().setStretchLastSection(True)
        self.user_table.verticalHeader().setVisible(False)
        self.user_table.setAlternatingRowColors(True)
        self.user_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.user_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.user_table.setShowGrid(False)
        self.user_table.setSelectionMode(QTableWidget.SingleSelection)

        self.delete_button = QPushButton("Deactivate Student & Remove Biometrics")
        self.delete_button.setObjectName("secondaryButton")
        self.delete_button.clicked.connect(self._emit_delete_request)
        self.reenroll_fingerprint_button = QPushButton("Re-enroll Fingerprint")
        self.reenroll_fingerprint_button.setObjectName("primaryButton")
        self.reenroll_fingerprint_button.clicked.connect(self._emit_reenroll_fingerprint_request)
        self.reenroll_face_button = QPushButton("Re-enroll Face")
        self.reenroll_face_button.setObjectName("primaryButton")
        self.reenroll_face_button.clicked.connect(self._emit_reenroll_face_request)

        self.actions_container = QWidget()
        actions_row = QHBoxLayout(self.actions_container)
        actions_row.setContentsMargins(0, 0, 0, 0)
        actions_row.addStretch(1)
        actions_row.addWidget(self.reenroll_face_button)
        actions_row.addWidget(self.reenroll_fingerprint_button)
        actions_row.addWidget(self.delete_button)

        layout = QVBoxLayout(self)
        layout.setSpacing(18)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(metrics_row)
        layout.addWidget(self.section_title)
        layout.addWidget(self.user_table)
        layout.addWidget(self.actions_container)

    def set_student_records_visible(self, visible: bool) -> None:
        self.section_title.setVisible(visible)
        self.user_table.setVisible(visible)
        self.actions_container.setVisible(visible)
        self.user_count_label.setText(
            "Registered users" if visible else "Student directory"
        )
        if not visible:
            self.user_count_value.setText("Restricted")

    def populate(self, users: list, log_count: int, sdk_available: bool, inside_count: int = 0) -> None:
        self.user_table.clearSpans()
        self.user_table.setRowCount(0)

        self.user_count_value.setText(str(len(users)))
        self.log_count_value.setText(str(log_count))
        self.inside_count_value.setText(str(inside_count))
        self.status_value.setText("Ready" if sdk_available else "Offline")

        if not users:
            self.user_table.setRowCount(1)
            empty_item = QTableWidgetItem("No users enrolled yet.")
            empty_item.setFlags(Qt.ItemIsEnabled)
            self.user_table.setItem(0, 0, empty_item)
            self.user_table.setSpan(0, 0, 1, 3)
            return

        self.user_table.setRowCount(len(users))
        for row_index, user in enumerate(users):
            id_item = QTableWidgetItem(str(user.id))
            id_item.setData(Qt.UserRole, user.id)
            self.user_table.setItem(row_index, 0, id_item)
            self.user_table.setItem(row_index, 1, QTableWidgetItem(user.full_name))
            self.user_table.setItem(row_index, 2, QTableWidgetItem(user.student_id))

    def _emit_delete_request(self) -> None:
        user_id = self._selected_user_id()
        if user_id is None:
            return

        self.delete_requested.emit(user_id)

    def _emit_reenroll_fingerprint_request(self) -> None:
        user_id = self._selected_user_id()
        if user_id is None:
            return

        self.reenroll_fingerprint_requested.emit(user_id)

    def _emit_reenroll_face_request(self) -> None:
        user_id = self._selected_user_id()
        if user_id is None:
            return

        self.reenroll_face_requested.emit(user_id)

    def _selected_user_id(self) -> int | None:
        selected_items = self.user_table.selectedItems()
        if not selected_items:
            return None

        user_id = selected_items[0].data(Qt.UserRole)
        if user_id is None:
            return None

        return int(user_id)

    def _build_metric_card(self, value_label: QLabel, title_label: QLabel) -> QFrame:
        card = QFrame()
        card.setObjectName("panelCard")

        layout = QVBoxLayout(card)
        layout.setSpacing(6)
        layout.addWidget(value_label)
        layout.addWidget(title_label)
        layout.addStretch(1)

        return card
