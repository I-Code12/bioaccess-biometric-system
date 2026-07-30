from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class AccessControlPage(QWidget):
    create_account_requested = Signal(dict)
    role_change_requested = Signal(int, str)
    status_change_requested = Signal(int, str)
    refresh_requested = Signal()

    def __init__(self) -> None:
        super().__init__()

        title = QLabel("Role-Based Access Control")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Create staff accounts, assign one operational role, and control sign-in access."
        )
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)

        self.account_table = QTableWidget(0, 6)
        self.account_table.setHorizontalHeaderLabels(
            ["Username", "Full Name", "Role", "Status", "Failed Sign-ins", "Last Login"]
        )
        self.account_table.horizontalHeader().setStretchLastSection(True)
        self.account_table.verticalHeader().setVisible(False)
        self.account_table.setAlternatingRowColors(True)
        self.account_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.account_table.setSelectionMode(QTableWidget.SingleSelection)
        self.account_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.account_table.setShowGrid(False)

        self.role_selector = QComboBox()
        self.change_role_button = QPushButton("Assign Selected Role")
        self.change_role_button.setObjectName("primaryButton")
        self.change_role_button.clicked.connect(self._emit_role_change)

        self.activate_button = QPushButton("Activate / Unlock")
        self.activate_button.setObjectName("primaryButton")
        self.activate_button.clicked.connect(
            lambda: self._emit_status_change("active")
        )
        self.disable_button = QPushButton("Disable Sign-in")
        self.disable_button.setObjectName("secondaryButton")
        self.disable_button.clicked.connect(
            lambda: self._emit_status_change("disabled")
        )
        refresh_button = QPushButton("Refresh")
        refresh_button.setObjectName("secondaryButton")
        refresh_button.clicked.connect(self.refresh_requested.emit)

        account_actions = QHBoxLayout()
        account_actions.setSpacing(10)
        account_actions.addWidget(QLabel("New role:"))
        account_actions.addWidget(self.role_selector)
        account_actions.addWidget(self.change_role_button)
        account_actions.addStretch(1)
        account_actions.addWidget(self.activate_button)
        account_actions.addWidget(self.disable_button)
        account_actions.addWidget(refresh_button)

        create_card = QFrame()
        create_card.setObjectName("panelCard")
        create_layout = QVBoxLayout(create_card)
        create_layout.setContentsMargins(20, 18, 20, 18)
        create_layout.setSpacing(12)

        create_title = QLabel("Create staff account")
        create_title.setObjectName("sectionTitle")
        create_note = QLabel(
            "Use a temporary password of at least 12 characters with uppercase, "
            "lowercase, number, and symbol characters."
        )
        create_note.setObjectName("pageSubtitle")
        create_note.setWordWrap(True)

        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText("Staff member's full name")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Sign-in username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Temporary password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.new_account_role_selector = QComboBox()

        form = QFormLayout()
        form.setSpacing(10)
        form.addRow("Full name", self.full_name_input)
        form.addRow("Username", self.username_input)
        form.addRow("Temporary password", self.password_input)
        form.addRow("Role", self.new_account_role_selector)

        create_button = QPushButton("Create Staff Account")
        create_button.setObjectName("primaryButton")
        create_button.clicked.connect(self._emit_create_account)

        create_layout.addWidget(create_title)
        create_layout.addWidget(create_note)
        create_layout.addLayout(form)
        create_layout.addWidget(create_button, alignment=Qt.AlignRight)

        layout = QVBoxLayout(self)
        layout.setSpacing(18)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.account_table, 1)
        layout.addLayout(account_actions)
        layout.addWidget(create_card)

    def set_roles(self, roles: list[dict]) -> None:
        current_role = self.role_selector.currentData()
        new_account_role = self.new_account_role_selector.currentData()
        for selector in (self.role_selector, self.new_account_role_selector):
            selector.clear()
            for role in roles:
                selector.addItem(role["label"], role["name"])

        self._restore_selection(self.role_selector, current_role)
        self._restore_selection(
            self.new_account_role_selector,
            new_account_role or "invigilator",
        )

    def populate_accounts(self, accounts: list[dict]) -> None:
        self.account_table.setRowCount(len(accounts))
        for row_index, account in enumerate(accounts):
            username_item = QTableWidgetItem(account["username"])
            username_item.setData(Qt.UserRole, int(account["id"]))
            self.account_table.setItem(row_index, 0, username_item)
            self.account_table.setItem(
                row_index, 1, QTableWidgetItem(account["display_name"])
            )
            self.account_table.setItem(
                row_index, 2, QTableWidgetItem(account["role_label"])
            )
            self.account_table.setItem(
                row_index, 3, QTableWidgetItem(account["status"].title())
            )
            self.account_table.setItem(
                row_index, 4, QTableWidgetItem(str(account["failed_login_attempts"]))
            )
            self.account_table.setItem(
                row_index, 5, QTableWidgetItem(account["last_login"] or "Never")
            )
        self.account_table.resizeColumnsToContents()

    def clear_new_account_form(self) -> None:
        self.full_name_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self._restore_selection(self.new_account_role_selector, "invigilator")

    def _emit_create_account(self) -> None:
        self.create_account_requested.emit(
            {
                "display_name": self.full_name_input.text().strip(),
                "username": self.username_input.text().strip().lower(),
                "password": self.password_input.text(),
                "role_name": self.new_account_role_selector.currentData() or "",
            }
        )

    def _emit_role_change(self) -> None:
        account_id = self._selected_account_id()
        role_name = self.role_selector.currentData()
        if account_id is not None and role_name:
            self.role_change_requested.emit(account_id, str(role_name))

    def _emit_status_change(self, status: str) -> None:
        account_id = self._selected_account_id()
        if account_id is not None:
            self.status_change_requested.emit(account_id, status)

    def _selected_account_id(self) -> int | None:
        selected_items = self.account_table.selectedItems()
        if not selected_items:
            return None
        account_id = self.account_table.item(selected_items[0].row(), 0).data(
            Qt.UserRole
        )
        return int(account_id) if account_id is not None else None

    @staticmethod
    def _restore_selection(selector: QComboBox, value: str | None) -> None:
        if not value:
            return
        index = selector.findData(value)
        if index >= 0:
            selector.setCurrentIndex(index)
