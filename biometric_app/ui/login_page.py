from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from biometric_app.services.db_service import DatabaseService


class LoginWindow(QWidget):
    authenticated = Signal(object)

    def __init__(self, db_service: DatabaseService) -> None:
        super().__init__()
        self.db_service = db_service
        self.setObjectName("loginRoot")
        self.setWindowTitle("BioAccess | Sign in")
        self.resize(1120, 720)
        self.setMinimumSize(940, 620)
        self._build_ui()
        self._apply_styles()

    def _build_ui(self) -> None:
        self.pages = QStackedWidget()
        self.pages.setObjectName("authPages")
        self.pages.setFixedWidth(500)
        self.pages.addWidget(self._login_form())
        self.pages.addWidget(self._account_form())

        auth_shell = QFrame()
        auth_shell.setObjectName("authShell")
        auth_shell.setFixedSize(900, 560)
        shell_layout = QHBoxLayout(auth_shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self._brand_panel())
        shell_layout.addWidget(self.pages)

        container = QWidget()
        container.setObjectName("stage")
        outer_layout = QVBoxLayout(container)
        outer_layout.setContentsMargins(20, 20, 20, 20)
        outer_layout.addStretch(1)
        outer_layout.addWidget(auth_shell, alignment=Qt.AlignCenter)
        outer_layout.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(container)

    def _brand_panel(self) -> QFrame:
        panel = QFrame(objectName="brandPanel")
        panel.setFixedWidth(400)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(42, 44, 42, 38)
        layout.setSpacing(12)

        product_label = QLabel("BIOMETRIC ACCESS CONTROL", objectName="productLabel")
        badge = QLabel("BA", objectName="brandBadge")
        self.brand_title = QLabel("BioAccess", objectName="brandTitle")
        tagline = QLabel(
            "A secure identity console for controlled examination access.",
            objectName="brandTagline",
        )
        tagline.setWordWrap(True)

        layout.addWidget(product_label)
        layout.addSpacing(8)
        layout.addWidget(badge, alignment=Qt.AlignLeft)
        layout.addWidget(self.brand_title)
        layout.addWidget(tagline)
        layout.addSpacing(18)

        divider = QFrame()
        divider.setObjectName("brandDivider")
        divider.setFrameShape(QFrame.HLine)
        layout.addWidget(divider)
        layout.addSpacing(10)

        feature_heading = QLabel("SECURITY BUILT IN", objectName="featureHeading")
        layout.addWidget(feature_heading)
        for feature in (
            "Face and fingerprint verification",
            "Role-based operator access",
            "Encrypted, auditable records",
        ):
            feature_label = QLabel(f"•  {feature}", objectName="featureItem")
            feature_label.setWordWrap(True)
            layout.addWidget(feature_label)

        layout.addStretch(1)
        footer = QLabel(
            "Secure  •  Traceable  •  Role controlled",
            objectName="brandFooter",
        )
        layout.addWidget(footer)
        return panel

    def _login_form(self) -> QWidget:
        page = QWidget()
        page.setObjectName("authPage")
        outer_layout = QVBoxLayout(page)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        card = QFrame(objectName="loginCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(48, 44, 48, 40)
        card_layout.setSpacing(12)

        eyebrow = QLabel("SECURE ACCESS", objectName="formEyebrow")
        heading = QLabel("Sign in", objectName="formTitle")
        subtitle = QLabel(
            "Enter your staff credentials to continue to the biometric console.",
            objectName="formSubtitle",
        )
        subtitle.setWordWrap(True)

        card_layout.addWidget(eyebrow)
        card_layout.addWidget(heading)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(16)

        form = QGridLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(9)

        self.login_username = QLineEdit(placeholderText="Enter your username")
        self.login_username.setClearButtonEnabled(True)
        self.login_password = QLineEdit(placeholderText="Enter your password")
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.returnPressed.connect(self._sign_in)
        self.password_toggle = QPushButton("Show", objectName="passwordToggle")
        self.password_toggle.setCheckable(True)
        self.password_toggle.setFixedWidth(62)
        self.password_toggle.toggled.connect(self._toggle_password_visibility)

        password_row = QHBoxLayout()
        password_row.setSpacing(8)
        password_row.addWidget(self.login_password, 1)
        password_row.addWidget(self.password_toggle)

        form.addWidget(QLabel("Username", objectName="fieldLabel"), 0, 0)
        form.addWidget(self.login_username, 1, 0)
        form.addWidget(QLabel("Password", objectName="fieldLabel"), 2, 0)
        form.addLayout(password_row, 3, 0)
        card_layout.addLayout(form)
        card_layout.addSpacing(10)

        sign_in = QPushButton("Sign in securely", objectName="primaryButton")
        sign_in.clicked.connect(self._sign_in)
        sign_in.setMinimumHeight(44)
        card_layout.addWidget(sign_in)

        if self.db_service.database.lower() == "mydatabase":
            account_note = QLabel(
                "Staff accounts and roles are managed by an administrator.",
                objectName="accountNote",
            )
            account_note.setWordWrap(True)
            account_note.setAlignment(Qt.AlignCenter)
            card_layout.addWidget(account_note)
        else:
            secondary = QPushButton(
                "Create a local account",
                objectName="secondaryButton",
            )
            secondary.clicked.connect(lambda: self.pages.setCurrentIndex(1))
            card_layout.addWidget(secondary)

        card_layout.addStretch(1)

        note = QLabel(
            f"SECURE DATABASE  ·  {self.db_service.database}  ·  TLS REQUIRED",
            objectName="connectionNote",
        )
        note.setWordWrap(True)
        note.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(note)

        outer_layout.addWidget(card)
        return page

    def _account_form(self) -> QWidget:
        page = QWidget()
        page.setObjectName("authPage")
        outer_layout = QVBoxLayout(page)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        card = QFrame(objectName="loginCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(48, 36, 48, 34)
        card_layout.setSpacing(10)

        eyebrow = QLabel("LOCAL TEST MODE", objectName="formEyebrow")
        heading = QLabel("Create account", objectName="formTitle")
        subtitle = QLabel(
            "Create a local account only when the app is not connected to the managed MySQL security database.",
            objectName="formSubtitle",
        )
        subtitle.setWordWrap(True)
        card_layout.addWidget(eyebrow)
        card_layout.addWidget(heading)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(8)

        form = QGridLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)

        self.display_name = QLineEdit(placeholderText="Full name")
        self.new_username = QLineEdit(placeholderText="Username")
        self.new_password = QLineEdit(placeholderText="Password")
        self.confirm_password = QLineEdit(placeholderText="Confirm password")
        self.new_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.setEchoMode(QLineEdit.Password)
        for field in (self.display_name, self.new_username, self.new_password, self.confirm_password):
            field.setClearButtonEnabled(True)

        form.addWidget(QLabel("Full name", objectName="fieldLabel"), 0, 0)
        form.addWidget(self.display_name, 1, 0)
        form.addWidget(QLabel("Username", objectName="fieldLabel"), 2, 0)
        form.addWidget(self.new_username, 3, 0)
        form.addWidget(QLabel("Password", objectName="fieldLabel"), 4, 0)
        form.addWidget(self.new_password, 5, 0)
        form.addWidget(QLabel("Confirm password", objectName="fieldLabel"), 6, 0)
        form.addWidget(self.confirm_password, 7, 0)
        card_layout.addLayout(form)

        actions = QHBoxLayout()
        save = QPushButton("Create and sign in", objectName="primaryButton")
        save.clicked.connect(self._create_account)
        back = QPushButton("Back to sign in", objectName="secondaryButton")
        back.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        actions.addWidget(save)
        actions.addStretch()
        actions.addWidget(back)
        card_layout.addLayout(actions)

        footer = QLabel("Account passwords are stored as salted PBKDF2 hashes.", objectName="supportNote")
        footer.setWordWrap(True)
        card_layout.addWidget(footer)

        outer_layout.addWidget(card)
        return page

    def _toggle_password_visibility(self, visible: bool) -> None:
        self.login_password.setEchoMode(
            QLineEdit.Normal if visible else QLineEdit.Password
        )
        self.password_toggle.setText("Hide" if visible else "Show")

    def _sign_in(self) -> None:
        account = self.db_service.authenticate(self.login_username.text(), self.login_password.text())
        if account is None:
            QMessageBox.warning(self, "Sign in failed", "The username or password is incorrect.")
            self.login_password.clear()
            return
        self.authenticated.emit(account)

    def _create_account(self) -> None:
        if self.new_password.text() != self.confirm_password.text():
            QMessageBox.warning(self, "Account not created", "The passwords do not match.")
            return
        try:
            account = self.db_service.create_account(
                self.display_name.text(), self.new_username.text(), self.new_password.text()
            )
        except ValueError as exc:
            if "already in use" in str(exc).lower():
                self.login_username.setText(self.new_username.text().strip().lower())
                self.login_password.clear()
                self.pages.setCurrentIndex(0)
                self.login_password.setFocus()
                QMessageBox.information(
                    self,
                    "Account already exists",
                    "This account was created earlier. Enter its password to sign in.",
                )
            else:
                QMessageBox.warning(self, "Account not created", str(exc))
            return
        self.authenticated.emit(account)

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            #loginRoot {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #edf5f3,
                    stop:0.55 #f7faf9,
                    stop:1 #e4efed
                );
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: 13px;
                color: #173333;
            }
            #stage, #authPages, #authPage, QLabel {
                background: transparent;
            }
            #authShell {
                background: #ffffff;
                border: 1px solid #cfdfdc;
                border-radius: 14px;
            }
            #authPages {
                background: #ffffff;
                border-top-right-radius: 14px;
                border-bottom-right-radius: 14px;
            }
            #brandPanel {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #12383c,
                    stop:0.58 #174c50,
                    stop:1 #21645d
                );
                border-top-left-radius: 14px;
                border-bottom-left-radius: 14px;
            }
            #productLabel, #featureHeading {
                color: #9ed6cb;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 1px;
            }
            #brandBadge {
                color: #12383c;
                background: #d8f1eb;
                border: 1px solid #eafffa;
                border-radius: 10px;
                padding: 11px 14px;
                font-size: 18px;
                font-weight: 900;
            }
            #brandTitle {
                color: #ffffff;
                font-size: 34px;
                font-weight: 750;
            }
            #brandTagline {
                color: #d2e7e2;
                font-size: 15px;
                line-height: 1.35;
            }
            #brandDivider {
                color: rgba(255,255,255,0.18);
                background: rgba(255,255,255,0.18);
                border: none;
                max-height: 1px;
            }
            #featureItem {
                color: #edf8f5;
                font-size: 13px;
                padding: 3px 0;
            }
            #brandFooter {
                color: #a9cbc4;
                font-size: 11px;
            }
            #loginCard {
                background: #ffffff;
                border: none;
                border-top-right-radius: 14px;
                border-bottom-right-radius: 14px;
            }
            #formEyebrow {
                color: #2f8f7b;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 1px;
            }
            #formTitle {
                color: #133536;
                font-size: 30px;
                font-weight: 750;
            }
            #formSubtitle {
                color: #5d7371;
                font-size: 13px;
            }
            #supportNote {
                color: #70817f;
                font-size: 11px;
            }
            #fieldLabel {
                color: #294846;
                font-size: 12px;
                font-weight: 650;
            }
            QLineEdit {
                background: #f8fbfa;
                border: 1px solid #cbdad7;
                border-radius: 8px;
                padding: 8px 12px;
                min-height: 28px;
                color: #173333;
                selection-background-color: #2f8f7b;
            }
            QLineEdit:focus {
                border: 2px solid #2f8f7b;
                background: #ffffff;
            }
            QPushButton#primaryButton {
                background: #2f8f7b;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 9px 18px;
                font-weight: 750;
                min-height: 34px;
            }
            QPushButton#primaryButton:hover {
                background: #267765;
            }
            QPushButton#primaryButton:pressed {
                background: #205f52;
            }
            QPushButton#secondaryButton {
                background: #eff6f4;
                color: #246b5d;
                border: 1px solid #c9ded9;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 650;
                min-height: 30px;
            }
            QPushButton#secondaryButton:hover {
                background: #e3f0ed;
            }
            QPushButton#passwordToggle {
                background: #eff6f4;
                color: #246b5d;
                border: 1px solid #cbdad7;
                border-radius: 8px;
                min-height: 44px;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton#passwordToggle:hover,
            QPushButton#passwordToggle:checked {
                background: #dcece8;
                border-color: #8ebeb4;
            }
            #accountNote {
                color: #607572;
                font-size: 11px;
                padding: 4px;
            }
            #connectionNote {
                color: #226b59;
                background: #e9f6f1;
                border: 1px solid #c7e6dd;
                border-radius: 7px;
                padding: 10px 12px;
                font-size: 10px;
                font-weight: 750;
                letter-spacing: 0.5px;
            }
        """)
