import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "biometric_app.db"

# MySQL Database Configuration
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "bioaccess_app")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "mydatabase")
ALLOW_SQLITE_FALLBACK = os.getenv("ALLOW_SQLITE_FALLBACK", "0") == "1"
MYSQL_EXECUTABLE = os.getenv(
    "MYSQL_EXECUTABLE",
    r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe",
)
MYSQL_SSL_MODE = os.getenv("MYSQL_SSL_MODE", "REQUIRED")
MYSQL_SSL_CA = Path(os.getenv("MYSQL_SSL_CA", str(DATA_DIR / "mysql-ca.pem")))

# The active fingerprint integration uses the packaged 32-bit Futronic helper,
# FTRAPI.dll, and ftrScanAPI.dll. This legacy setting remains only for backwards
# compatibility with older environment files and is not used by the current service.
FUTRONIC_DLL_PATH = os.getenv("FUTRONIC_DLL_PATH", "")

# Retained for compatibility with older configuration files. OpenCV SFace
# determines the current face-vector size from the recognition model.
FACE_EMBEDDING_SIZE = 128

AES_KEY_PATH = Path(os.getenv("BIOMETRIC_AES_KEY_PATH", str(DATA_DIR / "biometric_aes256.dpapi")))
