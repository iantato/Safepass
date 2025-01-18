from pathlib import Path

# Base settings.
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = BASE_DIR / 'data'

# Database settings.
DB_NAME = 'vault.db'
DB_PATH = DATA_DIR / DB_NAME

# PBKDF2 settings.
ITERATIONS = dict({
    'SHA256': 600_000,
    'SHA512': 210_000
})
KEY_LENGTH = 32
VERSION = 1