"""Set test-only configuration before importing the application."""

import os

os.environ["SENTINAL_API_KEY"] = "ci_test_key_abcdefghijklmnop12345678"
