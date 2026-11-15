"""Explicit synthetic test-only settings loaded before backend imports."""

import os

os.environ["ENVIRONMENT"] = "testing"
os.environ["DEBUG"] = "true"
os.environ["SECRET_KEY"] = "test-only-sentinel-jwt-signing-key-for-isolated-automated-tests-2026"
os.environ["SIMULATOR_PERSISTENCE_ENABLED"] = "true"
