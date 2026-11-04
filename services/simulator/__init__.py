"""Offline synthetic authentication events; no ingestion or detection side effects."""

from .generator import DEFAULT_REFERENCE_TIME, SCENARIOS, generate_events

__all__ = ["DEFAULT_REFERENCE_TIME", "SCENARIOS", "generate_events"]
