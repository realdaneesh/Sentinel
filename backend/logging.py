"""Centralized structured logging configuration for Sentinel backend."""

import logging
import sys


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure standard logging with clean format."""
    logger = logging.getLogger("sentinel")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers if re-initialized
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()

