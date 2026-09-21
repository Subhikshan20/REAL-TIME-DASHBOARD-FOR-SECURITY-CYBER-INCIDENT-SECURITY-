"""
logging_config.py
=================
Single place to configure structured application logging.

Call ``configure_logging()`` once at process start (done by app.py and the CLI
entry points). The log level is controlled by the ``SOC_LOG_LEVEL`` environment
variable (default INFO). A consistent, timestamped format is used across every
module so the dissertation can include reproducible run logs.
"""

from __future__ import annotations

import logging
import os
import sys

_CONFIGURED = False

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-18s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: str | None = None) -> None:
    """Idempotently configure root logging for the whole application."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = (level or os.getenv("SOC_LOG_LEVEL") or "INFO").upper()
    log_level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))

    root = logging.getLogger()
    root.setLevel(log_level)
    # Avoid duplicate handlers when Streamlit re-imports modules across reruns.
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        root.addHandler(handler)

    # Quiet down noisy third-party libraries.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Convenience accessor that guarantees logging is configured first."""
    configure_logging()
    return logging.getLogger(name)
