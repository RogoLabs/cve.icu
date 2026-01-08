"""
Logging configuration for CVE.ICU.

This module provides a centralized logging setup that replaces print()
statements throughout the codebase with proper logging capabilities.

Usage:
    from data.logging_config import setup_logging, get_logger

    # In entry point (build.py):
    setup_logging(level="INFO")

    # In any module:
    logger = get_logger(__name__)
    logger.info("Processing data...")
    logger.debug("Detailed info: %s", data)
    logger.warning("Missing optional data")
    logger.error("Failed to process: %s", error)
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Literal

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Default format includes emoji-style indicators for visual scanning
DEFAULT_FORMAT = "%(message)s"
DETAILED_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
MINIMAL_FORMAT = "%(levelname)s: %(message)s"

# Track if logging has been configured
_configured = False


def setup_logging(
    level: LogLevel = "INFO",
    log_file: Path | None = None,
    format_style: Literal["default", "detailed", "minimal"] = "default",
    force: bool = False,
) -> logging.Logger:
    """
    Configure logging for the CVE.ICU application.

    Args:
        level: Minimum log level to display (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to write logs to a file
        format_style: Log format - 'default' (messages only), 'detailed' (with timestamps),
                      or 'minimal' (level prefix only)
        force: If True, reconfigure even if already configured

    Returns:
        The root 'cve_icu' logger instance

    Example:
        # Basic usage
        setup_logging(level="INFO")

        # Verbose mode with file output
        setup_logging(level="DEBUG", log_file=Path("build.log"), format_style="detailed")

        # Quiet mode (warnings and errors only)
        setup_logging(level="WARNING")
    """
    global _configured

    if _configured and not force:
        return logging.getLogger("cve_icu")

    # Select format
    formats = {
        "default": DEFAULT_FORMAT,
        "detailed": DETAILED_FORMAT,
        "minimal": MINIMAL_FORMAT,
    }
    log_format = formats.get(format_style, DEFAULT_FORMAT)

    # Create handlers
    handlers: list[logging.Handler] = []

    # Console handler (always present)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format))
    handlers.append(console_handler)

    # File handler (optional)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(DETAILED_FORMAT))
        handlers.append(file_handler)

    # Configure root cve_icu logger
    root_logger = logging.getLogger("cve_icu")
    root_logger.setLevel(getattr(logging, level))

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    for handler in handlers:
        root_logger.addHandler(handler)

    # Prevent propagation to root logger (avoids duplicate messages)
    root_logger.propagate = False

    _configured = True
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    The logger will be a child of the 'cve_icu' root logger, inheriting
    its configuration.

    Args:
        name: Module name, typically __name__

    Returns:
        Logger instance configured as child of cve_icu

    Example:
        # In data/cve_years.py
        logger = get_logger(__name__)  # Creates 'cve_icu.data.cve_years'
        logger.info("Processing year data")
    """
    # Strip common prefixes to create cleaner logger names
    clean_name = name.replace("data.", "").replace("data.scripts.", "scripts.")
    return logging.getLogger(f"cve_icu.{clean_name}")


def silence_for_tests() -> None:
    """
    Silence all logging output for test runs.

    Call this in conftest.py to prevent log spam during tests.
    """
    logging.getLogger("cve_icu").setLevel(logging.CRITICAL + 1)


def restore_logging(level: LogLevel = "INFO") -> None:
    """
    Restore logging after silencing for tests.

    Args:
        level: Level to restore to
    """
    logging.getLogger("cve_icu").setLevel(getattr(logging, level))
