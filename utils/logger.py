import logging
import threading
from datetime import datetime
from pathlib import Path

_logger_instance = None
_log_file_path = None
_lock = threading.Lock()


def setup_logger() -> logging.Logger:
    """Create a new logger with a unique log file per run."""
    global _logger_instance, _log_file_path

    with _lock:
        if _logger_instance is not None:
            return _logger_instance

        logs_dir = Path(__file__).resolve().parent.parent / "logs"
        logs_dir.mkdir(exist_ok=True)

        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = logs_dir / f"run_{run_id}.log"
        _log_file_path = log_file

        logger = logging.getLogger("vms")
        logger.setLevel(logging.DEBUG)

        if logger.handlers:
            return logger

        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | thread=%(threadName)-20s | %(name)-30s | %(funcName)-40s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

        logger.info("Logger initialized | log_file=%s", log_file)
        _logger_instance = logger
        return logger


def get_logger(name: str = None) -> logging.Logger:
    """Return the singleton logger, optionally as a child logger for a module."""
    root = setup_logger()
    if name:
        return root.getChild(name)
    return root


def get_log_path() -> Path:
    """Return the current run's log file path."""
    setup_logger()
    return _log_file_path
