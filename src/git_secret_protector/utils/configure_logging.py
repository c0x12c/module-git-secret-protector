import logging
import logging.handlers
import os
import sys

from git_secret_protector.core.settings import get_settings


def configure_logging(verbose=False):
    settings = get_settings()
    log_file = settings.log_file
    log_level = settings.log_level
    log_max_size = settings.log_max_size
    log_backup_count = settings.log_backup_count

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=log_max_size, backupCount=log_backup_count
    )
    handler.setFormatter(formatter)

    handlers = [handler]
    if verbose:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(formatter)
        console.setLevel(logging.DEBUG)
        handlers.append(console)

    logging.basicConfig(level=log_level, handlers=handlers)
