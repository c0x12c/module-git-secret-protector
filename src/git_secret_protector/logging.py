import logging
import logging.handlers
import os

from settings import get_settings


def configure_logging():
    settings = get_settings()
    log_file = settings.log_file
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    log_max_size = settings.log_max_size
    log_backup_count = settings.log_backup_count

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=log_max_size, backupCount=log_backup_count
    )

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logging.basicConfig(level=log_level, handlers=[handler])


# Call this function at the start of your program
configure_logging()
