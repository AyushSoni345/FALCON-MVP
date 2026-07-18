import logging
from app.core.config import settings

def setup_logging():
    logging.basicConfig(
        level=settings.log_level.upper(),
        format=(
            '{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
            if settings.structured_json_logging
            else '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
    )
