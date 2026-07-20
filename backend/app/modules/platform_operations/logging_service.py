import logging
from app.modules.production.config import get_runtime_config
from app.modules.production.logging import ProductionJsonFormatter

JsonFormatter = ProductionJsonFormatter


def configure_logging():
    config = get_runtime_config()
    logger = logging.getLogger("threatscope.operations")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    if config.json_logging:
        handler.setFormatter(ProductionJsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, config.log_level, logging.INFO))
    logger.propagate = False
    return logger


logger = configure_logging()
