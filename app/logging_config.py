# logging_config.py - Logging configuration
import logging
import sys
from logging.handlers import RotatingFileHandler
import os
from app.config import settings

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)


def setup_logging():
    """Setup application logging"""
    # Create logger
    logger = logging.getLogger("app")
    logger.setLevel(logging.INFO if settings.ENVIRONMENT == "production" else logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler for rotating log files
    file_handler = RotatingFileHandler(
        "logs/app.log", maxBytes=10485760, backupCount=5  # 10MB
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


logger = setup_logging()


