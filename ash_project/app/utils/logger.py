import logging
from logging.handlers import RotatingFileHandler
import os
from flask import current_app

def init_logger(app):
    log_dir = os.path.join(app.root_path, '../logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, 'immigration_system.log')
    
    handler = RotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024 * 10,  # 10 MB
        backupCount=10
    )
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    
    app.logger.addHandler(handler)
    app.logger.setLevel(app.config['LOG_LEVEL'])
    
    # Disable Flask default handler
    app.logger.handlers = [handler]

log = logging.getLogger(__name__)