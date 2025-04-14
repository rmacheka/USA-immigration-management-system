#!/usr/bin/env python3
"""
USA Immigration Management System - API Main Entry Point
Developed by Ade Solanke
"""

import os
import sys
import argparse
import logging
from api.app import app
from api.integration import default_system

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("main")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='USA Immigration Management System API')
    
    parser.add_argument(
        '--host', 
        default='0.0.0.0',
        help='Host to run the server on (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=5000,
        help='Port to run the server on (default: 5000)'
    )
    
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='Run in debug mode'
    )
    
    parser.add_argument(
        '--data-path',
        default='data/records.csv',
        help='Path to the data file (default: data/records.csv)'
    )
    
    return parser.parse_args()

def setup_environment(args):
    """Set up the environment for the application"""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(args.data_path), exist_ok=True)
    
    # Initialize the system with the specified data path
    if args.data_path != 'data/records.csv':
        global default_system
        default_system = default_system.__class__(data_path=args.data_path)
    
    # Print system information
    logger.info(f"Starting USA Immigration Management System API")
    logger.info(f"Data file: {args.data_path}")
    logger.info(f"Records in database: {len(default_system.data)}")

def main():
    """Main entry point for the application"""
    args = parse_args()
    setup_environment(args)
    
    # Run the Flask application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug
    )

if __name__ == "__main__":
    main() 