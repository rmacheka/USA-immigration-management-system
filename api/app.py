"""
USA Immigration Management System - RESTful API
Implemented by: Ade Solanke (API/Integration Specialist)
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os
import json
from datetime import datetime
import sys

# Add the root directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_validation import validate_phone_number, validate_status, validate_uscis_number
from utils.geocoding import verify_address

# ... existing code ... 