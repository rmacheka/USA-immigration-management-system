"""
USA Immigration Management System - Notification System
Implemented by: Ade Solanke (API/Integration Specialist)
This module provides email notification capabilities including permit expiration alerts,
status change notifications, and weekly summary reports.
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import pandas as pd
from datetime import datetime, timedelta
import os
import logging

# ... existing code ... 