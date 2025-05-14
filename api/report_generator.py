"""
USA Immigration Management System - PDF Report Generation Module
Implemented by: Ade Solanke (API/Integration Specialist)
This module provides PDF report generation capabilities including summary reports,
detailed reports, permit expiry reports, and status reports.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import pandas as pd
import os
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import io

# ... existing code ... 