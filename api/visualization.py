"""
USA Immigration Management System - Visualization Module
Implemented by: Ade Solanke (API/Integration Specialist)
This module provides data visualization capabilities including status distribution charts,
nationality bar charts, permit expiry timelines, and profession-status heatmaps.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

# ... existing code ... 