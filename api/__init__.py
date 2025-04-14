"""
USA Immigration Management System API Package
Developed by Ade Solanke
"""

__version__ = "1.0.0"
__author__ = "Ade Solanke"
__description__ = "API and Integration Components for USA Immigration Management System"

# Import main components for easy access
from api.app import app
from api.integration import default_system
from api.analytics import (
    predict_expirations,
    cluster_immigrants,
    analyze_status_transitions,
    analyze_nationality_trends
)
from api.visualization import generate_all_visualizations
from api.geospatial import generate_all_geospatial_visualizations
from api.report_generator import (
    generate_summary_report,
    generate_detailed_report,
    generate_expiry_report,
    generate_status_report
)
from api.data_io import DataExporter, DataImporter, validate_imported_data
from api.notifications import default_notifier 