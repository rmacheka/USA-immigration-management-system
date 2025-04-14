import pandas as pd
import os
from datetime import datetime
import logging

# Import all modules
from api.app import app
from api.visualization import generate_all_visualizations
from api.geospatial import generate_all_geospatial_visualizations
from api.report_generator import (
    generate_summary_report,
    generate_detailed_report,
    generate_expiry_report,
    generate_status_report
)
from api.notifications import default_notifier
from api.data_io import DataExporter, DataImporter, validate_imported_data
from api.analytics import (
    predict_expirations,
    cluster_immigrants,
    analyze_status_transitions,
    analyze_nationality_trends
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("integration")

class ImmigrationSystem:
    """Main integration class for the immigration system"""
    
    def __init__(self, data_path="data/records.csv"):
        """
        Initialize the immigration system
        
        Args:
            data_path (str): Path to the immigration records file
        """
        self.data_path = data_path
        self.visualization_paths = {}
        self.geospatial_paths = {}
        self.report_paths = {}
        self.data = self.load_data()
    
    def load_data(self):
        """Load immigration data from file"""
        try:
            return pd.read_csv(self.data_path)
        except (FileNotFoundError, pd.errors.EmptyDataError):
            # Create empty DataFrame with required columns
            return pd.DataFrame(columns=[
                "Name", "Phone", "USCIS Number", "Profession", 
                "Address", "Nationality", "Permit Expiry", "Status"
            ])
    
    def save_data(self):
        """Save immigration data to file"""
        # Ensure the data directory exists
        os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
        self.data.to_csv(self.data_path, index=False)
    
    def add_immigrant(self, immigrant_data):
        """
        Add a new immigrant record
        
        Args:
            immigrant_data (dict): Dictionary with immigrant information
        
        Returns:
            int: Index of the new record
        """
        # Convert to DataFrame
        new_record = pd.DataFrame([immigrant_data])
        
        # Concatenate with existing data
        self.data = pd.concat([self.data, new_record], ignore_index=True)
        
        # Save to file
        self.save_data()
        
        return len(self.data) - 1
    
    def update_immigrant(self, index, immigrant_data):
        """
        Update an existing immigrant record
        
        Args:
            index (int): Index of the record to update
            immigrant_data (dict): Dictionary with updated information
        
        Returns:
            bool: Whether the update was successful
        """
        if index < 0 or index >= len(self.data):
            return False
        
        # Update the record
        for key, value in immigrant_data.items():
            if key in self.data.columns:
                self.data.at[index, key] = value
        
        # Save to file
        self.save_data()
        
        return True
    
    def delete_immigrant(self, index):
        """
        Delete an immigrant record
        
        Args:
            index (int): Index of the record to delete
        
        Returns:
            bool: Whether the deletion was successful
        """
        if index < 0 or index >= len(self.data):
            return False
        
        # Delete the record
        self.data = self.data.drop(index).reset_index(drop=True)
        
        # Save to file
        self.save_data()
        
        return True
    
    def search_immigrants(self, query=None):
        """
        Search for immigrants based on query parameters
        
        Args:
            query (dict): Dictionary with search parameters
        
        Returns:
            DataFrame: Filtered DataFrame with matching records
        """
        if query is None or not query:
            return self.data
        
        # Start with all data
        result = self.data
        
        # Apply filters
        for key, value in query.items():
            if key in result.columns:
                result = result[result[key].str.contains(value, case=False, na=False)]
        
        return result
    
    def generate_visualizations(self):
        """Generate all visualizations and return paths"""
        self.visualization_paths = generate_all_visualizations(self.data)
        return self.visualization_paths
    
    def generate_geospatial_visualizations(self):
        """Generate all geospatial visualizations and return paths"""
        self.geospatial_paths = generate_all_geospatial_visualizations(self.data)
        return self.geospatial_paths
    
    def generate_reports(self):
        """Generate all reports and return paths"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.report_paths = {
            'summary': generate_summary_report(
                self.data, 
                f"immigration_summary_{timestamp}.pdf"
            ),
            'detailed': generate_detailed_report(
                self.data, 
                f"immigration_detailed_{timestamp}.pdf"
            ),
            'expiry': generate_expiry_report(
                self.data, 
                f"immigration_expiry_{timestamp}.pdf"
            ),
            'status': generate_status_report(
                self.data, 
                f"immigration_status_{timestamp}.pdf"
            )
        }
        
        return self.report_paths
    
    def export_data(self, format='csv'):
        """
        Export data to the specified format
        
        Args:
            format (str): Export format ('csv', 'excel', 'json', 'xml')
        
        Returns:
            str: Path to the exported file
        """
        exporter = DataExporter()
        
        if format == 'csv':
            return exporter.export_to_csv(self.data)
        elif format == 'excel':
            return exporter.export_to_excel(self.data)
        elif format == 'json':
            return exporter.export_to_json(self.data)
        elif format == 'xml':
            return exporter.export_to_xml(self.data)
        else:
            logger.error(f"Unsupported export format: {format}")
            return None
    
    def import_data(self, filepath, replace=False):
        """
        Import data from file
        
        Args:
            filepath (str): Path to the file to import
            replace (bool): Whether to replace existing data
        
        Returns:
            tuple: (success status, error message)
        """
        # Import data
        importer = DataImporter()
        imported_df = importer.detect_and_import(filepath)
        
        # Validate data
        imported_df, errors = validate_imported_data(imported_df)
        
        if errors:
            return False, errors
        
        # Update data
        if replace:
            self.data = imported_df
        else:
            self.data = pd.concat([self.data, imported_df], ignore_index=True)
        
        # Save data
        self.save_data()
        
        return True, []
    
    def analyze_data(self):
        """
        Perform analytics on the data
        
        Returns:
            dict: Dictionary with analytics results
        """
        analytics = {}
        
        # Predict permit expirations
        analytics['expiration_forecast'] = predict_expirations(self.data)
        
        # Identify immigrant clusters
        clustered_data, cluster_info = cluster_immigrants(self.data)
        analytics['clusters'] = cluster_info.to_dict(orient='records') if not cluster_info.empty else []
        
        # Analyze nationality trends
        nationality_trends = analyze_nationality_trends(self.data)
        analytics['nationality_trends'] = nationality_trends.to_dict(orient='records') if not nationality_trends.empty else []
        
        return analytics
    
    def send_expiry_notifications(self, recipient, days_threshold=30):
        """
        Send notifications about permits expiring soon
        
        Args:
            recipient (str): Email recipient
            days_threshold (int): Days threshold for expiry warning
        
        Returns:
            bool: Whether the notification was sent successfully
        """
        return default_notifier.send_permit_expiry_notification(
            recipient, self.data, days_threshold
        )
    
    def send_weekly_summary(self, recipient):
        """
        Send weekly summary notification
        
        Args:
            recipient (str): Email recipient
        
        Returns:
            bool: Whether the notification was sent successfully
        """
        # Generate a summary report first
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = generate_summary_report(
            self.data, 
            f"weekly_summary_{timestamp}.pdf"
        )
        
        return default_notifier.send_weekly_summary(
            recipient, self.data, report_path
        )
    
    def notify_status_change(self, recipient, immigrant_id, old_status, new_status):
        """
        Send notification about a status change
        
        Args:
            recipient (str): Email recipient
            immigrant_id (int): ID of the immigrant
            old_status (str): Previous status
            new_status (str): New status
        
        Returns:
            bool: Whether the notification was sent successfully
        """
        if immigrant_id < 0 or immigrant_id >= len(self.data):
            return False
        
        immigrant_data = self.data.iloc[immigrant_id].to_dict()
        
        return default_notifier.send_status_change_notification(
            recipient, immigrant_data, old_status, new_status
        )
    
    def get_statistics(self):
        """
        Get statistical information about immigrants
        
        Returns:
            dict: Dictionary with statistics
        """
        if len(self.data) == 0:
            return {
                "total": 0,
                "by_status": {},
                "by_nationality": {}
            }
        
        # Get counts by status
        status_counts = self.data['Status'].value_counts().to_dict() if 'Status' in self.data.columns else {}
        
        # Get counts by nationality
        nationality_counts = self.data['Nationality'].value_counts().to_dict() if 'Nationality' in self.data.columns else {}
        
        # Count expiring permits
        if 'Permit Expiry' in self.data.columns:
            self.data['Permit Expiry'] = pd.to_datetime(self.data['Permit Expiry'], errors='coerce')
            today = datetime.now().date()
            self.data['Days Until Expiry'] = (self.data['Permit Expiry'].dt.date - today).dt.days
            
            expiring_30_days = len(self.data[(self.data['Days Until Expiry'] >= 0) & (self.data['Days Until Expiry'] <= 30)])
            expiring_7_days = len(self.data[(self.data['Days Until Expiry'] >= 0) & (self.data['Days Until Expiry'] <= 7)])
        else:
            expiring_30_days = 0
            expiring_7_days = 0
        
        return {
            "total": len(self.data),
            "by_status": status_counts,
            "by_nationality": nationality_counts,
            "expiring_soon": {
                "within_7_days": expiring_7_days,
                "within_30_days": expiring_30_days
            }
        }

# Create a default instance
default_system = ImmigrationSystem() 