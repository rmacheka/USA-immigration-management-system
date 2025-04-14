import pandas as pd
import json
import csv
import os
import xml.etree.ElementTree as ET
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("data_io")

# Ensure the data directory exists
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

class DataExporter:
    """Class to handle exporting data from the immigration system"""
    
    @staticmethod
    def export_to_csv(df, filename=None):
        """
        Export data to CSV format
        
        Args:
            df (DataFrame): DataFrame containing immigration records
            filename (str, optional): Filename to save the export.
                                     If None, a default name will be generated.
        
        Returns:
            str: Path to the exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"immigration_data_export_{timestamp}.csv"
        
        filepath = os.path.join(DATA_DIR, filename)
        
        try:
            df.to_csv(filepath, index=False)
            logger.info(f"Data exported to CSV: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to export to CSV: {e}")
            return None
    
    @staticmethod
    def export_to_excel(df, filename=None):
        """
        Export data to Excel format
        
        Args:
            df (DataFrame): DataFrame containing immigration records
            filename (str, optional): Filename to save the export.
                                     If None, a default name will be generated.
        
        Returns:
            str: Path to the exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"immigration_data_export_{timestamp}.xlsx"
        
        filepath = os.path.join(DATA_DIR, filename)
        
        try:
            df.to_excel(filepath, index=False, engine='openpyxl')
            logger.info(f"Data exported to Excel: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to export to Excel: {e}")
            return None
    
    @staticmethod
    def export_to_json(df, filename=None):
        """
        Export data to JSON format
        
        Args:
            df (DataFrame): DataFrame containing immigration records
            filename (str, optional): Filename to save the export.
                                     If None, a default name will be generated.
        
        Returns:
            str: Path to the exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"immigration_data_export_{timestamp}.json"
        
        filepath = os.path.join(DATA_DIR, filename)
        
        try:
            df.to_json(filepath, orient='records', date_format='iso')
            logger.info(f"Data exported to JSON: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to export to JSON: {e}")
            return None
    
    @staticmethod
    def export_to_xml(df, filename=None):
        """
        Export data to XML format
        
        Args:
            df (DataFrame): DataFrame containing immigration records
            filename (str, optional): Filename to save the export.
                                     If None, a default name will be generated.
        
        Returns:
            str: Path to the exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"immigration_data_export_{timestamp}.xml"
        
        filepath = os.path.join(DATA_DIR, filename)
        
        try:
            # Convert DataFrame to dict
            data_dict = df.to_dict(orient='records')
            
            # Create XML structure
            root = ET.Element("ImmigrationData")
            
            for record in data_dict:
                immigrant = ET.SubElement(root, "Immigrant")
                
                for key, value in record.items():
                    if pd.notna(value):  # Skip NaN values
                        field = ET.SubElement(immigrant, key.replace(" ", "_"))
                        field.text = str(value)
            
            # Create ElementTree and save to file
            tree = ET.ElementTree(root)
            tree.write(filepath)
            
            logger.info(f"Data exported to XML: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to export to XML: {e}")
            return None

class DataImporter:
    """Class to handle importing data into the immigration system"""
    
    @staticmethod
    def import_from_csv(filepath):
        """
        Import data from CSV file
        
        Args:
            filepath (str): Path to the CSV file
        
        Returns:
            DataFrame: DataFrame with imported data, or None if import fails
        """
        try:
            df = pd.read_csv(filepath)
            logger.info(f"Data imported from CSV: {filepath}")
            return df
        except Exception as e:
            logger.error(f"Failed to import from CSV: {e}")
            return None
    
    @staticmethod
    def import_from_excel(filepath):
        """
        Import data from Excel file
        
        Args:
            filepath (str): Path to the Excel file
        
        Returns:
            DataFrame: DataFrame with imported data, or None if import fails
        """
        try:
            df = pd.read_excel(filepath, engine='openpyxl')
            logger.info(f"Data imported from Excel: {filepath}")
            return df
        except Exception as e:
            logger.error(f"Failed to import from Excel: {e}")
            return None
    
    @staticmethod
    def import_from_json(filepath):
        """
        Import data from JSON file
        
        Args:
            filepath (str): Path to the JSON file
        
        Returns:
            DataFrame: DataFrame with imported data, or None if import fails
        """
        try:
            df = pd.read_json(filepath, orient='records')
            logger.info(f"Data imported from JSON: {filepath}")
            return df
        except Exception as e:
            logger.error(f"Failed to import from JSON: {e}")
            return None
    
    @staticmethod
    def import_from_xml(filepath):
        """
        Import data from XML file
        
        Args:
            filepath (str): Path to the XML file
        
        Returns:
            DataFrame: DataFrame with imported data, or None if import fails
        """
        try:
            # Parse XML file
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            records = []
            
            for immigrant in root.findall('Immigrant'):
                record = {}
                
                for field in immigrant:
                    # Convert XML tag names back to original column names
                    column_name = field.tag.replace("_", " ")
                    record[column_name] = field.text
                
                records.append(record)
            
            df = pd.DataFrame(records)
            logger.info(f"Data imported from XML: {filepath}")
            return df
        except Exception as e:
            logger.error(f"Failed to import from XML: {e}")
            return None
    
    @staticmethod
    def detect_and_import(filepath):
        """
        Detect file type and import data accordingly
        
        Args:
            filepath (str): Path to the data file
        
        Returns:
            DataFrame: DataFrame with imported data, or None if import fails
        """
        if not os.path.exists(filepath):
            logger.error(f"File does not exist: {filepath}")
            return None
        
        file_extension = os.path.splitext(filepath)[1].lower()
        
        if file_extension == '.csv':
            return DataImporter.import_from_csv(filepath)
        elif file_extension in ['.xlsx', '.xls']:
            return DataImporter.import_from_excel(filepath)
        elif file_extension == '.json':
            return DataImporter.import_from_json(filepath)
        elif file_extension == '.xml':
            return DataImporter.import_from_xml(filepath)
        else:
            logger.error(f"Unsupported file format: {file_extension}")
            return None

def validate_imported_data(df):
    """
    Validate imported data
    
    Args:
        df (DataFrame): DataFrame with imported data
    
    Returns:
        tuple: (valid DataFrame, list of validation errors)
    """
    if df is None or len(df) == 0:
        return df, ["Empty data set"]
    
    errors = []
    
    # Check required columns
    required_columns = ["Name", "USCIS Number", "Status"]
    for col in required_columns:
        if col not in df.columns:
            errors.append(f"Missing required column: {col}")
    
    if errors:
        return df, errors
    
    # Check for missing values in required fields
    for col in required_columns:
        missing_count = df[col].isna().sum()
        if missing_count > 0:
            errors.append(f"{missing_count} missing values in required column: {col}")
    
    # Validate status values
    valid_statuses = ['Permanent', 'Temporary', 'Expired', 'Illegal']
    invalid_statuses = df[~df['Status'].isin(valid_statuses)]['Status'].unique()
    if len(invalid_statuses) > 0:
        errors.append(f"Invalid status values found: {', '.join(map(str, invalid_statuses))}")
    
    # Validate date format for Permit Expiry
    if 'Permit Expiry' in df.columns:
        df['Permit Expiry'] = pd.to_datetime(df['Permit Expiry'], errors='coerce')
        invalid_dates = df['Permit Expiry'].isna().sum()
        if invalid_dates > 0:
            errors.append(f"{invalid_dates} invalid date values in Permit Expiry column")
    
    return df, errors 