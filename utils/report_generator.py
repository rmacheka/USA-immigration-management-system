"""
USA Immigration Management System - Basic Report Generator
Implemented by: RU (Backend Developer)
This module provides basic functionality for generating text-based reports.
Note: For advanced PDF report generation, see the API module implemented by Ade Solanke.
"""

def generate_report(df):
    """Generate a basic text report from the data."""
    if 'Status' not in df.columns:
        print("Error: DataFrame does not contain 'Status' column.")
        return
    print("\n--- Immigration Report ---")
    print(f"Total Records: {len(df)}")
    print(f"Permanent Residents: {len(df[df['Status'] == 'Permanent'])}")
    print(f"Temporary Visa Holders: {len(df[df['Status'] == 'Temporary'])}")
    print(f"Expired Permits: {len(df[df['Status'] == 'Expired'])}")
    print(f"Illegal Immigrants: {len(df[df['Status'] == 'Illegal'])}")
    print("\n--- Detailed Records ---")
