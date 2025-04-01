import pandas as pd
from datetime import datetime

def generate_report(report_type: str, parameters: dict, search_by: str = None, search_value: str = None) -> dict:
    """Generate a report based on type and parameters"""
    try:
        # Load appropriate data file
        if report_type == "applications":
            df = pd.read_csv("data/applications.csv")
            date_column = "Submission Date"
        elif report_type == "permits":
            df = pd.read_csv("data/permits.csv")
            date_column = "Issue Date"
        else:
            return {
                "error": "Invalid report type",
                "valid_types": ["applications", "permits"]
            }

        # Convert date column to datetime with specific format
        df[date_column] = pd.to_datetime(df[date_column], format='%Y-%m-%d')
        
        # Convert input dates to datetime
        start_date = datetime.strptime(parameters["start_date"], "%Y-%m-%d")
        end_date = datetime.strptime(parameters["end_date"], "%Y-%m-%d")
        
        # Filter by date range
        mask = (df[date_column] >= start_date) & (df[date_column] <= end_date)
        filtered_df = df[mask]

        # Apply search filter if provided
        if search_by and search_value:
            if search_by == "name":
                filtered_df = filtered_df[filtered_df['Name'].str.contains(search_value, case=False)]
            elif search_by == "phone":
                filtered_df = filtered_df[filtered_df['Phone'] == search_value]
        
        # Generate statistics
        stats = {
            f"total_{report_type}": len(filtered_df),
            "nationalities": filtered_df['Nationality'].value_counts().to_dict(),
            "professions": filtered_df['Profession'].value_counts().to_dict(),
            "status_distribution": filtered_df['Status'].value_counts().to_dict()
        }

        # Add type-specific statistics
        if report_type == "applications":
            stats["application_types"] = filtered_df['Application Type'].value_counts().to_dict()
        elif report_type == "permits":
            stats["permit_types"] = filtered_df['Permit Type'].value_counts().to_dict()
            # Convert Expiry Date to datetime for comparison
            filtered_df['Expiry Date'] = pd.to_datetime(filtered_df['Expiry Date'], format='%Y-%m-%d')
            stats["expiring_soon"] = len(filtered_df[
                (filtered_df['Expiry Date'] <= datetime.now() + pd.Timedelta(days=30)) &
                (filtered_df['Status'] == 'Active')
            ])

        # Format dates in records for display
        records = filtered_df.to_dict('records')
        for record in records:
            if 'Issue Date' in record:
                record['Issue Date'] = record['Issue Date'].strftime('%Y-%m-%d')
            if 'Expiry Date' in record:
                record['Expiry Date'] = record['Expiry Date'].strftime('%Y-%m-%d')
            if 'Submission Date' in record:
                record['Submission Date'] = record['Submission Date'].strftime('%Y-%m-%d')

        return {
            "report_type": report_type,
            "date_range": f"{parameters['start_date']} to {parameters['end_date']}",
            "search_criteria": {"by": search_by, "value": search_value} if search_by and search_value else None,
            "statistics": stats,
            "records": records
        }
            
    except Exception as e:
        return {
            "error": str(e),
            "message": "Error generating report"
        } 