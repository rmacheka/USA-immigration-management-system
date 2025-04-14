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

from api.visualization import (
    generate_status_distribution_chart,
    generate_nationality_bar_chart,
    generate_permit_expiry_timeline
)

# Ensure the reports directory exists
REPORTS_DIR = "data/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_pdf_report(df, report_type="summary", filename=None):
    """
    Generate a PDF report for immigration data
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        report_type (str): Type of report ('summary', 'detailed', 'expiry', 'status')
        filename (str, optional): Filename to save the report. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved report
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"immigration_report_{report_type}_{timestamp}.pdf"
    
    filepath = os.path.join(REPORTS_DIR, filename)
    
    # Create the PDF document
    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Create a story (list of flowables) to add to the document
    story = []
    
    # Add title
    if report_type == "summary":
        title = "USA Immigration Management System - Summary Report"
    elif report_type == "detailed":
        title = "USA Immigration Management System - Detailed Report"
    elif report_type == "expiry":
        title = "USA Immigration Management System - Permit Expiry Report"
    else:  # status
        title = "USA Immigration Management System - Status Report"
    
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 0.25*inch))
    
    # Add generation info
    generation_info = f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(generation_info, normal_style))
    story.append(Spacer(1, 0.25*inch))
    
    # Add summary statistics
    summary_title = "Summary Statistics"
    story.append(Paragraph(summary_title, subtitle_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Create summary table
    total_records = len(df)
    permanent_count = len(df[df['Status'] == 'Permanent']) if 'Status' in df.columns else 0
    temporary_count = len(df[df['Status'] == 'Temporary']) if 'Status' in df.columns else 0
    expired_count = len(df[df['Status'] == 'Expired']) if 'Status' in df.columns else 0
    illegal_count = len(df[df['Status'] == 'Illegal']) if 'Status' in df.columns else 0
    
    summary_data = [
        ["Category", "Count"],
        ["Total Records", total_records],
        ["Permanent Residents", permanent_count],
        ["Temporary Visa Holders", temporary_count],
        ["Expired Permits", expired_count],
        ["Illegal Immigrants", illegal_count]
    ]
    
    summary_table = Table(summary_data, colWidths=[3*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (1, 0), 12),
        ('BACKGROUND', (0, 1), (1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 1), (1, -1), 'CENTER'),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 0.5*inch))
    
    # Add visualizations
    story.append(Paragraph("Visualizations", subtitle_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Generate status distribution chart
    if 'Status' in df.columns and len(df) > 0:
        # Create the chart in memory
        status_counts = df['Status'].value_counts()
        plt.figure(figsize=(6, 4))
        plt.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', 
                shadow=True, startangle=90)
        plt.axis('equal')
        plt.title("Distribution of Immigration Statuses")
        
        # Save to BytesIO
        img_data = io.BytesIO()
        plt.savefig(img_data, format='png', bbox_inches='tight')
        img_data.seek(0)
        plt.close()
        
        # Add to report
        img = Image(img_data, width=6*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.25*inch))
    
    # If it's a detailed report, add the records table
    if report_type == "detailed" and len(df) > 0:
        story.append(Paragraph("Detailed Records", subtitle_style))
        story.append(Spacer(1, 0.1*inch))
        
        # Limit columns to display
        display_cols = ["Name", "Phone", "USCIS Number", "Status", "Nationality", "Profession"]
        display_cols = [col for col in display_cols if col in df.columns]
        
        # Create data for the table
        table_data = [display_cols]  # Header row
        
        # Add rows
        for _, row in df.iterrows():
            table_row = [str(row[col]) if pd.notna(row[col]) else "" for col in display_cols]
            table_data.append(table_row)
        
        # Create the table
        col_widths = [1.5*inch] * len(display_cols)
        records_table = Table(table_data, colWidths=col_widths)
        
        # Style the table
        records_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        story.append(records_table)
    
    # If it's an expiry report, add the expiry details
    if report_type == "expiry" and "Permit Expiry" in df.columns and len(df) > 0:
        story.append(Paragraph("Permit Expiry Details", subtitle_style))
        story.append(Spacer(1, 0.1*inch))
        
        # Convert expiry to datetime
        df_copy = df.copy()
        df_copy['Permit Expiry'] = pd.to_datetime(df_copy['Permit Expiry'], errors='coerce')
        
        # Sort by expiry date
        df_copy = df_copy.sort_values('Permit Expiry').dropna(subset=['Permit Expiry'])
        
        if len(df_copy) > 0:
            # Add expiry timeline
            # Create the chart in memory
            plt.figure(figsize=(7, 4))
            plt.scatter(df_copy['Permit Expiry'], np.ones(len(df_copy)), s=100, alpha=0.6)
            
            for i, row in df_copy.iterrows():
                plt.text(row['Permit Expiry'], 1.01, row['Name'], rotation=45, ha='left', fontsize=8)
            
            plt.yticks([])
            plt.title("Permit Expiry Timeline")
            plt.xlabel("Expiry Date")
            plt.grid(axis='x', linestyle='--', alpha=0.7)
            plt.tight_layout()
            
            # Save to BytesIO
            img_data = io.BytesIO()
            plt.savefig(img_data, format='png', bbox_inches='tight')
            img_data.seek(0)
            plt.close()
            
            # Add to report
            img = Image(img_data, width=7*inch, height=4*inch)
            story.append(img)
            story.append(Spacer(1, 0.25*inch))
            
            # Create expiry table
            display_cols = ["Name", "Phone", "USCIS Number", "Status", "Permit Expiry"]
            display_cols = [col for col in display_cols if col in df_copy.columns]
            
            # Create data for the table
            table_data = [display_cols]  # Header row
            
            # Format expiry date for display
            df_copy['Permit Expiry'] = df_copy['Permit Expiry'].dt.strftime('%Y-%m-%d')
            
            # Add rows
            for _, row in df_copy.iterrows():
                table_row = [str(row[col]) if pd.notna(row[col]) else "" for col in display_cols]
                table_data.append(table_row)
            
            # Create the table
            col_widths = [1.5*inch] * len(display_cols)
            expiry_table = Table(table_data, colWidths=col_widths)
            
            # Style the table
            expiry_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(expiry_table)
    
    # Build the PDF
    doc.build(story)
    
    return filepath

def generate_summary_report(df, filename=None):
    """
    Generate a summary report for immigration data
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the report. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved report
    """
    return generate_pdf_report(df, report_type="summary", filename=filename)

def generate_detailed_report(df, filename=None):
    """
    Generate a detailed report for immigration data
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the report. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved report
    """
    return generate_pdf_report(df, report_type="detailed", filename=filename)

def generate_expiry_report(df, filename=None):
    """
    Generate a permit expiry report for immigration data
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the report. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved report
    """
    return generate_pdf_report(df, report_type="expiry", filename=filename)

def generate_status_report(df, filename=None):
    """
    Generate a status report for immigration data
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the report. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved report
    """
    return generate_pdf_report(df, report_type="status", filename=filename) 