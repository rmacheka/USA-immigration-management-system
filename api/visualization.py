import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

# Ensure the visualizations directory exists
VISUALIZATION_DIR = "data/visualizations"
os.makedirs(VISUALIZATION_DIR, exist_ok=True)

def generate_status_distribution_chart(df, filename=None):
    """
    Generate a pie chart showing the distribution of immigration statuses
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the chart. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved chart
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"status_distribution_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Count records by status
    status_counts = df['Status'].value_counts()
    
    # Create the pie chart
    plt.figure(figsize=(10, 8))
    plt.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', 
            shadow=True, startangle=90)
    plt.axis('equal')  # Equal aspect ratio ensures the pie chart is circular
    plt.title("Distribution of Immigration Statuses", fontsize=16)
    
    # Save the chart
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_nationality_bar_chart(df, top_n=10, filename=None):
    """
    Generate a bar chart showing the distribution of top nationalities
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        top_n (int): Number of top nationalities to show
        filename (str, optional): Filename to save the chart. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved chart
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nationality_distribution_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Count records by nationality and get top N
    nationality_counts = df['Nationality'].value_counts().head(top_n)
    
    # Create the bar chart
    plt.figure(figsize=(12, 8))
    sns.barplot(x=nationality_counts.index, y=nationality_counts.values)
    plt.title(f"Top {top_n} Nationalities", fontsize=16)
    plt.xlabel("Nationality", fontsize=14)
    plt.ylabel("Count", fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save the chart
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_permit_expiry_timeline(df, filename=None):
    """
    Generate a timeline chart showing permit expiry dates
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the chart. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved chart
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"permit_expiry_timeline_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Convert permit expiry to datetime
    df_copy = df.copy()
    df_copy['Permit Expiry'] = pd.to_datetime(df_copy['Permit Expiry'], errors='coerce')
    
    # Drop rows with invalid date
    df_copy = df_copy.dropna(subset=['Permit Expiry'])
    
    if len(df_copy) == 0:
        # Create empty chart if no valid dates
        plt.figure(figsize=(12, 6))
        plt.title("Permit Expiry Timeline (No valid dates)", fontsize=16)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        return filepath
    
    # Sort by expiry date
    df_copy = df_copy.sort_values('Permit Expiry')
    
    # Create the timeline
    plt.figure(figsize=(12, 6))
    plt.scatter(df_copy['Permit Expiry'], np.ones(len(df_copy)), s=100, alpha=0.6)
    
    for i, row in df_copy.iterrows():
        plt.text(row['Permit Expiry'], 1.01, row['Name'], rotation=45, ha='left')
    
    plt.yticks([])  # Hide y-axis
    plt.title("Permit Expiry Timeline", fontsize=16)
    plt.xlabel("Expiry Date", fontsize=14)
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    # Save the chart
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_heatmap_by_profession_and_status(df, filename=None):
    """
    Generate a heatmap showing the relationship between profession and status
    
    Args:
        df (DataFrame): DataFrame containing immigration records
        filename (str, optional): Filename to save the chart. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved chart
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"profession_status_heatmap_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Create a cross-tabulation of profession vs status
    cross_tab = pd.crosstab(df['Profession'], df['Status'])
    
    # Create the heatmap
    plt.figure(figsize=(12, 10))
    sns.heatmap(cross_tab, annot=True, cmap='YlGnBu', fmt='d', cbar_kws={'label': 'Count'})
    plt.title("Profession vs. Immigration Status", fontsize=16)
    plt.xlabel("Status", fontsize=14)
    plt.ylabel("Profession", fontsize=14)
    plt.tight_layout()
    
    # Save the chart
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_all_visualizations(df):
    """
    Generate all visualization charts and return paths
    
    Args:
        df (DataFrame): DataFrame containing immigration records
    
    Returns:
        dict: Dictionary with paths to all generated charts
    """
    visualizations = {}
    
    visualizations['status_chart'] = generate_status_distribution_chart(df)
    visualizations['nationality_chart'] = generate_nationality_bar_chart(df)
    visualizations['expiry_timeline'] = generate_permit_expiry_timeline(df)
    visualizations['profession_status_heatmap'] = generate_heatmap_by_profession_and_status(df)
    
    return visualizations 