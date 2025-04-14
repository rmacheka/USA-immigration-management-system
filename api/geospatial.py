import geopandas as gpd
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from geopy.geocoders import Nominatim
from shapely.geometry import Point
import os
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

# Ensure the visualizations directory exists
VISUALIZATION_DIR = "data/visualizations"
os.makedirs(VISUALIZATION_DIR, exist_ok=True)

def geocode_addresses(df):
    """
    Geocode addresses in the DataFrame to get lat/long coordinates
    
    Args:
        df (DataFrame): DataFrame containing immigration records with Address column
    
    Returns:
        DataFrame: Original DataFrame with Latitude and Longitude columns added
    """
    # Create a copy to avoid modifying the original
    df_geo = df.copy()
    
    # Initialize lists to store coordinates
    latitudes = []
    longitudes = []
    
    # Initialize geocoder
    geolocator = Nominatim(user_agent="usa_immigration_system")
    
    # Geocode each address
    for address in df_geo['Address']:
        try:
            location = geolocator.geocode(address)
            if location:
                latitudes.append(location.latitude)
                longitudes.append(location.longitude)
            else:
                latitudes.append(None)
                longitudes.append(None)
        except Exception:
            # Handle errors by adding None values
            latitudes.append(None)
            longitudes.append(None)
    
    # Add coordinates to DataFrame
    df_geo['Latitude'] = latitudes
    df_geo['Longitude'] = longitudes
    
    return df_geo

def create_geospatial_dataframe(df):
    """
    Convert DataFrame with lat/long to GeoDataFrame for spatial analysis
    
    Args:
        df (DataFrame): DataFrame with Latitude and Longitude columns
    
    Returns:
        GeoDataFrame: GeoDataFrame with geometry column
    """
    # Filter out rows with missing coordinates
    df_with_coords = df.dropna(subset=['Latitude', 'Longitude'])
    
    # Create geometry points
    geometry = [Point(xy) for xy in zip(df_with_coords['Longitude'], df_with_coords['Latitude'])]
    
    # Create GeoDataFrame
    gdf = gpd.GeoDataFrame(df_with_coords, geometry=geometry)
    
    # Set coordinate reference system
    gdf.crs = "EPSG:4326"  # WGS 84 - standard coordinate system
    
    return gdf

def generate_us_distribution_map(df, filename=None):
    """
    Generate a map showing the distribution of immigrants across the US
    
    Args:
        df (DataFrame): DataFrame containing immigration records with Address column
        filename (str, optional): Filename to save the map. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved map
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"immigrant_distribution_map_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Get coordinates for addresses
    df_geo = geocode_addresses(df)
    
    # Create GeoDataFrame
    gdf = create_geospatial_dataframe(df_geo)
    
    if len(gdf) == 0:
        # Create empty map if no valid coordinates
        plt.figure(figsize=(12, 8))
        plt.title("Immigrant Distribution Map (No valid coordinates)", fontsize=16)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        return filepath
    
    # Load US states shapefile
    usa = gpd.read_file(gpd.datasets.get_path('naturalearth_lowres'))
    usa = usa[usa.name == "United States of America"]
    
    # Create the map
    fig, ax = plt.subplots(figsize=(15, 10))
    usa.plot(ax=ax, color='lightgray', edgecolor='white')
    
    # Plot points with different colors based on status
    status_colors = {
        'Permanent': 'green',
        'Temporary': 'blue',
        'Expired': 'orange',
        'Illegal': 'red'
    }
    
    for status, color in status_colors.items():
        subset = gdf[gdf['Status'] == status]
        if len(subset) > 0:
            subset.plot(ax=ax, color=color, markersize=50, label=status, alpha=0.7)
    
    # Customize the map
    plt.title("Immigrant Distribution Across the US", fontsize=16)
    plt.legend(title="Status")
    plt.axis('off')
    
    # Save the map
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_heatmap(df, filename=None):
    """
    Generate a heatmap showing the density of immigrants across the US
    
    Args:
        df (DataFrame): DataFrame containing immigration records with Address column
        filename (str, optional): Filename to save the heatmap. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved heatmap
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"immigrant_density_heatmap_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Get coordinates for addresses
    df_geo = geocode_addresses(df)
    
    # Create GeoDataFrame
    gdf = create_geospatial_dataframe(df_geo)
    
    if len(gdf) == 0:
        # Create empty map if no valid coordinates
        plt.figure(figsize=(12, 8))
        plt.title("Immigrant Density Heatmap (No valid coordinates)", fontsize=16)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        return filepath
    
    # Load US states shapefile
    usa = gpd.read_file(gpd.datasets.get_path('naturalearth_lowres'))
    usa = usa[usa.name == "United States of America"]
    
    # Create the map with heatmap
    fig, ax = plt.subplots(figsize=(15, 10))
    
    # Plot base map
    usa.plot(ax=ax, color='lightgray', edgecolor='white')
    
    # Create a 2D histogram (heatmap)
    plt.hist2d(gdf['Longitude'], gdf['Latitude'], bins=50, cmap='hot', alpha=0.7)
    plt.colorbar(label='Number of Immigrants')
    
    # Customize the map
    plt.title("Immigrant Density Heatmap", fontsize=16)
    plt.axis('off')
    
    # Save the map
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_status_distribution_by_state(df, filename=None):
    """
    Generate a map showing the distribution of immigrant statuses by state
    
    Args:
        df (DataFrame): DataFrame containing immigration records with Address column
        filename (str, optional): Filename to save the map. 
                                 If None, a default name will be generated.
    
    Returns:
        str: Path to the saved map
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"status_by_state_map_{timestamp}.png"
    
    filepath = os.path.join(VISUALIZATION_DIR, filename)
    
    # Get coordinates for addresses
    df_geo = geocode_addresses(df)
    
    # Add state information using reverse geocoding
    geolocator = Nominatim(user_agent="usa_immigration_system")
    
    def get_state(row):
        try:
            if pd.notna(row['Latitude']) and pd.notna(row['Longitude']):
                location = geolocator.reverse((row['Latitude'], row['Longitude']))
                address = location.raw['address']
                return address.get('state', None)
            return None
        except Exception:
            return None
    
    df_geo['State'] = df_geo.apply(get_state, axis=1)
    
    # Count by state and status
    state_status_counts = df_geo.groupby(['State', 'Status']).size().unstack(fill_value=0)
    
    if len(state_status_counts) == 0:
        # Create empty map if no valid data
        plt.figure(figsize=(12, 8))
        plt.title("Status Distribution by State (No valid data)", fontsize=16)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        return filepath
    
    # Load US states shapefile
    states = gpd.read_file('https://raw.githubusercontent.com/OpenDataDE/State-zip-code-GeoJSON/master/us-states.json')
    
    # Merge with our data
    # Note: State names might need normalization to match between datasets
    merged = states.merge(state_status_counts, left_on='NAME', right_index=True, how='left')
    
    # Fill NAs with 0
    for status in ['Permanent', 'Temporary', 'Expired', 'Illegal']:
        if status in merged.columns:
            merged[status] = merged[status].fillna(0)
    
    # Create a map for each status
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    axes = axes.flatten()
    
    statuses = ['Permanent', 'Temporary', 'Expired', 'Illegal']
    for i, status in enumerate(statuses):
        ax = axes[i]
        if status in merged.columns:
            merged.plot(column=status, ax=ax, legend=True, 
                       cmap='viridis', edgecolor='white',
                       legend_kwds={'label': f"Number of {status} Immigrants"})
        ax.set_title(f"{status} Immigrants by State")
        ax.axis('off')
    
    plt.tight_layout()
    
    # Save the map
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filepath

def generate_all_geospatial_visualizations(df):
    """
    Generate all geospatial visualizations and return paths
    
    Args:
        df (DataFrame): DataFrame containing immigration records
    
    Returns:
        dict: Dictionary with paths to all generated maps
    """
    visualizations = {}
    
    visualizations['distribution_map'] = generate_us_distribution_map(df)
    visualizations['density_heatmap'] = generate_heatmap(df)
    visualizations['status_by_state'] = generate_status_distribution_by_state(df)
    
    return visualizations 