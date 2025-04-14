"""
USA Immigration Management System - Geocoding Utilities
Implemented by: RU (Backend Developer)
This module provides address verification using geolocation services.
"""

from geopy.geocoders import Nominatim


def verify_address(address: str) -> bool:
    """
    Verify if an address is valid by geocoding it.
    
    Args:
        address (str): The address to verify
        
    Returns:
        bool: True if the address is valid, False otherwise
    """
    geolocator = Nominatim(user_agent="usa_immigration_system")
    location = geolocator.geocode(address)
    return location is not None
