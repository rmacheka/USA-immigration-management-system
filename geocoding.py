from geopy.geocoders import Nominatim


def verify_address(address: str) -> bool:
    geolocator = Nominatim(user_agent="usa_immigration_system")
    location = geolocator.geocode(address)
    return location is not None
