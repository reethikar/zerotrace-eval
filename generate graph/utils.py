"""File for utility functions while analyzing the log data"""

import requests
from geopy import distance
from geopy.geocoders import Nominatim
import json
import pandas as pd

class NoCityFound:
    
    def __init__(self) -> None:
        self.latitude = 0
        self.longitude = 0


class LocationUtils:
    
    # BBB location
    SERVER_LOCATION = (42.292778, -83.716111)

    def __init__(self) -> None:
        self.geolocator = Nominatim(user_agent="teacup_tapers_0k@icloud.com")
        
        # Initialize caches which are helpful because there are a lot of duplicates
        # and this helps us get around the throttling limits
        self.ip_responses = {}
        self.geolocation_responses = {}
        
        
    def apply_distance_from_server_to_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply the distance from server metric to an entire dataframe containing ip addresses"""
        
        df['distance_from_server'] = df['ipaddr'].apply(self.get_ip_dist_from_server)
        return df
    
    
    def apply_coordinates_of_user_loc(self, df: pd.DataFrame):
        """
        Apply the coordinates of the user location using the Nominatim API.
        Assumes the dataframe has the 'location_user' attribute.
        Creates 'user_coordinates' - the best guess for the coordinates of the user's input city.
        Creates 'manual_check' - if this value is True, it should probably be double checked manually to make sure it's correct
        """
        coordinate_tuple = df['location_user'].apply(self.get_location_data)

        df['user_coordinates'] = coordinate_tuple.apply(lambda x: x[0])
        df['manual_check'] = coordinate_tuple.apply(lambda x: x[1])
        
        return df
    
    
    def apply_distance_bet_user_server(self, df: pd.DataFrame):
        """
        Calculate the distance between the user and the VPN server.
        Assumes the dataframe has user_coordinates attribute already,
        and that all values that need to be manually checked have been checked.
        
        Creates 'dist_bet_user_vpn' - an estimate of the distance between the user and the VPN server (was pretty accurate in testing).
        
        Warning: Because of the rate limiting of the ip address API, this could take a while to run
        """
        
        df['dist_bet_user_vpn'] = df.apply(lambda row: self.get_dist_bet_coords(row.ipaddr, row.user_coordinates), axis=1)
        return df



    def get_dist_bet_coords(self, ipaddr: str, coords: tuple):
        """Return distance (in miles) between IP address location and a given set of coordinates (lat, lon)"""
        location = self.get_ip_location(ipaddr)
        lat = location['lat']
        lon = location['lon']
        
        return distance.distance(coords, (lat, lon)).miles
    

    def get_ip_location(self, ipaddr: str):
        """Return the IP location information given by this API: https://ip-api.com/"""
        
        if ipaddr in self.ip_responses:
            print("DUPLICATE IP ADDRESS:", ipaddr)
            return self.ip_responses[ipaddr]
        
        
        # There is a throttling rate limit on the API to 45 requests per minute ~ 1.33 seconds/request
        import time
        time.sleep(2)
        
        url = "http://ip-api.com/json/{}".format(ipaddr)
        
        response = requests.get(url)
        
        try:
            response_body = json.loads(response.text)
        except json.JSONDecodeError:
            print(response.content)
            print(ipaddr)
            raise json.JSONDecodeError
        
        self.ip_responses[ipaddr] = response_body
        return response_body


    def get_dist_from_server_coord(self, lat, lon):
        """Get the distance from the server in the BBB"""
        
        return distance.distance(self.SERVER_LOCATION, (lat, lon)).miles


    def get_ip_dist_from_server(self, ipaddr: str):
        """Query IP locator API and determine distance from BBB server"""
        
        
        location = self.get_ip_location(ipaddr)
        lat = location['lat']
        lon = location['lon']
        
        distance = self.get_dist_from_server_coord(lat, lon)
        
        return distance
    
    
    def get_geolocation(self, city: str):
        """
        Get geolocation data from city name
        See: https://geopy.readthedocs.io/en/stable/#nominatim 
        And: https://operations.osmfoundation.org/policies/nominatim/
        """
        city = city.lower()
        
        if city in self.geolocation_responses:
            print("DUPLICATE CITY:", city)
            return self.geolocation_responses[city]
        
        # There is a hard throttling rate limit of 1 request/second - 1.25 is conservative
        import time
        time.sleep(1.25)
        
        try:
            location = self.geolocator.geocode(city, timeout=5)
        except Exception as e:
            print(e)
            return NoCityFound()
        self.geolocation_responses[city] = location
        
        return location
    
    
    def get_lat_lon_from_city(self, city: str):
        """Get latitude and longitude from a city name"""
        
        location = self.get_geolocation(city)
        return (location.latitude, location.longitude)
    
    
    def get_location_data(self, user_loc: str):
        """
        Return tuple of coordinate data from geolocation service, along with True/False value of if it should be manually checked.
        We only query the gelocation with the city name. If the returned country/state information
        matches with the input country/state information then manual_check is set to False
        """
        
        # If no user location data available
        if not user_loc:
            return (0, 0), True
        
        loc_arr = user_loc.split(',')
        loc_arr = [format_location_strs(x) for x in loc_arr]
        
        city = loc_arr[0]
        
        # Could use full string in future, but figured this would allow us to double check using country/state info
        location_data = self.get_geolocation(city)
        
        # Couldn't determine from city (most likely city name is mispelled)
        if location_data is None:
            return (0, 0), True
        
        
        coordinates = (location_data.latitude, location_data.longitude)
        
        location_str = str(location_data)
        loc_strs_lower = [x.lower().lstrip() for x in location_str.split(',')[1:]]
        
        manual_check = True
        
        for loc in loc_arr[1:]:
            if loc in loc_strs_lower:
                manual_check = False
                break
        
        return coordinates, manual_check
     
        
def format_location_strs(location: str):
    """Convert all strings to lower case, convert state abbreviations to full names"""
    
    location = location.lower().lstrip()
    if location in states:
        location = states[location]
        
    elif location == 'usa':
        location = "United States"
        
    return location
    
    
    
        
states = {
    'ak': 'alaska',
    'al': 'alabama',
    'ar': 'arkansas',
    'az': 'arizona',
    'ca': 'california',
    'co': 'colorado',
    'ct': 'connecticut',
    'dc': 'district of columbia',
    'de': 'delaware',
    'fl': 'florida',
    'ga': 'georgia',
    'hi': 'hawaii',
    'ia': 'iowa',
    'id': 'idaho',
    'il': 'illinois',
    'in': 'indiana',
    'ks': 'kansas',
    'ky': 'kentucky',
    'la': 'louisiana',
    'ma': 'massachusetts',
    'md': 'maryland',
    'me': 'maine',
    'mi': 'michigan',
    'mn': 'minnesota',
    'mo': 'missouri',
    'ms': 'mississippi',
    'mt': 'montana',
    'nc': 'north carolina',
    'nd': 'north dakota',
    'ne': 'nebraska',
    'nh': 'new hampshire',
    'nj': 'new jersey',
    'nm': 'new mexico',
    'nv': 'nevada',
    'ny': 'new york',
    'oh': 'ohio',
    'ok': 'oklahoma',
    'or': 'oregon',
    'pa': 'pennsylvania',
    'ri': 'rhode island',
    'sc': 'south carolina',
    'sd': 'south dakota',
    'tn': 'tennessee',
    'tx': 'texas',
    'ut': 'utah',
    'va': 'virginia',
    'vt': 'vermont',
    'wa': 'washington',
    'wi': 'wisconsin',
    'wv': 'west virginia',
    'wy': 'wyoming'
}