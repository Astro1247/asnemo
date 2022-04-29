from datetime import datetime

import requests
import json

from controller import config


class Device(object):
    def __init__(self, ip, mac, name, data):
        self.ip_address = ip
        self.mac_address = mac
        self.name = name
        self.data = data
        self.owner = self.get_mac_details()
        self.last_seen = datetime.now()

    def get_mac_details(self):
        if self.mac_address is None or self.mac_address == '00:00:00:00:00:00':
            return None
        url = "https://api.maclookup.app/v2/macs/{}?apiKey={}".format(self.mac_address, config.MAC_LOOKUP_API_KEY)

        # Use get method to fetch details
        response = requests.get(url)
        if response.status_code != 200:
            return None
        data = json.loads(response.content.decode())
        if data['success'] is True and data['found'] is True:
            return data['company']
        else:
            return None

    def to_string(self):
        return 'IP: {}\tMAC: {}\tName: {}\nOwner: {}'.format(self.ip_address, self.mac_address, self.name, self.owner)
