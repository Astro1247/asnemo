# Program made by: Astro ( https://zonastro.com/ )
# Date: 2022-04-17
# Version: 1.0
# Description: This program is made for live lan network monitoring and report state changes to telegram.
import asyncio
import logging
import os
import sys

from asyncio import sleep

import nmap
import netifaces
import threading

from netaddr import IPAddress

import controller.config as config

from controller.database import check_devices, check_tables
from objects.network import Network

print_lock = threading.Lock()


# Get ip address of interface
def get_ip_address(ifname):
    try:
        return netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
    except Exception as e:
        # ip address not found
        return None


# Get network information
def get_net_info(ifname):
    return netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]


# Independent monitoring thread
async def network_monitoring_thread():
    while True:
        # Get available interfaces and their ip addresses with netmask
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            ip_address = get_ip_address(interface)
            if interface in ['lo', 'docker0'] or 'br-' in interface:
                continue
            if ip_address is None:
                continue
            net_info = get_net_info(interface)
            netmask = net_info['netmask']
            # Convert netmask to CIDR
            cidr = IPAddress(netmask).netmask_bits()
            # Create network object
            network = Network(ip_address + '/' + str(cidr))
            # Get all devices on network
            devices = network.get_devices()
            # Check if devices are saved to database
            if devices is None:
                continue
            check_devices(devices)
        await sleep(30)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.info('Started')
    # Check if config file exists and create with default values if not
    if not os.path.exists('config.yaml'):
        with open('config.yaml', 'w') as config_file:
            config_file.write(
                """telegram:\n  token: ''\n  chat_id: ''\ndatabase:\n  host: 'localhost'\n  port: '5432'\n  user: ''\n  password: ''\n  database: ''maclookup:\n  api_key: ''""")
        logger.info('Config file created with default values, please edit config.yaml')
        sys.exit(0)
    # Load config file
    config.load_config()
    hosts = nmap.PortScanner.all_hosts

    check_tables()

    # Start new network monitoring thread
    asyncio.run(network_monitoring_thread())
