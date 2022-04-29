# Program made by: Astro ( https://zonastro.com/ )
# Date: 2022-04-17
# Version: 1.0
# Description: This program is made for live lan network monitoring and report state changes to telegram.
import asyncio
import logging
import os
import sys
from contextlib import closing

from asyncio import sleep

import nmap
import yaml
import netifaces
import telegram
from queue import Queue
import threading

from netaddr import IPAddress

import controller.config as config

from controller.database import get_db_connection, check_devices, check_tables
from objects.network import Network

print_lock = threading.Lock()

q = Queue()

# Global variables
monitored_ipaddress = []
# Get current ip
current_ip = None


# Functions
def get_ip_address(ifname):
    try:
        return netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
    except Exception as e:
        # ip address not found
        return None


def get_net_info(ifname):
    return netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]


def get_net_info_all(ifname):
    return netifaces.ifaddresses(ifname)


def check_ip_pingable(ip):
    response = os.system("ping -c 5 -i 1 " + ip + " > /dev/null 2>&1")
    if response == 0:
        return True
    else:
        return False


def ipscan(ip_address):
    from objects.network import Network
    network = Network(ip_address['ip']+'/32')
    try:
        devices = network.get_devices()
    except Exception as e:
        logging.error('Error while scanning ip address: ' + ip_address['ip'])
        logging.error(e)
        return
    return devices
    if check_ip_pingable(ip_address['ip']):
        if 'up' not in ip_address.keys():
            ip_address['up'] = True
            # Send message to telegram
            # bot.send_message(chat_id=CHAT_ID, text='Found new IP address that is up: {}'.format(ip_address['ip']))
            logging.debug('Found new IP address that is up: ' + ip_address['ip'])
        else:
            if ip_address['up'] is False:
                ip_address['up'] = True
                # Send message to telegram
                telegram.Bot(token=config.TOKEN).send_message(chat_id=config.CHAT_ID,
                                                       text='IP state changed to UP: {}'.format(ip_address['ip']))
                logging.info('IP state changed to UP: ' + ip_address['ip'])
    else:
        if 'up' in ip_address.keys():
            if ip_address['up'] is True:
                ip_address['up'] = False
                # Send message to telegram
                telegram.Bot(token=config.TOKEN).send_message(chat_id=config.CHAT_ID,
                                                       text='IP state changed to DOWN: {}'.format(ip_address['ip']))
                logging.info('IP state changed to DOWN: ' + ip_address['ip'])
        else:
            ip_address['up'] = False


def threader(i):
    logging.info('Thread #{} started'.format(i))
    while True:
        worker = q.get(timeout=60)
        ipscan(worker)
        q.task_done()


async def remade_network_monitoring_thread():
    while True:
        # Get available interfaces and their ip addresses with netmask
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            ip_address = get_ip_address(interface)
            if interface == 'lo':
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






async def network_monitoring_thread():
    global current_ip, monitored_ipaddress
    while True:
        # Get current net info
        current_net_info = get_net_info(config.INTERFACE)
        # Get current net info all
        current_net_info_all = get_net_info_all(config.INTERFACE)
        ip_addresses = []
        for i in range(0, 255):
            ip_addresses.append({'ip': net_info['addr'].split('.')[0] + '.' + net_info['addr'].split('.')[1] + '.' +
                                       net_info['addr'].split('.')[2] + '.' + str(i)})
        # Check if ip is pingable
        for ip_address in ip_addresses:
            if ip_address['ip'] not in [x['ip'] for x in monitored_ipaddress]:
                logging.debug('New ip address appended for monitoring: ' + ip_address['ip'])
                monitored_ipaddress.append(ip_address)
        for i in range(0, len(monitored_ipaddress)):
            q.put(monitored_ipaddress[i])
        # Check if ip is changed
        if current_ip != current_net_info['addr']:
            # Send message to telegram
            telegram.Bot(token=config.TOKEN).send_message(chat_id=config.CHAT_ID,
                                                          text='IP address changed from {} to {}'.format(current_ip,
                                                                                                         current_net_info[
                                                                                                             'addr']))
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
                """telegram:\n  token: ''\n  chat_id: ''\nnetwork:\n  interface: ''\ndatabase:\n  host: 'localhost'\n  port: '5432'\n  user: ''\n  password: ''\n  database: ''maclookup:\n  api_key: ''""")
        logger.info('Config file created with default values, please edit config.yaml')
        sys.exit(0)
    # Load config file
    config.load_config()
    hosts = nmap.PortScanner.all_hosts

    check_tables()

    # Start new network monitoring thread
    asyncio.run(remade_network_monitoring_thread())

    sys.exit(0)
    # Old scanner below

    # Start threads that will check worker for new ips to scan
    logging.debug('Running threads for ip scanning')
    for x in range(256//2):
        t = threading.Thread(target=threader, args=(x,))
        t.daemon = True
        t.start()
    current_ip = get_ip_address(config.INTERFACE)
    # Get current ip address
    ip_address = get_ip_address(config.INTERFACE)
    # Get current net info
    net_info = get_net_info(config.INTERFACE)
    # Get current net info all
    net_info_all = get_net_info_all(config.INTERFACE)

    # Check database connection
    logging.debug('Checking database connection')
    try:
        with closing(get_db_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute('SELECT 1')
                conn.commit()
                logging.debug('Database connection established')
    except Exception as e:
        logger.error('Failed to connect to database: ' + str(e))
        sys.exit(1)

    try:
        asyncio.run(network_monitoring_thread())
    except KeyboardInterrupt:
        logging.info('Stopped')
        sys.exit(0)
    except Exception as e:
        logger.error('Error: ' + str(e))
        sys.exit(1)
