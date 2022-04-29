# Program made by: Astro ( https://zonastro.com/ )
# Date: 2022-04-17
# Version: 1.0
# Description: This program is made for live lan network monitoring and report state changes to telegram.
import asyncio
import ipaddress
import logging
import os
import sys
import time
import json
from tinydb import TinyDB, Query
from asyncio import sleep

import nmap
import yaml
import requests
import netifaces
import psutil
import telegram
from queue import Queue
import threading
print_lock = threading.Lock()

q = Queue()


# Global variables
# Telegram bot token
TOKEN = ''
# Telegram bot chat id
CHAT_ID = ''
# Interface to monitor
INTERFACE = ''
monitored_ipaddress = []
# Get current ip
current_ip = None




# Functions
def get_ip_address(ifname):
    return netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']


def get_net_info(ifname):
    return netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]


def get_net_info_all(ifname):
    return netifaces.ifaddresses(ifname)


def check_ip_pingable(ip):
    response = os.system("ping -c 1 -i 1 " + ip + " > /dev/null 2>&1")
    if response == 0:
        return True
    else:
        return False


def ipscan(ip_address):
    if check_ip_pingable(ip_address['ip']):
        if 'up' not in ip_address.keys():
            ip_address['up'] = True
            # Send message to telegram
            #bot.send_message(chat_id=CHAT_ID, text='Found new IP address that is up: {}'.format(ip_address['ip']))
            logging.debug('Found new IP address that is up: ' + ip_address['ip'])
        else:
            if ip_address['up'] is False:
                ip_address['up'] = True
                # Send message to telegram
                telegram.Bot(token=TOKEN).send_message(chat_id=CHAT_ID, text='IP state changed to UP: {}'.format(ip_address['ip']))
                logging.info('IP state changed to UP: ' + ip_address['ip'])
    else:
        if 'up' in ip_address.keys():
            if ip_address['up'] is True:
                ip_address['up'] = False
                # Send message to telegram
                telegram.Bot(token=TOKEN).send_message(chat_id=CHAT_ID, text='IP state changed to DOWN: {}'.format(ip_address['ip']))
                logging.info('IP state changed to DOWN: ' + ip_address['ip'])
        else:
            ip_address['up'] = False


def threader(i):
    logging.info('Thread #{} started'.format(i))
    while True:
        worker = q.get()
        ipscan(worker)
        q.task_done()


async def network_monitoring_thread():
    global INTERFACE, CHAT_ID, TOKEN, current_ip, monitored_ipaddress
    while True:
        # Get current net info
        current_net_info = get_net_info(INTERFACE)
        # Get current net info all
        current_net_info_all = get_net_info_all(INTERFACE)
        ip_addresses = []
        for i in range(0, 255):
            ip_addresses.append({'ip': net_info['addr'].split('.')[0] + '.' + net_info['addr'].split('.')[1] + '.' +
                                       net_info['addr'].split('.')[2] + '.' + str(i)})
        # Check if ip is pingable
        for ip_address in ip_addresses:
            if ip_address['ip'] not in [x['ip'] for x in monitored_ipaddress]:
                logging.debug('New ip address appended for monitoring: ' + ip_address['ip'])
                monitored_ipaddress.append(ip_address)
        for i in range(0,len(monitored_ipaddress)):
            q.put(monitored_ipaddress[i])
        # Check if ip is changed
        if current_ip != current_net_info['addr']:
            # Send message to telegram
            telegram.Bot(token=TOKEN).send_message(chat_id=CHAT_ID, text='IP address changed from {} to {}'.format(current_ip,
                                                                                             current_net_info['addr']))
        await sleep(30)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.info('Started')
    # Check if config file exists and create with default values if not
    if not os.path.exists('config.yaml'):
        with open('config.yaml', 'w') as config_file:
            config_file.write("telegram:\n  token: ''\n  chat_id: ''\nnetwork:\n  interface: ''\ndatabase:\n  path: './data/db.json'")
        logger.info('Config file created with default values, please edit config.yaml')
        sys.exit(0)
    hosts = nmap.PortScanner.all_hosts
    for x in range(100):
        t = threading.Thread(target=threader, args=(x,))
        t.daemon = True
        t.start()
    # Get telegram bot token and interface to monitor
    try:
        with open('config.yaml', 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
            TOKEN = cfg['telegram']['token']
            CHAT_ID = cfg['telegram']['chat_id']
            INTERFACE = cfg['network']['interface']
    except Exception as e:
        logger.error('Error: ' + str(e))
        sys.exit(1)
    current_ip = get_ip_address(INTERFACE)
    # Get current ip address
    ip_address = get_ip_address(INTERFACE)
    # Get current net info
    net_info = get_net_info(INTERFACE)
    # Get current net info all
    net_info_all = get_net_info_all(INTERFACE)
    try:
        asyncio.run(network_monitoring_thread())
    except Exception as e:
        logger.error('Error: ' + str(e))
        sys.exit(1)

