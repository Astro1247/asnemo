import logging

from nmap import PortScanner
from subprocess import Popen, PIPE
import re

from objects.device import Device


class Network(object):
    def __init__(self, ip):
        self.ip = ip

    def get_devices(self):
        """
        Get all devices on the network
        :return: list of devices
        """
        p_scanner = PortScanner()
        logging.info('Scanning {}...'.format(self.ip))
        p_scanner.scan(hosts=self.ip, arguments='-sn')
        device_list = [{'ip_address': host, 'name': p_scanner[host]['hostnames'][0]['name'], 'data': p_scanner[host]} for host in p_scanner.all_hosts()]
        for device in device_list:
            pid = Popen(["arp", "-n", device['ip_address']], stdout=PIPE)
            s = pid.communicate()[0]
            try:
                device['mac_address'] = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", str(s)).groups()[0]
            except AttributeError:
                device['mac_address'] = None
        devices = [Device(ip=device['ip_address'], name=device['name'], mac=device['mac_address'], data=device) for device in device_list]
        return devices
