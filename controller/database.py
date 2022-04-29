import logging
from datetime import datetime, timezone

import controller.config as config
import controller.telegram as telegram_bot

import psycopg2

logger = logging.getLogger(__name__)


def get_db_connection():
    try:
        conn = psycopg2.connect(host=config.data['database']['host'],
                                port=config.data['database']['port'],
                                database=config.data['database']['database'],
                                user=config.data['database']['user'],
                                password=config.data['database']['password'])
        return conn
    except Exception as e:
        logging.error('Unable to connect to the database. Error: {}'.format(e))


# Check if device already exists in database by mac address
def check_device_exists(mac_address):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE mac_address = %s", (mac_address,))
    result = cur.fetchone()
    conn.close()
    return result


# Add device to database
def add_device(mac_address, name, ip_address, last_seen, owner):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO devices (mac_address, name, ip_address, last_seen, owner) VALUES (%s, %s, %s, %s, %s)",
                (mac_address, name, ip_address, last_seen, owner))
    conn.commit()
    conn.close()


# Check devices if ther are already in database, save if not and update last seen
def check_devices(devices):
    for device in devices:
        if device.mac_address is not None:
            if check_device_exists(device.mac_address) is None:
                logging.info('New device {} found, saving to database'.format(device.mac_address))
                telegram_bot.send_message('Found new device in network: ' + device.to_string())
                add_device(device.mac_address, device.name, device.ip_address, datetime.now(timezone.utc), device.owner)
            else:
                logging.debug('Known device {} detected'.format(device.mac_address))
                update_device(device.mac_address, device.name, device.ip_address, datetime.now(timezone.utc))


# Update device in database
def update_device(mac_address, name, ip_address, last_seen):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET name = %s, ip_address = %s, last_seen = %s WHERE mac_address = %s",
                (name, ip_address, last_seen, mac_address))
    conn.commit()
    conn.close()


# Set owner for device in database
def set_owner(mac_address, owner):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET owner = %s WHERE mac_address = %s", (owner, mac_address))
    conn.commit()
    conn.close()


# Check tables exist and create tables if they don't
def check_tables():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM information_schema.tables WHERE table_name = 'devices'")
    result = cur.fetchone()
    if result is None:
        cur.execute("CREATE TABLE devices (mac_address varchar(17), name varchar(50), ip_address varchar(15), "
                    "last_seen timestamp, owner varchar(255))")
        conn.commit()
    conn.close()