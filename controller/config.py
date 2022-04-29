import logging
import sys
import yaml

data = None
# Telegram bot token
TOKEN = ''
# Telegram bot chat id
CHAT_ID = ''
# Interface to monitor
INTERFACE = ''
# Mac address lookup api key for maclookup.app
MAC_LOOKUP_API_KEY = ''


logger = logging.getLogger(__name__)


# Read config file
def load_config():
    global data, TOKEN, CHAT_ID, INTERFACE, MAC_LOOKUP_API_KEY
    try:
        with open('config.yaml', 'r') as ymlfile:
            data = yaml.load(ymlfile, Loader=yaml.FullLoader)
            TOKEN = data['telegram']['token']
            CHAT_ID = data['telegram']['chat_id']
            INTERFACE = data['network']['interface']
            MAC_LOOKUP_API_KEY = data['maclookup']['api_key']
    except Exception as e:
        logger.error('Failed to read config file: ' + str(e))
        sys.exit(1)