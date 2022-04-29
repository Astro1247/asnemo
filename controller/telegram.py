import telegram

from controller import config


def send_message(message):
    telegram.Bot(token=config.TOKEN).send_message(chat_id=config.CHAT_ID, text=message)
