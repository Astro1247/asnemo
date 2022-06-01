import telegram

from controller import config


def send_message(message):
    """
    Send a message to the Telegram bot.
    :param message: Message to send.
    """
    telegram.Bot(token=config.TOKEN).send_message(chat_id=config.CHAT_ID, text=message)
