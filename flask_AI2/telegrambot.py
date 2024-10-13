# API_KEY = "7074979224:AAH7EOTya1AhcKKqNXzv-Sl4nA026WA3gHo"
# ID = "1271362249"
API_KEY = "8054704256:AAFv7Rp865_iO5s3pKU7TWSLWK5Z2dA_8lU"
ID = "-4569161691"

from telegram import Bot
import asyncio
def send_photo(bot, chat_id, photo_path, caption=None):
    with open(photo_path, 'rb') as photo_file:
        asyncio.run(bot.send_photo(chat_id=chat_id, photo=photo_file, caption=caption))

def send_notification(image, message):
    bot = Bot(token=API_KEY)
    chat_id = ID
    photo_path = image
    caption = message
    send_photo(bot, chat_id, photo_path, caption)

# send_notification("./detection/images/http___www_mustandmore_in_.png", "Detection")