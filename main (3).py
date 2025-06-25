#!/usr/bin/env python3
import os
import time
import requests
import telebot
import uuid
from user_agent import generate_user_agent
from dotenv import load_dotenv
from keep_alive import keep_alive

load_dotenv()
TOKEN = os.getenv("TOKEN")
CHANNEL_USERNAME = "@ogb4nners"
CHANNEL_LINK = "https://t.me/ogb4nners"
DEVELOPERS_LINK = "https://t.me/ogb4nners"

bot = telebot.TeleBot(TOKEN)

def check_membership(user_id):
    try:
        member = bot.get_chat_member(CHANNEL_USERNAME, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except:
        return False

def rest1(user_id, message):
    headers = {
        'authority': 'www.instagram.com',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9,en-GB;q=0.8',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.instagram.com',
        'referer': 'https://www.instagram.com/accounts/password/reset/',
        'user-agent': generate_user_agent(),
        'x-asbd-id': '129477',
        'x-csrftoken': 'MoKKhcy0MtQHyxInGtndUr',
        'x-ig-app-id': '936619743392459',
    }

    data = {'email_or_username': user_id}
    try:
        res = requests.post('https://www.instagram.com/api/v1/web/accounts/account_recovery_send_ajax/',
                            headers=headers, data=data).json()
        if 'contact_point' in res:
            we = res['contact_point']
            ms = f"""[ADV RESET TOOL]

Password Reset Link Sent Successfully!
Email/Username: [{we}]

Developers: {DEVELOPERS_LINK}
"""
            bot.reply_to(message, ms)
        else:
            gh = f"""[ADV RESET TOOL]

Account Not Found!
The email or username you entered doesn't exist.

Developers: {DEVELOPERS_LINK}
"""
            bot.reply_to(message, gh)
    except:
        mn = f"""[ADV RESET TOOL]

Connection Error!
Please check your internet connection and try again.

Developers: {DEVELOPERS_LINK}
"""
        bot.reply_to(message, mn)

def rest(user_id, message):
    url = "https://i.instagram.com/api/v1/accounts/send_password_reset/"
    payload = {
        'ig_sig_key_version': "4",
        'user_email': user_id,
        'device_id': str(uuid.uuid4()),
    }
    headers = {
        'User-Agent': "Instagram 113.0.0.39.122 Android",
        'X-IG-Connection-Type': "WIFI",
    }

    try:
        res = requests.post(url, data=payload, headers=headers).json()
        if 'obfuscated_email' in res:
            se = res['obfuscated_email']
            ms = f"""[ADV RESET TOOL]

Password Reset Link Sent Successfully!
Associated Email: [{se}]

Developers: {DEVELOPERS_LINK}
"""
            bot.reply_to(message, ms)
        elif 'rate_limit_error' in res:
            md = f"""[ADV RESET TOOL]

Rate Limit Exceeded!
Please wait 20 minutes and try again.

Developers: {DEVELOPERS_LINK}
"""
            bot.reply_to(message, md)
        else:
            rest1(user_id, message)
    except:
        rest1(user_id, message)

@bot.message_handler(commands=['start', 'help'])
def send_instructions(message):
    if not check_membership(message.from_user.id):
        bot.reply_to(message, f"""[ADV RESET TOOL]

Access Denied!
Please join our channel first to use this bot: {CHANNEL_LINK}

Developers: {DEVELOPERS_LINK}
""")
        return
    help_msg = f"""[ADV RESET TOOL]

Advanced Instagram Password Reset Tool

Available Commands:
/reset @username - Reset Instagram password

Developers: {DEVELOPERS_LINK}
"""
    bot.reply_to(message, help_msg)

@bot.message_handler(commands=['reset'])
def handle_reset(message):
    if not check_membership(message.from_user.id):
        bot.reply_to(message, f"""[ADV RESET TOOL]

Access Denied!
Please join our channel first to use this bot: {CHANNEL_LINK}

Developers: {DEVELOPERS_LINK}
""")
        return

    if '@' in message.text:
        user_id = message.text.split('@')[1].strip()
        if user_id:
            bot.reply_to(message, "Processing your request...")
            rest(user_id, message)
        else:
            bot.reply_to(message, "Invalid Command! Use /reset @username")
    else:
        bot.reply_to(message, "Invalid Format! Use /reset @username")

@bot.message_handler(func=lambda message: True)
def ignore_message(message):
    if not check_membership(message.from_user.id):
        bot.reply_to(message, f"""[ADV RESET TOOL]

Access Denied!
Please join our channel first to use this bot: {CHANNEL_LINK}

Developers: {DEVELOPERS_LINK}
""")
        return

    bot.reply_to(message, "Unknown Command! Type /help to see available commands.")

if __name__ == "__main__":
    keep_alive()
    print("ADV RESET BOT IS RUNNING")
    bot.remove_webhook()
    time.sleep(1)
    bot.polling(none_stop=True)
