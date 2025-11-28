"""Configuration settings for FIM system"""
import os
import socket

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

WATCH_DIRECTORY = os.path.join(BASE_DIR, "watched")

os.makedirs(WATCH_DIRECTORY, exist_ok=True)

ENDPOINT_NAME = os.environ.get("ENDPOINT_NAME", "replit_agent")
AGENT_ID = os.environ.get("AGENT_ID", socket.gethostname())
HOSTNAME = socket.gethostname()
USERNAME = os.environ.get("USER", "replit")

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

CLASSIFICATION_LEVELS = ["Unclassified", "Confidential", "Secret", "Top Secret"]
