# File Integrity Monitoring (FIM) System

## Overview
A real-time File Integrity Monitoring system that tracks file changes (creation, modification, deletion) and provides security alerts. Built with Flask and PostgreSQL.

## Features
- Real-time file system monitoring using watchdog
- SHA-256 hash calculation for file integrity verification
- Security classification system (Unclassified, Confidential, Secret, Top Secret)
- Webhook alerts for n8n.io and Telegram integration
- PostgreSQL database for event storage and baseline management
- Web dashboard for monitoring and configuration

## Project Structure
```
/
├── main.py           # Main entry point
├── app.py            # Flask application setup
├── models.py         # SQLAlchemy database models
├── routes.py         # Flask routes
├── config.py         # Configuration settings
├── hashing.py        # File hashing utilities
├── alerts.py         # Webhook/Telegram alert system
├── watcher.py        # File system watcher
├── templates/        # Jinja2 templates
│   ├── base.html
│   ├── index.html
│   ├── classification.html
│   └── alerts.html
└── watched/          # Directory being monitored
```

## Workflow
1. File changes detected in `watched/` directory
2. Hash calculated and compared with baseline
3. Event logged to PostgreSQL database
4. Alert sent via configured webhooks (n8n, Telegram)
5. Dashboard displays real-time events

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string (required)
- `FLASK_SECRET_KEY` - Flask session secret key (optional - auto-generated if not set, but recommended for production persistence)
- `N8N_WEBHOOK_URL` - n8n webhook URL for alerts (optional)
- `TELEGRAM_BOT_TOKEN` - Telegram bot token (optional)
- `TELEGRAM_CHAT_ID` - Telegram chat ID (optional)

## Running the Application
```bash
python main.py
```
The dashboard will be available at http://0.0.0.0:5000

## Alert Integration
### n8n.io
1. Create a webhook trigger in n8n
2. Copy the production webhook URL
3. Add it in the Alerts page of the dashboard

### Telegram
Set the `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` environment variables.

## Recent Changes
- Replaced MongoDB with PostgreSQL
- Merged REFER agent with FIM codebase
- Added webhook alert configuration
- Added file security classification system
