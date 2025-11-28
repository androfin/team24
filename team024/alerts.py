"""Alert system for sending notifications via webhooks (n8n, Telegram, etc.)"""
import json
import requests
from datetime import datetime
from typing import Dict, Optional, List

from config import N8N_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID


def send_webhook_alert(webhook_url: str, event_data: Dict) -> tuple:
    """Send alert to a webhook URL (e.g., n8n)"""
    if not webhook_url:
        return False, "No webhook URL configured"
    
    try:
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "FIM_System",
            "event": event_data
        }
        
        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code in [200, 201, 202, 204]:
            return True, response.status_code
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
            
    except requests.exceptions.Timeout:
        return False, "Request timeout"
    except requests.exceptions.RequestException as e:
        return False, str(e)


def send_telegram_alert(event_data: Dict) -> tuple:
    """Send alert directly to Telegram bot"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "Telegram not configured"
    
    try:
        event_type = event_data.get('event_type', 'unknown').upper()
        file_path = event_data.get('file_path', 'unknown')
        timestamp = event_data.get('timestamp', datetime.utcnow().isoformat())
        classification = event_data.get('classification', 'Unclassified')
        
        emoji = {
            'CREATED': '🆕',
            'MODIFIED': '📝',
            'DELETED': '🗑️'
        }.get(event_type, '⚠️')
        
        message = f"""
{emoji} *FIM Security Alert*

*Event Type:* {event_type}
*File:* `{file_path}`
*Classification:* {classification}
*Time:* {timestamp}
*Endpoint:* {event_data.get('endpoint', 'unknown')}

Hash Before: `{event_data.get('hash_before', 'N/A')[:16]}...`
Hash After: `{event_data.get('hash_after', 'N/A')[:16]}...`
"""
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            return True, response.status_code
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
            
    except requests.exceptions.RequestException as e:
        return False, str(e)


def process_event_alerts(event_data: Dict, alert_configs: List[Dict]) -> List[Dict]:
    """Process and send alerts for an event based on configured webhooks"""
    results = []
    
    event_type = event_data.get('event_type', '').lower()
    classification = event_data.get('classification', 'Unclassified')
    
    classification_order = ['Unclassified', 'Confidential', 'Secret', 'Top Secret']
    
    for config in alert_configs:
        if not config.get('is_active', True):
            continue
        
        should_alert = False
        if event_type == 'created' and config.get('alert_on_created', True):
            should_alert = True
        elif event_type == 'modified' and config.get('alert_on_modified', True):
            should_alert = True
        elif event_type == 'deleted' and config.get('alert_on_deleted', True):
            should_alert = True
        
        if should_alert:
            min_class = config.get('min_classification', 'Unclassified')
            if classification in classification_order and min_class in classification_order:
                if classification_order.index(classification) >= classification_order.index(min_class):
                    webhook_url = config.get('webhook_url', '')
                    success, response = send_webhook_alert(webhook_url, event_data)
                    results.append({
                        'config_id': config.get('id'),
                        'config_name': config.get('name'),
                        'success': success,
                        'response': response
                    })
    
    if N8N_WEBHOOK_URL:
        success, response = send_webhook_alert(N8N_WEBHOOK_URL, event_data)
        results.append({
            'config_name': 'n8n_default',
            'success': success,
            'response': response
        })
    
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        success, response = send_telegram_alert(event_data)
        results.append({
            'config_name': 'telegram_direct',
            'success': success,
            'response': response
        })
    
    return results
