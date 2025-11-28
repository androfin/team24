"""Database models for File Integrity Monitoring System - PostgreSQL"""
from datetime import datetime
from app import db


class Event(db.Model):
    """File system events table"""
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    file_path = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    endpoint = db.Column(db.String(255), nullable=False, default='replit_agent')
    hostname = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    hash_before = db.Column(db.String(128))
    hash_after = db.Column(db.String(128))
    state_hash = db.Column(db.String(128))
    content_hash = db.Column(db.String(128))
    file_size = db.Column(db.BigInteger)
    metadata_json = db.Column(db.Text)
    alert_sent = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'file_path': self.file_path,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'endpoint': self.endpoint,
            'hostname': self.hostname,
            'username': self.username,
            'hash_before': self.hash_before,
            'hash_after': self.hash_after,
            'state_hash': self.state_hash,
            'content_hash': self.content_hash,
            'file_size': self.file_size,
            'alert_sent': self.alert_sent
        }


class FileClassification(db.Model):
    """Security classification for monitored files"""
    __tablename__ = 'file_classification'
    
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.Text, nullable=False, unique=True, index=True)
    classification = db.Column(db.String(50), nullable=False)
    last_updated_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    endpoint = db.Column(db.String(255))
    hostname = db.Column(db.String(255))
    username = db.Column(db.String(255))
    
    def to_dict(self):
        return {
            'id': self.id,
            'file_path': self.file_path,
            'classification': self.classification,
            'last_updated_timestamp': self.last_updated_timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.last_updated_timestamp else None,
            'endpoint': self.endpoint,
            'hostname': self.hostname,
            'username': self.username
        }


class HashBaseline(db.Model):
    """Baseline hashes for file integrity comparison"""
    __tablename__ = 'hash_baseline'
    
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.Text, nullable=False, unique=True, index=True)
    content_hash = db.Column(db.String(128), nullable=False)
    state_hash = db.Column(db.String(128))
    file_size = db.Column(db.BigInteger)
    metadata_json = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'file_path': self.file_path,
            'content_hash': self.content_hash,
            'state_hash': self.state_hash,
            'file_size': self.file_size,
            'last_updated': self.last_updated.strftime('%Y-%m-%d %H:%M:%S') if self.last_updated else None
        }


class AlertConfig(db.Model):
    """Configuration for webhook alerts (n8n, Telegram, etc.)"""
    __tablename__ = 'alert_config'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    webhook_url = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    alert_on_created = db.Column(db.Boolean, default=True)
    alert_on_modified = db.Column(db.Boolean, default=True)
    alert_on_deleted = db.Column(db.Boolean, default=True)
    min_classification = db.Column(db.String(50), default='Unclassified')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'webhook_url': self.webhook_url,
            'is_active': self.is_active,
            'alert_on_created': self.alert_on_created,
            'alert_on_modified': self.alert_on_modified,
            'alert_on_deleted': self.alert_on_deleted,
            'min_classification': self.min_classification
        }


class AlertHistory(db.Model):
    """History of sent alerts"""
    __tablename__ = 'alert_history'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    alert_config_id = db.Column(db.Integer, db.ForeignKey('alert_config.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='sent')
    response_code = db.Column(db.Integer)
    error_message = db.Column(db.Text)
    
    event = db.relationship('Event', backref='alerts')
    alert_config = db.relationship('AlertConfig', backref='history')
