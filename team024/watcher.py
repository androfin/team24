"""File system watcher for real-time integrity monitoring"""
import os
import time
import json
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import WATCH_DIRECTORY, ENDPOINT_NAME, HOSTNAME, USERNAME
from hashing import calculate_state_hash, is_temp_file


class FIMEventHandler(FileSystemEventHandler):
    """Handle file system events and record them to the database"""
    
    def __init__(self, app_context):
        super().__init__()
        self.app_context = app_context
        self._lock = threading.Lock()
    
    def _record_event(self, file_path: str, event_type: str):
        """Record a file event to the PostgreSQL database"""
        if is_temp_file(file_path):
            return
        
        if os.path.isdir(file_path):
            return
        
        abs_path = os.path.abspath(file_path)
        
        with self._lock:
            with self.app_context:
                from app import db
                from models import Event, HashBaseline, FileClassification
                from alerts import process_event_alerts
                
                hash_before = None
                baseline = HashBaseline.query.filter_by(file_path=abs_path).first()
                if baseline:
                    hash_before = baseline.content_hash
                
                state_info = None
                hash_after = None
                file_size = None
                state_hash = None
                metadata_json = None
                
                if event_type != 'deleted' and os.path.exists(abs_path):
                    state_info = calculate_state_hash(abs_path)
                    if state_info:
                        hash_after = state_info['content_hash']
                        state_hash = state_info['state_hash']
                        file_size = state_info['file_size']
                        metadata_json = json.dumps(state_info['metadata'])
                        
                        if baseline:
                            if baseline.content_hash == hash_after:
                                return
                            baseline.content_hash = hash_after
                            baseline.state_hash = state_hash
                            baseline.file_size = file_size
                            baseline.metadata_json = metadata_json
                            baseline.last_updated = datetime.utcnow()
                        else:
                            new_baseline = HashBaseline(
                                file_path=abs_path,
                                content_hash=hash_after,
                                state_hash=state_hash,
                                file_size=file_size,
                                metadata_json=metadata_json
                            )
                            db.session.add(new_baseline)
                
                if event_type == 'deleted' and baseline:
                    db.session.delete(baseline)
                
                event = Event(
                    event_type=event_type,
                    file_path=abs_path,
                    timestamp=datetime.utcnow(),
                    endpoint=ENDPOINT_NAME,
                    hostname=HOSTNAME,
                    username=USERNAME,
                    hash_before=hash_before,
                    hash_after=hash_after,
                    state_hash=state_hash,
                    content_hash=hash_after,
                    file_size=file_size,
                    metadata_json=metadata_json
                )
                db.session.add(event)
                
                try:
                    db.session.commit()
                    print(f"[FIM] {event_type.upper()}: {abs_path}")
                    
                    classification = None
                    file_class = FileClassification.query.filter_by(file_path=abs_path).first()
                    if file_class:
                        classification = file_class.classification
                    
                    from models import AlertConfig
                    configs = [c.to_dict() for c in AlertConfig.query.filter_by(is_active=True).all()]
                    
                    if configs:
                        event_data = event.to_dict()
                        event_data['classification'] = classification or 'Unclassified'
                        process_event_alerts(event_data, configs)
                        
                except Exception as e:
                    db.session.rollback()
                    print(f"[FIM] Error recording event: {e}")
    
    def on_created(self, event):
        if not event.is_directory:
            self._record_event(event.src_path, 'created')
    
    def on_modified(self, event):
        if not event.is_directory:
            self._record_event(event.src_path, 'modified')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._record_event(event.src_path, 'deleted')
    
    def on_moved(self, event):
        if not event.is_directory:
            self._record_event(event.src_path, 'deleted')
            self._record_event(event.dest_path, 'created')


class DirectoryWatcher:
    """Manage the file system observer"""
    
    def __init__(self, app_context, watch_path: str = None):
        self.watch_path = watch_path or WATCH_DIRECTORY
        self.app_context = app_context
        self.observer = None
        self._running = False
    
    def start(self):
        """Start watching the directory"""
        if not os.path.exists(self.watch_path):
            os.makedirs(self.watch_path)
            print(f"[WATCHER] Created watch directory: {self.watch_path}")
        
        self.observer = Observer()
        handler = FIMEventHandler(self.app_context)
        self.observer.schedule(handler, self.watch_path, recursive=True)
        self.observer.start()
        self._running = True
        print(f"[WATCHER] Monitoring: {self.watch_path}")
        
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop watching the directory"""
        self._running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
            print("[WATCHER] Stopped monitoring")
    
    def start_background(self):
        """Start watcher in background thread"""
        if not os.path.exists(self.watch_path):
            os.makedirs(self.watch_path)
            print(f"[WATCHER] Created watch directory: {self.watch_path}")
        
        self.observer = Observer()
        handler = FIMEventHandler(self.app_context)
        self.observer.schedule(handler, self.watch_path, recursive=True)
        self.observer.start()
        self._running = True
        print(f"[WATCHER] Background monitoring: {self.watch_path}")
