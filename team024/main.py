"""Main entry point - runs the FIM system with Flask dashboard and file watcher"""
import threading
from app import app
from watcher import DirectoryWatcher
from config import FLASK_HOST, FLASK_PORT, WATCH_DIRECTORY


def main():
    """Initialize and run both the watcher and Flask app"""
    print("[INIT] Starting File Integrity Monitoring System...")
    print(f"[INIT] Watch directory: {WATCH_DIRECTORY}")
    
    with app.app_context():
        print("[INIT] Database tables ready")
    
    print("[INIT] Starting directory watcher...")
    watcher = DirectoryWatcher(app.app_context())
    watcher_thread = threading.Thread(target=watcher.start_background, daemon=True)
    watcher_thread.start()
    
    print(f"[FLASK] Starting dashboard on http://{FLASK_HOST}:{FLASK_PORT}")
    
    try:
        app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Shutting down...")
        watcher.stop()


if __name__ == "__main__":
    main()
