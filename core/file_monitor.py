import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.scanner import AntiVirusScanner

class KoalaFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.scanner = AntiVirusScanner()

    def on_created(self, event):
        print(f"🔄 File created: {event.src_path}")
        self.process_event(event)

    def on_modified(self, event):
        print(f"🔄 File modified: {event.src_path}")
        self.process_event(event)

    def on_closed(self, event):
        print(f"🔄 File closed: {event.src_path}")
        self.process_event(event)

    def process_event(self, event):
        if not event.is_directory:
            threading.Thread(
                target=self._analyze_file,
                args=(event.src_path,)
            ).start()

    def _analyze_file(self, file_path):
        if file_path.endswith('.part') or not os.path.exists(file_path):
            print(f"⏩ Skipping incomplete file: {os.path.basename(file_path)}")
            return

        alerts = self.scanner.scan_file(file_path)
        if alerts:
            filename = os.path.basename(file_path)
            print(f"\nSubject: 🚨 MALWARE ALERT - {filename}")
            print("Body: Suspicious file detected!")
            print(f"      Name: {filename}")
            print(f"      Reasons: {', '.join(alerts)}")

def start_monitoring(monitor_dir):
    observer = Observer()
    event_handler = KoalaFileHandler()
    observer.schedule(event_handler, monitor_dir, recursive=True)
    observer.start()
    print(f"👀 Monitoring directory: {monitor_dir}")

    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
