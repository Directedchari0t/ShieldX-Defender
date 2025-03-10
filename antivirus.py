import sys
import signal
import multiprocessing
from time import sleep
from web.dashboard import app
from core.file_monitor import start_monitoring
from core.database import initialize_database

# Configuration
MONITOR_DIR = "/home/koala/Downloads"  # Change this if needed
DASHBOARD_PORT = 6969

def run_dashboard():
    """Start Flask dashboard"""
    print(f"🌐 Dashboard starting on port {DASHBOARD_PORT}...")
    app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)

def run_file_monitor():
    """Start file monitoring"""
    print(f"👀 Monitoring directory: {MONITOR_DIR}")
    start_monitoring(MONITOR_DIR)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n🛑 Shutting down system...")
    for p in processes:
        p.terminate()
    sys.exit(0)

if __name__ == "__main__":
    # Initialize components
    initialize_database()
    
    # Create processes
    processes = [
        multiprocessing.Process(target=run_dashboard),
        multiprocessing.Process(target=run_file_monitor)
    ]

    # Start processes
    signal.signal(signal.SIGINT, signal_handler)
    [p.start() for p in processes]
    
    # Keep alive
    print("✅ System running! Press Ctrl+C to exit")
    [p.join() for p in processes]
