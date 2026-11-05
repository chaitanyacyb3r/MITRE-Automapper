import os
import time
import threading
import random
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RansomGuardHandler(FileSystemEventHandler):
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.last_event_time = 0
        self.event_count = 0
        
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            ext = os.path.splitext(file_path)[1]
            current_time = time.time()
            
            # Simple rate tracking
            if current_time - self.last_event_time < 1.0:
                self.event_count += 1
            else:
                self.event_count = 1
                self.last_event_time = current_time
                
            # Compute a dummy entropy change or mock check
            entropy = round(random.uniform(6.5, 7.9) if self.event_count > 3 else random.uniform(3.5, 5.5), 2)
            
            alert = {
                "timestamp": time.strftime("%H:%M:%S"),
                "event": "Modified",
                "file": os.path.basename(file_path),
                "entropy": entropy,
                "extension": ext if ext else "None",
                "rate": self.event_count
            }
            self.alert_callback(alert)

class RansomGuard:
    def __init__(self, watch_dir=None):
        self.watch_dir = watch_dir
        self.observer = None
        self.handler = None
        self.is_running = False
        self.alerts = []
        self.simulation_thread = None
        
    def start_monitoring(self, alert_callback):
        if self.is_running:
            return
        
        self.alerts = []
        self.is_running = True
        
        # If directory specified, start watchdog observer
        if self.watch_dir and os.path.exists(self.watch_dir):
            self.handler = RansomGuardHandler(alert_callback)
            self.observer = Observer()
            self.observer.schedule(self.handler, self.watch_dir, recursive=False)
            self.observer.start()
        else:
            # Fall back to simulation thread
            self.start_simulation(alert_callback)
            
    def stop_monitoring(self):
        if not self.is_running:
            return
            
        self.is_running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
        if self.simulation_thread:
            self.simulation_thread.join()
            self.simulation_thread = None
            
    def start_simulation(self, alert_callback):
        def run_sim():
            extensions = [".txt", ".docx", ".pdf", ".jpg", ".xlsx", ".png"]
            ransom_extensions = [".crypt", ".locked", ".wannacry", ".cryptor"]
            
            files = [f"document_{i}" for i in range(1, 20)] + [f"invoice_{i}" for i in range(1, 10)] + [f"photo_{i}" for i in range(1, 15)]
            
            start_time = time.time()
            rate = 0
            
            while self.is_running:
                elapsed = time.time() - start_time
                
                # Ransomware simulation: after 5 seconds, behavior becomes malicious
                is_malicious = elapsed > 5.0 and elapsed < 18.0
                
                if is_malicious:
                    # High rate of modifications, encryption extensions, high entropy
                    rate = random.randint(6, 18)
                    file_name = random.choice(files) + random.choice(ransom_extensions)
                    entropy = round(random.uniform(7.5, 7.98), 2)
                    event_type = "Renamed/Encrypted"
                    sleep_time = random.uniform(0.15, 0.4) # very fast modifications
                else:
                    # Regular user activity
                    rate = 1 if random.random() > 0.7 else 0
                    file_name = random.choice(files) + random.choice(extensions)
                    entropy = round(random.uniform(3.5, 5.8), 2)
                    event_type = "Modified" if rate > 0 else "None"
                    sleep_time = random.uniform(1.5, 3.0)
                    
                if event_type != "None":
                    alert = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "event": event_type,
                        "file": file_name,
                        "entropy": entropy,
                        "extension": os.path.splitext(file_name)[1],
                        "rate": rate if is_malicious else 1
                    }
                    alert_callback(alert)
                    
                time.sleep(sleep_time)
                
        self.simulation_thread = threading.Thread(target=run_sim, daemon=True)
        self.simulation_thread.start()

if __name__ == "__main__":
    def print_alert(alert):
        print(f"[{alert['timestamp']}] Event: {alert['event']} | File: {alert['file']} | Entropy: {alert['entropy']} | Rate: {alert['rate']} modifications/sec")
        if alert['rate'] > 5:
            print(">>> WARNING: Ransomware-like activity detected!")
            
    guard = RansomGuard()
    print("Starting simulation for 10 seconds...")
    guard.start_monitoring(print_alert)
    time.sleep(10)
    guard.stop_monitoring()
    print("Stopped.")
