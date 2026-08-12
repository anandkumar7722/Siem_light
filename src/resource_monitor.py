import psutil
import os
import time
import threading
import pandas as pd

class ResourceMonitor:
    """Samples CPU% and RAM (RSS) of the current process every `interval` seconds
    on a background thread, while your pipeline runs in the main thread."""
    def __init__(self, interval=0.5):
        self.interval = interval
        self.process = psutil.Process(os.getpid())
        self.samples = []
        self._running = False

    def _run(self):
        while self._running:
            cpu = self.process.cpu_percent(interval=None)
            mem_mb = self.process.memory_info().rss / (1024 * 1024)
            self.samples.append({"time": time.time(), "cpu_pct": cpu, "ram_mb": mem_mb})
            time.sleep(self.interval)

    def start(self):
        self._running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self, save_path="results/resource_usage.csv"):
        self._running = False
        if hasattr(self, 'thread'):
            self.thread.join()
        df = pd.DataFrame(self.samples)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        df.to_csv(save_path, index=False)
        if not df.empty:
            print(f"Peak RAM: {df['ram_mb'].max():.1f} MB")
            print(f"Avg CPU: {df['cpu_pct'].mean():.1f}%")
            print(f"Peak CPU: {df['cpu_pct'].max():.1f}%")
        return df
