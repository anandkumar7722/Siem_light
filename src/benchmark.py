import time
import psutil
import os

class ResourceMonitor:
    """Helper script for resource usage measurement (CPU%, RAM MB, pipeline latency)."""
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.start_time = None

    def start_timer(self):
        self.start_time = time.time()

    def stop_timer(self):
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    def get_resource_usage(self):
        mem_info = self.process.memory_info()
        ram_mb = mem_info.rss / (1024 * 1024)
        cpu_pct = psutil.cpu_percent(interval=0.1)
        return {
            "ram_mb": round(ram_mb, 2),
            "cpu_percent": cpu_pct
        }
