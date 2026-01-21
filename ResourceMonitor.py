import time
import psutil

class ResourceMonitor:
    def __init__(self, user='www-data'):
        self.user = user
        self.last_io_time = None
        self.last_read_bytes = 0
        self.last_write_bytes = 0
    
    def get_user_resource_usage(self):
        current_time = time.time()
        total_cpu = 0.0
        total_memory = 0.0
        current_read_bytes = 0
        current_write_bytes = 0
        
        for proc in psutil.process_iter(['pid', 'username', 'cpu_percent', 'memory_info', 'io_counters']):
            try:
                if proc.info['username'] == self.user:
                    total_cpu += proc.cpu_percent(interval=0.1)
                    total_memory += proc.info['memory_info'].rss / (1024 * 1024)
                    io = proc.info['io_counters']
                    current_read_bytes += io.read_bytes
                    current_write_bytes += io.write_bytes
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if self.last_io_time is None or current_time == self.last_io_time:
            read_rate_kb_s = 0.0
            write_rate_kb_s = 0.0
        else:
            delta_time = current_time - self.last_io_time
            delta_read = current_read_bytes - self.last_read_bytes
            delta_write = current_write_bytes - self.last_write_bytes
            read_rate_kb_s = (delta_read / delta_time) / 1024
            write_rate_kb_s = (delta_write / delta_time) / 1024
        
        self.last_io_time = current_time
        self.last_read_bytes = current_read_bytes
        self.last_write_bytes = current_write_bytes
        
        return total_cpu, total_memory, read_rate_kb_s, write_rate_kb_s