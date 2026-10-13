import asyncio
import json
import os
import structlog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

logger = structlog.get_logger()

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, callback):
        self.watch_dir = watch_dir
        self.callback = callback
        self.file_positions = {}
        # Find all existing .log, .txt, .json files
        for root, dirs, files in os.walk(watch_dir):
            for file in files:
                if file.endswith(('.log', '.txt', '.json', '.csv')):
                    path = os.path.join(root, file)
                    self.file_positions[path] = 0

    def is_valid_file(self, path):
        return path.endswith(('.log', '.txt', '.json', '.csv'))

    def on_modified(self, event):
        if not event.is_directory and self.is_valid_file(event.src_path):
            self.read_new_lines(event.src_path)
            
    def on_created(self, event):
        if not event.is_directory and self.is_valid_file(event.src_path):
            self.file_positions[event.src_path] = 0
            self.read_new_lines(event.src_path)

    def process_all_existing(self):
        for path in list(self.file_positions.keys()):
            self.read_new_lines(path)

    def read_new_lines(self, file_path):
        try:
            pos = self.file_positions.get(file_path, 0)
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                return
                
            if file_size == pos:
                return
            if file_size < pos:
                pos = 0

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(pos)
                data = f.read(65536) # Read in 64K chunks
                if not data:
                    return
                
                self.file_positions[file_path] = f.tell()
                
                for line in data.splitlines():
                    line = line.strip()
                    if line:
                        asyncio.run_coroutine_threadsafe(self.callback(file_path, line), asyncio.get_event_loop())
        except Exception as e:
            logger.error("Error reading file", path=file_path, error=str(e))

class FileCollector:
    def __init__(self, redis_client, watch_dir="/logs", queue_name="siem:events:raw"):
        self.redis_client = redis_client
        self.watch_dir = watch_dir
        self.queue_name = queue_name
        self.observer = Observer()
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.worker_task = None

    async def _redis_worker(self):
        while True:
            try:
                # Get events in batches if possible
                events_to_send = []
                file_path, line = await self.event_queue.get()
                events_to_send.append((file_path, line))
                
                # Try to get more items if available immediately
                while len(events_to_send) < 100:
                    try:
                        fp, ln = self.event_queue.get_nowait()
                        events_to_send.append((fp, ln))
                    except asyncio.QueueEmpty:
                        break
                        
                # Publish batch to redis
                async with self.redis_client.pipeline(transaction=True) as pipe:
                    for fp, ln in events_to_send:
                        event = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "source_file": fp,
                            "event_type": "file_log",
                            "raw": ln
                        }
                        if "eve.json" in fp:
                            try:
                                event["parsed"] = json.loads(ln)
                                event["event_type"] = "suricata"
                            except json.JSONDecodeError:
                                pass
                        pipe.xadd(self.queue_name, {"event": json.dumps(event)})
                    
                    await pipe.execute()
                
                for _ in events_to_send:
                    self.event_queue.task_done()
            except Exception as e:
                logger.error("Failed to publish file event batch", error=str(e))
                await asyncio.sleep(1)

    async def process_log_line(self, file_path, line):
        try:
            # Don't block the event loop, just drop if queue is completely full
            self.event_queue.put_nowait((file_path, line))
        except asyncio.QueueFull:
            logger.warning("Event queue full, dropping log line")

    async def start(self):
        logger.info("Starting File Collector", watch_dir=self.watch_dir)
        if not os.path.exists(self.watch_dir):
            logger.warning(f"Watch dir {self.watch_dir} does not exist.")
            return
            
        self.worker_task = asyncio.create_task(self._redis_worker())
            
        handler = LogFileHandler(self.watch_dir, self.process_log_line)
        self.observer.schedule(handler, self.watch_dir, recursive=True)
        self.observer.start()
        
        # Process existing logs
        logger.info("Processing existing logs in directory", watch_dir=self.watch_dir)
        handler.process_all_existing()
        
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.observer.stop()
            self.observer.join()
            if self.worker_task:
                self.worker_task.cancel()

    async def stop(self):
        self.observer.stop()
        self.observer.join()
        if self.worker_task:
            self.worker_task.cancel()
