import asyncio
import os
import structlog
import redis.asyncio as redis
from dotenv import load_dotenv

from agents.syslog_collector import SyslogCollector
from agents.file_collector import FileCollector
from agents.api_collector import APICollector
from agents.windows_collector import WindowsCollector

load_dotenv()

logger = structlog.get_logger()

async def main():
    logger.info("Starting SIEM Log Collectors")
    
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(redis_url, max_connections=50)
    
    # Initialize collectors
    watch_dir = os.getenv("LOG_WATCH_DIR", "/logs")
    collectors = [
        SyslogCollector(redis_client, port=514),
        FileCollector(redis_client, watch_dir=watch_dir),
        APICollector(redis_client),
        WindowsCollector(redis_client)
    ]
    
    # Start all collector tasks
    tasks = []
    for collector in collectors:
        tasks.append(asyncio.create_task(collector.start()))
        
    logger.info("All collectors started. Awaiting events...")
    
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Shutting down collectors...")
        for collector in collectors:
            await collector.stop()

if __name__ == "__main__":
    asyncio.run(main())
