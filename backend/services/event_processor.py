import os
import json
import structlog
import asyncio
import redis.asyncio as redis

logger = structlog.get_logger()

class EventProcessor:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = redis.from_url(redis_url)
        self.queue_name = "siem:events:raw"
        self.group_name = "processor_group"
        self.consumer_name = "processor_1"

    async def setup(self):
        try:
            await self.redis_client.xgroup_create(self.queue_name, self.group_name, id='0', mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def process_event(self, event_data):
        try:
            event = json.loads(event_data)
            logger.info("Processing event", event_type=event.get("event_type"))
            # Here:
            # 1. Validate & Enrich
            # 2. Save to Postgres
            # 3. Index to ES
            # 4. Trigger AI/Correlation Engine
        except json.JSONDecodeError:
            logger.error("Failed to parse event JSON")

    async def run(self):
        await self.setup()
        logger.info("Event Processor started")
        
        while True:
            try:
                # Read from stream
                messages = await self.redis_client.xreadgroup(
                    self.group_name, 
                    self.consumer_name, 
                    {self.queue_name: '>'}, 
                    count=10, 
                    block=1000
                )
                
                for stream, msg_list in messages:
                    for msg_id, msg_data in msg_list:
                        event_json = msg_data.get(b'event', b'').decode('utf-8')
                        if event_json:
                            await self.process_event(event_json)
                        await self.redis_client.xack(self.queue_name, self.group_name, msg_id)
            except Exception as e:
                logger.error("Error reading from Redis", error=str(e))
                await asyncio.sleep(1)

if __name__ == "__main__":
    processor = EventProcessor()
    asyncio.run(processor.run())
