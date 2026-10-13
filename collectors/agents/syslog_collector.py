import asyncio
import json
import structlog
from datetime import datetime
from syslog_rfc5424_parser import SyslogMessage, ParseError

logger = structlog.get_logger()

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, redis_client, queue_name):
        self.redis_client = redis_client
        self.queue_name = queue_name

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.process_message(data.decode('utf-8', errors='ignore'), addr))

    async def process_message(self, message, addr):
        try:
            # Try to parse as RFC5424 first
            syslog_msg = SyslogMessage.parse(message)
            event = {
                "timestamp": syslog_msg.timestamp.isoformat() if syslog_msg.timestamp else datetime.utcnow().isoformat(),
                "source_ip": addr[0],
                "hostname": syslog_msg.hostname,
                "app_name": syslog_msg.appname,
                "message": syslog_msg.msg,
                "severity": syslog_msg.severity,
                "facility": syslog_msg.facility,
                "event_type": "syslog",
                "raw": message
            }
        except ParseError:
            # Fallback for RFC3164 or non-standard format
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": addr[0],
                "message": message.strip(),
                "event_type": "syslog",
                "raw": message
            }
            
        await self.publish_event(event)

    async def publish_event(self, event):
        try:
            await self.redis_client.xadd(self.queue_name, {"event": json.dumps(event)})
        except Exception as e:
            logger.error("Failed to publish syslog event", error=str(e))

class SyslogCollector:
    def __init__(self, redis_client, port=514, queue_name="siem:events:raw"):
        self.redis_client = redis_client
        self.port = port
        self.queue_name = queue_name
        self.transport = None

    async def start(self):
        logger.info("Starting Syslog Collector", port=self.port)
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self.redis_client, self.queue_name),
            local_addr=('0.0.0.0', self.port)
        )
        # Keep running
        while True:
            await asyncio.sleep(3600)

    async def stop(self):
        if self.transport:
            self.transport.close()
