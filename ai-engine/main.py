"""
AI Engine - FastAPI Service for AI-powered security analysis.
Provides endpoints for event analysis, anomaly detection,
threat intel enrichment, playbook generation, and NLP log classification.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any
import structlog

from analyzers.event_analyzer import EventAnalyzer, AnalysisResult, CorrelationResult
from analyzers.anomaly_detector import AnomalyDetector, AnomalyScore
from analyzers.threat_intel import ThreatIntelEnricher
from analyzers.playbook_generator import PlaybookGenerator, PlaybookDefinition
from analyzers.nlp_classifier import LogClassifier, LogClassification

from prometheus_client import make_asgi_app

logger = structlog.get_logger(__name__)

# Thread pool for running sync AI calls without blocking the event loop
_executor = ThreadPoolExecutor(max_workers=4)

app = FastAPI(
    title="SIEM/SOAR AI Engine",
    description="AI-powered security analysis using Gemini API",
    version="1.0.0",
)

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Initialize analyzers at startup (singleton)
event_analyzer = EventAnalyzer()
anomaly_detector = AnomalyDetector()
threat_intel = ThreatIntelEnricher()
playbook_generator = PlaybookGenerator()
log_classifier = LogClassifier()


async def run_in_thread(func, *args):
    """Run a blocking (sync) function in a thread pool to avoid blocking the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, func, *args)


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "ai-engine"}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": str(exc)})


# ─── Event Analysis ───────────────────────────────────────────────────────────

@app.post("/analyze/event", response_model=AnalysisResult, tags=["Analysis"])
async def analyze_event(event_data: Dict[str, Any]):
    """Analyze a single security event using Gemini AI."""
    try:
        result = await run_in_thread(event_analyzer.analyze_event, event_data)
        return result
    except Exception as e:
        logger.error("analyze_event_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Event analysis failed: {e}")


@app.post("/analyze/batch", response_model=List[AnalysisResult], tags=["Analysis"])
async def analyze_batch(events: List[Dict[str, Any]]):
    """Batch analyze multiple security events."""
    try:
        result = await run_in_thread(event_analyzer.analyze_batch, events)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {e}")


@app.post("/analyze/anomaly", response_model=AnomalyScore, tags=["Analysis"])
async def analyze_anomaly(event: Dict[str, Any]):
    """Detect anomalies using ML (Isolation Forest)."""
    try:
        return await run_in_thread(anomaly_detector.detect, event)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {e}")


# ─── NLP Log Classification ───────────────────────────────────────────────────

@app.post("/classify/log", response_model=LogClassification, tags=["NLP"])
async def classify_log(request: Dict[str, Any]):
    """Parse and classify an unstructured log entry."""
    raw_log = request.get("raw_log", "")
    if not raw_log:
        raise HTTPException(status_code=400, detail="raw_log is required")
    try:
        return await run_in_thread(log_classifier.classify_log, raw_log)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log classification failed: {e}")


# ─── Playbook Generation ──────────────────────────────────────────────────────

@app.post("/generate/playbook", response_model=PlaybookDefinition, tags=["SOAR"])
async def generate_playbook(request: Dict[str, Any]):
    """Generate an AI-powered SOAR playbook for an incident."""
    desc = request.get("incident_description", "")
    event_type = request.get("event_type", "unknown")
    assets = request.get("affected_assets", [])
    try:
        return await run_in_thread(
            playbook_generator.generate_playbook, desc, event_type, assets
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Playbook generation failed: {e}")


# ─── Threat Intelligence ──────────────────────────────────────────────────────

@app.post("/enrich/threat-intel", tags=["Threat Intel"])
async def enrich_threat_intel(request: Dict[str, Any]):
    """Enrich an IP address with threat intelligence data."""
    ip = request.get("ip")
    domain = request.get("domain")
    file_hash = request.get("hash")

    if ip:
        return await run_in_thread(threat_intel.enrich_ip, ip)
    elif domain:
        return await run_in_thread(threat_intel.enrich_domain, domain)
    elif file_hash:
        return await run_in_thread(threat_intel.enrich_hash, file_hash)
    raise HTTPException(status_code=400, detail="Provide ip, domain, or hash")


# ─── Alert Correlation ────────────────────────────────────────────────────────

@app.post("/correlate/alerts", response_model=CorrelationResult, tags=["Analysis"])
async def correlate_alerts(events: List[Dict[str, Any]]):
    """Correlate multiple events to identify attack patterns."""
    if not events:
        raise HTTPException(status_code=400, detail="At least one event required")
    try:
        return await run_in_thread(event_analyzer.correlate_events, events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation failed: {e}")

