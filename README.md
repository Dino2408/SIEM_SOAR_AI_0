# AI-Powered SIEM/SOAR

A modern, AI-driven Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform.

## System Architecture

```
[Beats/Syslog] -> [Logstash] -> [Elasticsearch] <- [Backend API] <-> [Frontend SPA]
                                                    ^
                                                    |
                                                [Gemini AI]
```

## Components

- **Frontend**: Single-page application built with HTML, Tailwind CSS, and vanilla JS.
- **Backend API**: Python FastAPI application (planned).
- **Logstash**: Data processing pipeline.
- **Elasticsearch**: Data storage and search engine.
- **Kibana**: Data visualization.
- **Prometheus/Grafana**: Monitoring and alerting.
- **Redis**: Caching and message broker.
- **PostgreSQL**: Relational database for settings and user management.

## Prerequisites

- Docker and docker-compose
- Python 3.9+ (for setup scripts)

## Quick Start

1. Clone the repository.
2. Run `cp .env.example .env` and fill in the required keys.
3. Run `bash scripts/setup/init.sh`.
4. Access the frontend at `http://localhost:80`.
5. Access Kibana at `http://localhost:5601`.

## Configuration

- Logstash pipelines are configured in `configs/logstash/`.
- Environment variables are managed in `.env`.

## API Documentation

- API documentation will be available at `http://localhost:8000/docs` once the backend is running.

## AI Features

- **Alert Analysis**: The system integrates with Gemini AI to analyze alerts and suggest remediation steps.
- **Incident Querying**: You can use natural language to query incidents and logs through the frontend chat panel.

## Troubleshooting

- Ensure Docker is running.
- Check the logs of individual containers using `docker-compose logs <service_name>`.

## Contributing

- Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
