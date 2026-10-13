#!/bin/bash

echo "Initializing SIEM/SOAR..."

if ! command -v docker &> /dev/null
then
    echo "Docker could not be found. Please install Docker."
    exit 1
fi

if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
fi

echo "Pulling Docker images..."
docker-compose pull

echo "Starting infrastructure..."
docker-compose up -d elasticsearch kibana redis postgres

echo "Waiting for Elasticsearch to start..."
until curl -s http://localhost:9200 > /dev/null; do
    sleep 5
done

echo "Running Python script to create indices..."
pip install elasticsearch
python scripts/setup/create_indices.py

echo "Initialization complete."
echo "Access URLs:"
echo "Frontend: http://localhost:80"
echo "Kibana: http://localhost:5601"
echo "Grafana: http://localhost:3000"
