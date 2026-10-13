import json
import time
from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

def create_index(index_name, mapping):
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name, body=mapping)
        print(f"Created index {index_name}")
    else:
        print(f"Index {index_name} already exists")

def create_ilm_policy():
    policy = {
        "policy": {
            "phases": {
                "hot": {
                    "actions": {
                        "rollover": {
                            "max_age": "7d",
                            "max_size": "50gb"
                        }
                    }
                },
                "warm": {
                    "min_age": "7d",
                    "actions": {
                        "forcemerge": {
                            "max_num_segments": 1
                        }
                    }
                },
                "delete": {
                    "min_age": "90d",
                    "actions": {
                        "delete": {}
                    }
                }
            }
        }
    }
    es.ilm.put_lifecycle(name="siem_policy", body=policy)
    print("Created ILM policy siem_policy")

security_events_mapping = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "source_ip": {"type": "ip"},
            "destination_ip": {"type": "ip"},
            "event_type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "message": {"type": "text"},
            "geoip": {
                "properties": {
                    "location": {"type": "geo_point"}
                }
            }
        }
    }
}

alerts_mapping = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "alert_id": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "status": {"type": "keyword"},
            "description": {"type": "text"}
        }
    }
}

incidents_mapping = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "incident_id": {"type": "keyword"},
            "status": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "description": {"type": "text"}
        }
    }
}

if __name__ == "__main__":
    while not es.ping():
        print("Waiting for Elasticsearch...")
        time.sleep(5)

    create_ilm_policy()
    create_index("security_events", security_events_mapping)
    create_index("alerts", alerts_mapping)
    create_index("incidents", incidents_mapping)
    print("Indices created successfully.")
