import numpy as np
from sklearn.ensemble import IsolationForest
from pydantic import BaseModel

class AnomalyScore(BaseModel):
    is_anomaly: bool
    score: float
    anomaly_type: str
    baseline_deviation: float

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_fitted = False

    def fit(self, historical_data: list[list[float]]):
        if historical_data:
            self.model.fit(historical_data)
            self.is_fitted = True

    def detect(self, event: dict) -> AnomalyScore:
        features = [
            event.get("connection_frequency", 0),
            event.get("port_scanning", 0),
            event.get("traffic_volume", 0),
            event.get("user_behavior", 0)
        ]
        
        if not self.is_fitted:
            return AnomalyScore(is_anomaly=False, score=0.0, anomaly_type="unknown", baseline_deviation=0.0)

        X = np.array([features])
        pred = self.model.predict(X)
        score = self.model.decision_function(X)[0]
        
        is_anomaly = bool(pred[0] == -1)
        norm_score = float(1.0 / (1.0 + np.exp(score)))

        return AnomalyScore(
            is_anomaly=is_anomaly,
            score=norm_score,
            anomaly_type="network_anomaly" if is_anomaly else "normal",
            baseline_deviation=float(abs(score))
        )
