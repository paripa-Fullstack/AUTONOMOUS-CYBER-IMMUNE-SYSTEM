"""Anomaly detection module for AEGIS."""

import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Machine learning-based anomaly detector for security telemetry.
    
    Implements multiple anomaly detection algorithms including:
    - Isolation Forest
    - One-Class SVM
    - Autoencoders
    - Statistical methods (Z-score, IQR)
    """

    def __init__(
        self,
        method: str = "isolation_forest",
        contamination: float = 0.1,
        threshold: float = 2.5,
    ):
        """Initialize anomaly detector.
        
        Args:
            method: Detection method ('isolation_forest', 'ocsvm', 'autoencoder', 'zscore').
            contamination: Expected proportion of anomalies in the dataset.
            threshold: Threshold for anomaly classification.
        """
        self.method = method
        self.contamination = contamination
        self.threshold = threshold
        self.model = None
        self.is_fitted = False
        self.feature_stats = {}
        
        logger.info(f"Initialized AnomalyDetector with method={method}")

    def fit(self, data: np.ndarray) -> "AnomalyDetector":
        """Fit the anomaly detection model.
        
        Args:
            data: Training data matrix (n_samples, n_features).
        
        Returns:
            Self for method chaining.
        """
        if self.method == "isolation_forest":
            self._fit_isolation_forest(data)
        elif self.method == "ocsvm":
            self._fit_ocsvm(data)
        elif self.method == "autoencoder":
            self._fit_autoencoder(data)
        elif self.method == "zscore":
            self._fit_zscore(data)
        else:
            raise ValueError(f"Unknown method: {self.method}")
        
        self.is_fitted = True
        logger.info(f"AnomalyDetector fitted using {self.method}")
        return self

    def _fit_isolation_forest(self, data: np.ndarray) -> None:
        """Fit Isolation Forest model."""
        try:
            from sklearn.ensemble import IsolationForest
            
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self.model.fit(data)
            
        except ImportError:
            logger.warning("scikit-learn not available, using mock model")
            self.model = {"mean": np.mean(data, axis=0), "std": np.std(data, axis=0)}

    def _fit_ocsvm(self, data: np.ndarray) -> None:
        """Fit One-Class SVM model."""
        try:
            from sklearn.svm import OneClassSVM
            
            self.model = OneClassSVM(
                kernel="rbf",
                gamma="auto",
                nu=self.contamination,
            )
            self.model.fit(data)
            
        except ImportError:
            logger.warning("scikit-learn not available, using mock model")
            self.model = {"mean": np.mean(data, axis=0), "std": np.std(data, axis=0)}

    def _fit_autoencoder(self, data: np.ndarray) -> None:
        """Fit Autoencoder model."""
        try:
            import torch
            import torch.nn as nn
            
            input_dim = data.shape[1]
            hidden_dim = input_dim // 2
            
            class Autoencoder(nn.Module):
                def __init__(self, input_dim: int, hidden_dim: int):
                    super().__init__()
                    self.encoder = nn.Sequential(
                        nn.Linear(input_dim, hidden_dim),
                        nn.ReLU(),
                        nn.Linear(hidden_dim, hidden_dim // 2),
                    )
                    self.decoder = nn.Sequential(
                        nn.Linear(hidden_dim // 2, hidden_dim),
                        nn.ReLU(),
                        nn.Linear(hidden_dim, input_dim),
                    )
                
                def forward(self, x):
                    encoded = self.encoder(x)
                    decoded = self.decoder(encoded)
                    return decoded
            
            self.model = Autoencoder(input_dim, hidden_dim)
            
            # Train autoencoder
            optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
            criterion = nn.MSELoss()
            
            data_tensor = torch.FloatTensor(data)
            self.model.train()
            
            for epoch in range(50):
                optimizer.zero_grad()
                output = self.model(data_tensor)
                loss = criterion(output, data_tensor)
                loss.backward()
                optimizer.step()
            
        except ImportError:
            logger.warning("PyTorch not available, using mock model")
            self.model = {"mean": np.mean(data, axis=0), "std": np.std(data, axis=0)}

    def _fit_zscore(self, data: np.ndarray) -> None:
        """Fit Z-score statistical model."""
        self.model = {
            "mean": np.mean(data, axis=0),
            "std": np.std(data, axis=0),
        }

    def predict(self, data: np.ndarray) -> np.ndarray:
        """Predict anomalies in new data.
        
        Args:
            data: Data matrix to analyze (n_samples, n_features).
        
        Returns:
            Array of predictions (-1 for anomaly, 1 for normal).
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before prediction")
        
        if self.method == "isolation_forest" and hasattr(self.model, "predict"):
            return self.model.predict(data)
        elif self.method == "ocsvm" and hasattr(self.model, "predict"):
            return self.model.predict(data)
        elif self.method == "autoencoder":
            return self._predict_autoencoder(data)
        elif self.method == "zscore":
            return self._predict_zscore(data)
        else:
            # Mock prediction
            return np.ones(data.shape[0])

    def _predict_autoencoder(self, data: np.ndarray) -> np.ndarray:
        """Predict using autoencoder reconstruction error."""
        try:
            import torch
            
            self.model.eval()
            data_tensor = torch.FloatTensor(data)
            
            with torch.no_grad():
                reconstructed = self.model(data_tensor)
                errors = torch.mean((data_tensor - reconstructed) ** 2, dim=1)
            
            predictions = np.where(errors.numpy() > self.threshold, -1, 1)
            return predictions
            
        except Exception:
            return np.ones(data.shape[0])

    def _predict_zscore(self, data: np.ndarray) -> np.ndarray:
        """Predict using Z-score method."""
        z_scores = np.abs((data - self.model["mean"]) / (self.model["std"] + 1e-8))
        max_z_scores = np.max(z_scores, axis=1)
        predictions = np.where(max_z_scores > self.threshold, -1, 1)
        return predictions

    def get_anomaly_scores(self, data: np.ndarray) -> np.ndarray:
        """Get continuous anomaly scores for data points.
        
        Args:
            data: Data matrix to score.
        
        Returns:
            Array of anomaly scores (higher = more anomalous).
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before scoring")
        
        if self.method == "isolation_forest" and hasattr(self.model, "decision_function"):
            return -self.model.decision_function(data)
        elif self.method == "ocsvm" and hasattr(self.model, "decision_function"):
            return -self.model.decision_function(data)
        elif self.method == "autoencoder":
            return self._get_autoencoder_scores(data)
        elif self.method == "zscore":
            z_scores = np.abs((data - self.model["mean"]) / (self.model["std"] + 1e-8))
            return np.max(z_scores, axis=1)
        else:
            return np.zeros(data.shape[0])

    def _get_autoencoder_scores(self, data: np.ndarray) -> np.ndarray:
        """Get reconstruction error scores from autoencoder."""
        try:
            import torch
            
            self.model.eval()
            data_tensor = torch.FloatTensor(data)
            
            with torch.no_grad():
                reconstructed = self.model(data_tensor)
                errors = torch.mean((data_tensor - reconstructed) ** 2, dim=1)
            
            return errors.numpy()
            
        except Exception:
            return np.zeros(data.shape[0])

    def detect_realtime(
        self,
        telemetry: Dict[str, Any],
    ) -> Tuple[bool, float, str]:
        """Detect anomalies in real-time telemetry data.
        
        Args:
            telemetry: Telemetry dictionary with network metrics.
        
        Returns:
            Tuple of (is_anomaly, score, reason).
        """
        try:
            # Extract features from telemetry
            features = self._extract_features(telemetry)
            
            if features is None or len(features) == 0:
                return False, 0.0, "Insufficient features"
            
            features_array = np.array(features).reshape(1, -1)
            
            # Get anomaly score
            if self.is_fitted:
                score = self.get_anomaly_scores(features_array)[0]
                is_anomaly = self.predict(features_array)[0] == -1
            else:
                # Use simple heuristics if model not fitted
                score, is_anomaly = self._heuristic_check(telemetry)
            
            reason = self._generate_reason(is_anomaly, score, telemetry)
            
            return is_anomaly, float(score), reason
            
        except Exception as e:
            logger.error(f"Realtime detection error: {e}")
            return False, 0.0, f"Detection error: {str(e)}"

    def _extract_features(self, telemetry: Dict[str, Any]) -> Optional[List[float]]:
        """Extract numerical features from telemetry dict."""
        features = []
        
        # Network features
        if "bytes_sent" in telemetry:
            features.append(float(telemetry["bytes_sent"]))
        if "bytes_received" in telemetry:
            features.append(float(telemetry["bytes_received"]))
        if "packets" in telemetry:
            features.append(float(telemetry["packets"]))
        if "source_port" in telemetry:
            features.append(float(telemetry["source_port"]))
        if "destination_port" in telemetry:
            features.append(float(telemetry["destination_port"]))
        
        return features if features else None

    def _heuristic_check(
        self,
        telemetry: Dict[str, Any],
    ) -> Tuple[float, bool]:
        """Simple heuristic-based anomaly check."""
        score = 0.0
        
        # Check for unusual ports
        dst_port = telemetry.get("destination_port", 0)
        if dst_port in [4444, 5555, 6666, 31337]:  # Common malware ports
            score += 2.0
        
        # Check for high traffic volume
        bytes_sent = telemetry.get("bytes_sent", 0)
        if bytes_sent > 10_000_000:  # 10 MB
            score += 1.5
        
        # Check for unusual protocols
        protocol = telemetry.get("protocol", "").upper()
        if protocol in ["ICMP"] and bytes_sent > 1000:
            score += 1.0
        
        is_anomaly = score >= self.threshold
        
        return score, is_anomaly

    def _generate_reason(
        self,
        is_anomaly: bool,
        score: float,
        telemetry: Dict[str, Any],
    ) -> str:
        """Generate human-readable explanation for detection."""
        if not is_anomaly:
            return "Normal traffic pattern detected"
        
        reasons = []
        
        dst_port = telemetry.get("destination_port", 0)
        if dst_port in [4444, 5555, 6666, 31337]:
            reasons.append(f"suspicious port {dst_port}")
        
        bytes_sent = telemetry.get("bytes_sent", 0)
        if bytes_sent > 10_000_000:
            reasons.append(f"high outbound traffic ({bytes_sent} bytes)")
        
        if score > self.threshold * 2:
            reasons.append("statistical outlier")
        
        return f"Anomaly detected: {', '.join(reasons) if reasons else 'unusual pattern'}"
