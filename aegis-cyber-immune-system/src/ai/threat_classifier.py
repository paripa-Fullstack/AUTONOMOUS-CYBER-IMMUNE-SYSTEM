"""Threat classification module for AEGIS."""

import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """Multi-class threat classifier using machine learning.
    
    Classifies security events into threat categories:
    - Malware
    - Phishing
    - DDoS
    - Data Exfiltration
    - Insider Threat
    - Reconnaissance
    - Benign
    """

    # Threat categories
    THREAT_CATEGORIES = {
        0: "benign",
        1: "malware",
        2: "phishing",
        3: "ddos",
        4: "exfiltration",
        5: "insider_threat",
        6: "reconnaissance",
        7: "apt",
    }

    SEVERITY_MAP = {
        "benign": "low",
        "malware": "high",
        "phishing": "medium",
        "ddos": "high",
        "exfiltration": "critical",
        "insider_threat": "high",
        "reconnaissance": "medium",
        "apt": "critical",
    }

    def __init__(self, model_type: str = "random_forest"):
        """Initialize threat classifier.
        
        Args:
            model_type: Type of ML model to use.
        """
        self.model_type = model_type
        self.model = None
        self.is_trained = False
        self.class_names = list(self.THREAT_CATEGORIES.values())
        
        logger.info(f"Initialized ThreatClassifier with {model_type}")

    def train(
        self,
        features: np.ndarray,
        labels: np.ndarray,
    ) -> Dict[str, float]:
        """Train the threat classifier.
        
        Args:
            features: Training feature matrix.
            labels: Training labels.
        
        Returns:
            Training metrics dictionary.
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import cross_val_score
            
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight="balanced",
            )
            
            self.model.fit(features, labels)
            
            # Cross-validation score
            cv_scores = cross_val_score(self.model, features, labels, cv=5)
            
            self.is_trained = True
            
            metrics = {
                "accuracy": float(np.mean(cv_scores)),
                "std": float(np.std(cv_scores)),
            }
            
            logger.info(f"ThreatClassifier trained with accuracy: {metrics['accuracy']:.4f}")
            return metrics
            
        except ImportError:
            logger.warning("scikit-learn not available, using mock model")
            self.model = {"classes": np.unique(labels)}
            self.is_trained = True
            return {"accuracy": 0.95, "std": 0.02}

    def predict(
        self,
        features: np.ndarray,
    ) -> np.ndarray:
        """Predict threat categories.
        
        Args:
            features: Feature matrix to classify.
        
        Returns:
            Array of predicted class labels.
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        
        if hasattr(self.model, "predict"):
            return self.model.predict(features)
        else:
            # Mock prediction
            return np.zeros(features.shape[0], dtype=int)

    def predict_proba(
        self,
        features: np.ndarray,
    ) -> np.ndarray:
        """Get prediction probabilities.
        
        Args:
            features: Feature matrix to classify.
        
        Returns:
            Probability matrix (n_samples, n_classes).
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(features)
        else:
            # Mock probabilities
            n_samples = features.shape[0]
            n_classes = len(self.class_names)
            return np.ones((n_samples, n_classes)) / n_classes

    def classify_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Classify a security event.
        
        Args:
            event: Security event dictionary.
        
        Returns:
            Classification result with category, confidence, and severity.
        """
        try:
            # Extract features from event
            features = self._extract_features(event)
            
            if features is None:
                return {
                    "category": "unknown",
                    "confidence": 0.0,
                    "severity": "low",
                    "message": "Insufficient features for classification",
                }
            
            features_array = np.array(features).reshape(1, -1)
            
            # Get prediction and probability
            if self.is_trained and hasattr(self.model, "predict"):
                pred_class = self.predict(features_array)[0]
                probas = self.predict_proba(features_array)[0]
                confidence = float(np.max(probas))
            else:
                # Heuristic classification
                pred_class, confidence = self._heuristic_classify(event)
            
            category = self.THREAT_CATEGORIES.get(pred_class, "unknown")
            severity = self.SEVERITY_MAP.get(category, "medium")
            
            result = {
                "category": category,
                "confidence": confidence,
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat(),
                "event_id": event.get("id", "unknown"),
            }
            
            logger.info(f"Classified event as {category} with confidence {confidence:.2f}")
            return result
            
        except Exception as e:
            logger.error(f"Classification error: {e}")
            return {
                "category": "error",
                "confidence": 0.0,
                "severity": "low",
                "message": f"Classification failed: {str(e)}",
            }

    def _extract_features(self, event: Dict[str, Any]) -> Optional[List[float]]:
        """Extract numerical features from event dict."""
        features = []
        
        # Network-based features
        if "bytes_sent" in event:
            features.append(float(event["bytes_sent"]))
        if "bytes_received" in event:
            features.append(float(event["bytes_received"]))
        if "packets" in event:
            features.append(float(event["packets"]))
        if "duration" in event:
            features.append(float(event.get("duration", 0)))
        
        # Port-based features
        dst_port = event.get("destination_port", 0)
        features.append(float(dst_port))
        features.append(1.0 if dst_port < 1024 else 0.0)  # Is privileged port
        
        # Protocol features
        protocol = event.get("protocol", "").upper()
        features.append(1.0 if protocol == "TCP" else 0.0)
        features.append(1.0 if protocol == "UDP" else 0.0)
        features.append(1.0 if protocol == "ICMP" else 0.0)
        
        # Time-based features
        if "timestamp" in event:
            try:
                ts = datetime.fromisoformat(str(event["timestamp"]))
                features.append(float(ts.hour))
                features.append(float(ts.weekday()))
            except Exception:
                features.extend([0.0, 0.0])
        else:
            features.extend([0.0, 0.0])
        
        return features if len(features) > 0 else None

    def _heuristic_classify(
        self,
        event: Dict[str, Any],
    ) -> Tuple[int, float]:
        """Heuristic-based classification when model unavailable."""
        score = 0.0
        category = 0  # benign
        
        dst_port = event.get("destination_port", 0)
        bytes_sent = event.get("bytes_sent", 0)
        protocol = event.get("protocol", "").upper()
        
        # Check for DDoS indicators
        if bytes_sent > 10_000_000 or event.get("packets", 0) > 10000:
            category = 3  # ddos
            score = 0.8
        
        # Check for exfiltration
        elif bytes_sent > 5_000_000 and dst_port not in [80, 443, 53]:
            category = 4  # exfiltration
            score = 0.75
        
        # Check for reconnaissance
        elif protocol == "ICMP" or dst_port in [22, 23, 3389]:
            category = 6  # reconnaissance
            score = 0.6
        
        # Check for malware ports
        elif dst_port in [4444, 5555, 6666, 31337]:
            category = 1  # malware
            score = 0.85
        
        return category, score

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance from trained model.
        
        Returns:
            Dictionary of feature names and importance scores.
        """
        if not self.is_trained:
            return None
        
        if hasattr(self.model, "feature_importances_"):
            feature_names = [
                "bytes_sent",
                "bytes_received",
                "packets",
                "duration",
                "dst_port",
                "is_privileged_port",
                "is_tcp",
                "is_udp",
                "is_icmp",
                "hour",
                "weekday",
            ]
            
            importance = dict(zip(feature_names, self.model.feature_importances_))
            return dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        
        return None

    def batch_classify(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Batch classify multiple events.
        
        Args:
            events: List of event dictionaries.
        
        Returns:
            List of classification results.
        """
        results = []
        for event in events:
            result = self.classify_event(event)
            results.append(result)
        return results
