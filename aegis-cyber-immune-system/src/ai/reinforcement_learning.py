"""Reinforcement Learning agent for automated response in AEGIS."""

import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class ReinforcementLearningAgent:
    """RL agent for learning optimal security response strategies.
    
    Uses Q-learning to learn which remediation actions are most effective
    for different types of threats, optimizing for:
    - Threat neutralization speed
    - Minimal business disruption
    - Resource efficiency
    """

    # Available actions
    ACTIONS = [
        "monitor",           # Continue monitoring
        "alert",             # Send alert to SOC
        "block_ip",          # Block source IP
        "isolate_host",      # Isolate affected host
        "kill_process",      # Terminate malicious process
        "quarantine_file",   # Quarantine suspicious file
        "reset_credentials", # Reset user credentials
        "full_incident_response",  # Escalate to full IR
    ]

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        exploration_rate: float = 0.3,
        decay_rate: float = 0.995,
        min_exploration: float = 0.01,
    ):
        """Initialize RL agent.
        
        Args:
            learning_rate: Alpha - how fast agent learns.
            discount_factor: Gamma - importance of future rewards.
            exploration_rate: Epsilon - exploration vs exploitation.
            decay_rate: How fast exploration decays.
            min_exploration: Minimum exploration rate.
        """
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.decay_rate = decay_rate
        self.min_exploration = min_exploration
        
        # Q-table: state -> action -> value
        self.q_table: Dict[str, Dict[str, float]] = {}
        
        # Experience replay buffer
        self.experience_buffer: List[Tuple] = []
        self.max_buffer_size = 10000
        
        self.episodes = 0
        self.total_reward = 0.0
        
        logger.info("Initialized RL Agent for automated response")

    def _get_state_key(self, threat_info: Dict[str, Any]) -> str:
        """Convert threat information to state key.
        
        Args:
            threat_info: Dictionary with threat characteristics.
        
        Returns:
            String state key.
        """
        severity = threat_info.get("severity", "medium").lower()
        category = threat_info.get("category", "unknown").lower()
        confidence = threat_info.get("confidence", 0.5)
        
        # Discretize confidence
        conf_level = "low" if confidence < 0.5 else "medium" if confidence < 0.8 else "high"
        
        return f"{severity}_{category}_{conf_level}"

    def get_action(
        self,
        threat_info: Dict[str, Any],
        training: bool = False,
    ) -> str:
        """Select action based on current policy.
        
        Args:
            threat_info: Information about the detected threat.
            training: Whether in training mode (more exploration).
        
        Returns:
            Selected action string.
        """
        state_key = self._get_state_key(threat_info)
        
        # Initialize state if new
        if state_key not in self.q_table:
            self.q_table[state_key] = {action: 0.0 for action in self.ACTIONS}
        
        # Epsilon-greedy action selection
        if training or np.random.random() < self.exploration_rate:
            # Explore: random action
            action = np.random.choice(self.ACTIONS)
        else:
            # Exploit: best known action
            q_values = self.q_table[state_key]
            max_q = max(q_values.values())
            best_actions = [a for a, q in q_values.items() if q == max_q]
            action = np.random.choice(best_actions)  # Random tie-breaking
        
        return action

    def update(
        self,
        threat_info: Dict[str, Any],
        action: str,
        reward: float,
        next_threat_info: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Update Q-values using Q-learning update rule.
        
        Args:
            threat_info: Current threat state.
            action: Action taken.
            reward: Reward received.
            next_threat_info: Next state (optional for terminal states).
        
        Returns:
            Temporal difference error.
        """
        state_key = self._get_state_key(threat_info)
        
        # Initialize state if new
        if state_key not in self.q_table:
            self.q_table[state_key] = {action: 0.0 for action in self.ACTIONS}
        
        if action not in self.q_table[state_key]:
            self.q_table[state_key][action] = 0.0
        
        # Get current Q-value
        current_q = self.q_table[state_key][action]
        
        # Calculate max Q-value for next state
        if next_threat_info:
            next_state_key = self._get_state_key(next_threat_info)
            if next_state_key not in self.q_table:
                self.q_table[next_state_key] = {a: 0.0 for a in self.ACTIONS}
            max_next_q = max(self.q_table[next_state_key].values())
        else:
            # Terminal state
            max_next_q = 0.0
        
        # Q-learning update
        td_error = reward + self.discount_factor * max_next_q - current_q
        self.q_table[state_key][action] += self.learning_rate * td_error
        
        # Store experience
        self.experience_buffer.append((state_key, action, reward, next_state_key))
        if len(self.experience_buffer) > self.max_buffer_size:
            self.experience_buffer.pop(0)
        
        self.total_reward += reward
        
        return td_error

    def calculate_reward(
        self,
        threat_neutralized: bool,
        time_to_respond: float,
        false_positive: bool = False,
        business_impact: str = "low",
    ) -> float:
        """Calculate reward for an action.
        
        Args:
            threat_neutralized: Whether threat was successfully neutralized.
            time_to_respond: Time taken to respond in seconds.
            false_positive: Whether this was a false positive.
            business_impact: Business impact level (low/medium/high).
        
        Returns:
            Calculated reward value.
        """
        reward = 0.0
        
        # Base reward for neutralization
        if threat_neutralized:
            reward += 10.0
        else:
            reward -= 5.0
        
        # Time penalty (faster is better)
        time_penalty = min(time_to_respond / 60.0, 5.0)  # Max 5 point penalty
        reward -= time_penalty
        
        # False positive penalty
        if false_positive:
            reward -= 15.0
        
        # Business impact bonus/penalty
        impact_multipliers = {"low": 1.0, "medium": 0.8, "high": 0.5}
        reward *= impact_multipliers.get(business_impact, 1.0)
        
        return reward

    def train_episode(
        self,
        scenarios: List[Dict[str, Any]],
    ) -> float:
        """Train one episode on multiple scenarios.
        
        Args:
            scenarios: List of threat scenarios to train on.
        
        Returns:
            Total reward for the episode.
        """
        episode_reward = 0.0
        
        for scenario in scenarios:
            # Get initial action
            action = self.get_action(scenario, training=True)
            
            # Simulate response (in real system, this would execute the action)
            threat_neutralized = np.random.random() > 0.3  # 70% success rate
            time_to_respond = np.random.uniform(5, 120)  # 5-120 seconds
            false_positive = np.random.random() < 0.1  # 10% false positive rate
            business_impact = np.random.choice(["low", "medium", "high"], p=[0.6, 0.3, 0.1])
            
            # Calculate reward
            reward = self.calculate_reward(
                threat_neutralized,
                time_to_respond,
                false_positive,
                business_impact,
            )
            
            # Update Q-values
            self.update(scenario, action, reward)
            episode_reward += reward
        
        # Decay exploration rate
        self.exploration_rate = max(
            self.exploration_rate * self.decay_rate,
            self.min_exploration,
        )
        
        self.episodes += 1
        
        if self.episodes % 10 == 0:
            logger.info(
                f"Episode {self.episodes}: Avg reward = {episode_reward / len(scenarios):.2f}, "
                f"Exploration rate = {self.exploration_rate:.3f}"
            )
        
        return episode_reward

    def recommend_response(
        self,
        threat_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Get recommended response for a threat.
        
        Args:
            threat_info: Threat information dictionary.
        
        Returns:
            Recommendation with action, confidence, and reasoning.
        """
        state_key = self._get_state_key(threat_info)
        
        # Initialize if new state
        if state_key not in self.q_table:
            self.q_table[state_key] = {action: 0.0 for action in self.ACTIONS}
        
        # Get best action
        q_values = self.q_table[state_key]
        best_action = max(q_values, key=q_values.get)
        best_q = q_values[best_action]
        
        # Calculate confidence based on Q-value spread
        q_values_list = list(q_values.values())
        q_spread = max(q_values_list) - min(q_values_list)
        confidence = min(q_spread / 10.0, 1.0)  # Normalize to 0-1
        
        # Generate reasoning
        reasoning = self._generate_reasoning(best_action, threat_info)
        
        return {
            "recommended_action": best_action,
            "confidence": confidence,
            "reasoning": reasoning,
            "alternative_actions": self._get_alternatives(q_values, best_action),
            "state_key": state_key,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _generate_reasoning(
        self,
        action: str,
        threat_info: Dict[str, Any],
    ) -> str:
        """Generate human-readable reasoning for recommendation."""
        severity = threat_info.get("severity", "medium")
        category = threat_info.get("category", "unknown")
        
        reasoning_templates = {
            "monitor": f"Low-risk {category} threat. Continued monitoring recommended.",
            "alert": f"{severity.capitalize()} severity {category} detected. SOC notification advised.",
            "block_ip": f"Blocking source IP due to {category} activity with {severity} severity.",
            "isolate_host": f"Host isolation recommended for {severity} {category} containment.",
            "kill_process": f"Terminating malicious process associated with {category}.",
            "quarantine_file": f"Quarantining suspicious file linked to {category}.",
            "reset_credentials": f"Credential reset required due to {category} compromise.",
            "full_incident_response": f"Critical {category} threat requires full incident response.",
        }
        
        return reasoning_templates.get(action, f"Taking {action} for {category} threat.")

    def _get_alternatives(
        self,
        q_values: Dict[str, float],
        best_action: str,
        top_n: int = 2,
    ) -> List[Dict[str, Any]]:
        """Get alternative actions with their scores."""
        sorted_actions = sorted(q_values.items(), key=lambda x: x[1], reverse=True)
        
        alternatives = []
        for action, score in sorted_actions[1:top_n + 1]:
            if action != best_action:
                alternatives.append({
                    "action": action,
                    "score": score,
                    "relative_confidence": score / (q_values[best_action] + 1e-8),
                })
        
        return alternatives

    def get_statistics(self) -> Dict[str, Any]:
        """Get agent training statistics."""
        return {
            "episodes": self.episodes,
            "total_reward": self.total_reward,
            "average_reward": self.total_reward / max(self.episodes, 1),
            "exploration_rate": self.exploration_rate,
            "states_learned": len(self.q_table),
            "experience_buffer_size": len(self.experience_buffer),
        }

    def save(self, path: str) -> None:
        """Save agent to disk."""
        import pickle
        
        data = {
            "q_table": self.q_table,
            "exploration_rate": self.exploration_rate,
            "episodes": self.episodes,
            "total_reward": self.total_reward,
        }
        
        with open(path, "wb") as f:
            pickle.dump(data, f)
        
        logger.info(f"RL Agent saved to {path}")

    def load(self, path: str) -> None:
        """Load agent from disk."""
        import pickle
        
        with open(path, "rb") as f:
            data = pickle.load(f)
        
        self.q_table = data["q_table"]
        self.exploration_rate = data["exploration_rate"]
        self.episodes = data["episodes"]
        self.total_reward = data["total_reward"]
        
        logger.info(f"RL Agent loaded from {path}")
