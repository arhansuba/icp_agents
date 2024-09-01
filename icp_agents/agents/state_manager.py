# state_manager.py

import json
import time
from enum import Enum
from threading import RLock
from collections import defaultdict
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field
from .logger import get_logger
from .exceptions import AgentStateError
from .utils import timestamp_now

# Initialize Logger
logger = get_logger(__name__)

class AgentStatus(Enum):
    INITIALIZING = 'initializing'
    ACTIVE = 'active'
    INACTIVE = 'inactive'
    TERMINATED = 'terminated'
    ERROR = 'error'

@dataclass
class Task:
    """Represents a task assigned to an agent."""
    task_id: str
    description: str
    status: str = 'pending'
    created_at: float = field(default_factory=timestamp_now)
    last_updated: float = field(default_factory=timestamp_now)

@dataclass
class AgentState:
    """Holds the current state of an agent."""
    agent_id: str
    status: AgentStatus = AgentStatus.INITIALIZING
    tasks: List[Task] = field(default_factory=list)
    cycle_balance: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_updated: float = field(default_factory=timestamp_now)

class StateManager:
    """
    Manages the state of agents in the system.
    Provides synchronization, state persistence, and fault tolerance mechanisms.
    """
    def __init__(self):
        self._states: Dict[str, AgentState] = {}
        self._lock = RLock()
        self._state_history: Dict[str, List[Dict]] = defaultdict(list)
        logger.info("StateManager initialized")

    def register_agent(self, agent_id: str, metadata: Optional[Dict[str, Any]] = None) -> AgentState:
        """
        Registers a new agent into the state manager.
        """
        with self._lock:
            if agent_id in self._states:
                raise AgentStateError(f"Agent {agent_id} is already registered.")
            
            metadata = metadata or {}
            new_state = AgentState(agent_id=agent_id, status=AgentStatus.INITIALIZING, metadata=metadata)
            self._states[agent_id] = new_state
            logger.info(f"Agent {agent_id} registered with state: {new_state}")
            self._record_state_history(agent_id)
            return new_state

    def update_agent_status(self, agent_id: str, new_status: AgentStatus):
        """
        Updates the status of the agent.
        """
        with self._lock:
            self._validate_agent(agent_id)
            self._states[agent_id].status = new_status
            self._states[agent_id].last_updated = timestamp_now()
            logger.info(f"Agent {agent_id} status updated to {new_status}")
            self._record_state_history(agent_id)

    def add_task_to_agent(self, agent_id: str, task: Task):
        """
        Adds a new task to the agent's task list.
        """
        with self._lock:
            self._validate_agent(agent_id)
            self._states[agent_id].tasks.append(task)
            self._states[agent_id].last_updated = timestamp_now()
            logger.info(f"Task {task.task_id} added to agent {agent_id}")
            self._record_state_history(agent_id)

    def update_task_status(self, agent_id: str, task_id: str, new_status: str):
        """
        Updates the status of a specific task for a given agent.
        """
        with self._lock:
            self._validate_agent(agent_id)
            tasks = self._states[agent_id].tasks
            for task in tasks:
                if task.task_id == task_id:
                    task.status = new_status
                    task.last_updated = timestamp_now()
                    logger.info(f"Task {task_id} on agent {agent_id} updated to {new_status}")
                    self._record_state_history(agent_id)
                    return
            raise AgentStateError(f"Task {task_id} not found on agent {agent_id}")

    def adjust_cycle_balance(self, agent_id: str, amount: float):
        """
        Adjusts the cycle balance of the agent.
        """
        with self._lock:
            self._validate_agent(agent_id)
            self._states[agent_id].cycle_balance += amount
            self._states[agent_id].last_updated = timestamp_now()
            logger.info(f"Agent {agent_id} cycle balance adjusted by {amount}. New balance: {self._states[agent_id].cycle_balance}")
            self._record_state_history(agent_id)

    def get_agent_state(self, agent_id: str) -> AgentState:
        """
        Returns the current state of the agent.
        """
        with self._lock:
            self._validate_agent(agent_id)
            return self._states[agent_id]

    def terminate_agent(self, agent_id: str):
        """
        Terminates the agent, marking its state as TERMINATED and clearing tasks.
        """
        with self._lock:
            self._validate_agent(agent_id)
            self._states[agent_id].status = AgentStatus.TERMINATED
            self._states[agent_id].tasks.clear()
            self._states[agent_id].last_updated = timestamp_now()
            logger.info(f"Agent {agent_id} terminated")
            self._record_state_history(agent_id)

    def _validate_agent(self, agent_id: str):
        """
        Validates if the agent exists.
        """
        if agent_id not in self._states:
            raise AgentStateError(f"Agent {agent_id} not found.")

    def _record_state_history(self, agent_id: str):
        """
        Records the state change for the agent in the history log.
        """
        agent_state = self._states[agent_id]
        state_snapshot = {
            'status': agent_state.status.value,
            'tasks': [t.__dict__ for t in agent_state.tasks],
            'cycle_balance': agent_state.cycle_balance,
            'metadata': agent_state.metadata,
            'last_updated': agent_state.last_updated
        }
        self._state_history[agent_id].append(state_snapshot)

    def get_state_history(self, agent_id: str) -> List[Dict]:
        """
        Returns the history of state changes for the agent.
        """
        with self._lock:
            self._validate_agent(agent_id)
            return self._state_history[agent_id]

    def persist_state(self, file_path: str):
        """
        Persists the current state of all agents to a file.
        """
        with self._lock:
            with open(file_path, 'w') as f:
                json.dump({agent_id: state.__dict__ for agent_id, state in self._states.items()}, f, indent=4)
            logger.info(f"All agent states persisted to {file_path}")

    def load_state(self, file_path: str):
        """
        Loads agent states from a persisted file.
        """
        with self._lock:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    for agent_id, state_dict in data.items():
                        state = AgentState(**state_dict)
                        self._states[agent_id] = state
                        logger.info(f"Agent {agent_id} state restored from {file_path}")
            except Exception as e:
                raise AgentStateError(f"Failed to load agent states: {e}")
