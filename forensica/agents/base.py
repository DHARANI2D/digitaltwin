from abc import ABC, abstractmethod
from typing import Any

# Use TYPE_CHECKING to avoid circular imports if needed
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from state import DFIRState

class BaseAgent(ABC):
    """
    Abstract base class for all FORENSICA LangGraph agents.
    Ensures standard execution, error handling, and state mutation.
    """
    
    @abstractmethod
    def run(self, state: "DFIRState") -> "DFIRState":
        """
        Execute the agent's logic on the shared investigation state.
        Must return the mutated state.
        """
        pass
