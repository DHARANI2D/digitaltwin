# agents/risk_engine_agent.py

from .base import BaseAgent
from db_helper import DatabaseHelper

class RiskEngineAgent(BaseAgent):
    """
    Implements a Bayesian Belief Network simulation to compute a conditional 
    probability score given the evidence observed.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[RiskEngineAgent] Calculating Bayesian risk scores...")
        
        db = DatabaseHelper()
        
        # Bayesian Network nodes
        initial_access_present = False
        execution_present = False
        persistence_present = False
        c2_present = False

        factors = []

        # Analyze attack graph components
        kg = state.attack_graph.get("kill_chain", {})
        if kg:
            if len(kg.get("Initial Access", [])) > 0:
                initial_access_present = True
                factors.append({"factor": "Initial Access Vector Identified", "impact": "P(Compromise|Access) = 0.40"})
            if len(kg.get("Execution", [])) > 0:
                execution_present = True
                factors.append({"factor": "Script/Binary Execution Confirmed", "impact": "P(Compromise|Access,Exec) = 0.70"})
            if len(kg.get("Persistence", [])) > 0:
                persistence_present = True
                factors.append({"factor": "Persistence Mechanism Installed", "impact": "P(Compromise|Access,Exec,Persist) = 0.88"})
            if len(kg.get("Command and Control", [])) > 0:
                c2_present = True
                factors.append({"factor": "Outbound Command & Control Active", "impact": "P(Compromise|Access,Exec,C2) = 0.96"})

        # Calculate joint probability P(Compromise | E)
        # Using a conditional probability model:
        # P(Compromise) starts at 5% (prior)
        # We apply Bayesian updates using likelihood ratios for each phase.
        # Posterior = Prior * LR_access * LR_exec * LR_persist * LR_c2
        p_compromise = 0.05
        
        # Likelihood ratios: P(Evidence | Compromise) / P(Evidence | No Compromise)
        lr_access = 6.0 if initial_access_present else 1.0
        lr_exec = 4.0 if execution_present else 1.0
        lr_persist = 5.0 if persistence_present else 1.0
        lr_c2 = 12.0 if c2_present else 1.0

        # Calculate odds
        prior_odds = p_compromise / (1.0 - p_compromise)
        post_odds = prior_odds * lr_access * lr_exec * lr_persist * lr_c2
        p_compromise_post = post_odds / (1.0 + post_odds)

        # Convert to percentage
        risk_percentage = int(round(p_compromise_post * 100))
        risk_percentage = min(risk_percentage, 99) # limit to 99% for safety margin

        # If C2 and execution are both high-confidence, set to 98%
        if c2_present and execution_present:
            risk_percentage = max(risk_percentage, 96)

        state.risk_score = risk_percentage
        state.risk_factors = factors
        
        # Save case updates
        db.insert_case(state.case_id, state.evidence_path, risk_percentage)

        print(f"[RiskEngineAgent] Bayesian joint probability P(Compromise|Evidence) = {risk_percentage}%.")
        return state
