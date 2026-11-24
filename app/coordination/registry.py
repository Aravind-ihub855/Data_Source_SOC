from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from app.coordination.context import ScenarioContext, build_scenario_context
from app.util import iso_now

@dataclass
class ScenarioDefinition:
    """
    Metadata specification for an individual security scenario.
    """
    scenario_id: str
    name: str
    category: str  # identity, endpoint, network, cloud, attack_chain, benign, data_quality
    classification: str  # malicious, benign, inconclusive, data_quality
    severity: str  # informational, low, medium, high, critical
    mitre_attack: Dict[str, str]  # tactic, technique_id, technique_name
    required_sources: List[str]
    expected_detections: List[str]
    description: str
    generator_fn: Optional[Callable[[ScenarioContext], List[Any]]] = None
    scenario_type: str = "baseline"
    label: str = "malicious"
    expected_verdict: str = "true_positive"
    last_run_timestamp: Optional[str] = None
    execution_count: int = 0

class ScenarioRegistry:
    """
    Central registry for all 20 security scenarios.
    Enforces strict lookup, prevents accidental fallback, and indexes MITRE mappings.
    """
    def __init__(self):
        self._scenarios: Dict[str, ScenarioDefinition] = {}

    def register(self, definition: ScenarioDefinition):
        self._scenarios[definition.scenario_id.upper()] = definition

    def get(self, scenario_id: str) -> ScenarioDefinition:
        sid = scenario_id.upper().strip()
        if sid not in self._scenarios:
            available = list(self._scenarios.keys())
            raise KeyError(
                f"Unknown scenario ID '{scenario_id}'. Must be one of the registered scenarios: {available}"
            )
        return self._scenarios[sid]

    def list_all(self) -> List[ScenarioDefinition]:
        return list(self._scenarios.values())

    def filter_by_category(self, category: str) -> List[ScenarioDefinition]:
        cat_lower = category.lower().strip()
        return [s for s in self._scenarios.values() if s.category.lower() == cat_lower]

    def execute_scenario(
        self,
        scenario_id: str,
        context: Optional[ScenarioContext] = None
    ) -> List[Any]:
        definition = self.get(scenario_id)
        ctx = context or build_scenario_context(scenario_id=definition.scenario_id)
        if not definition.generator_fn:
            raise NotImplementedError(f"No generator function bound to scenario {scenario_id}")
        
        events = definition.generator_fn(ctx)
        definition.last_run_timestamp = iso_now()
        definition.execution_count += 1
        return events

scenario_registry = ScenarioRegistry()
