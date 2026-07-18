from typing import List, Dict, Any
from module_8.models.output_models import SOARTask
from module_8.utils.helpers import generate_id

class SOARTaskGenerator:
    def generate_tasks(self, matched_rule: Dict[str, Any], status: str = "Prepared", seed: str = None) -> List[SOARTask]:
        tasks = []
        playbook_name = matched_rule.get("playbook_name", "Default Playbook")
        automation_level = matched_rule.get("execution_type", "Manual")
        actions = matched_rule.get("recommended_actions", [])
        
        previous_task_id = None
        for idx, action in enumerate(actions):
            task_seed = f"{seed}_{idx}" if seed else None
            task_id = generate_id("task", task_seed)
            prereqs = [previous_task_id] if previous_task_id else []
            
            task = SOARTask(
                task_id=task_id,
                playbook_name=playbook_name,
                automation_level=automation_level,
                prerequisites=prereqs,
                execution_status=status
            )
            tasks.append(task)
            previous_task_id = task_id
            
        return tasks
