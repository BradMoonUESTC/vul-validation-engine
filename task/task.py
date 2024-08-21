from agent.agent import Agent
class Task:
    def __init__(self, description, expected_output):
        self.description = description
        self.expected_output = expected_output

    def execute(self, agent:Agent, inputs, use_json=True):
        print(f"任务描述: {self.description}")
        result = agent.perform_task(self.description, inputs, use_json)
        return result
