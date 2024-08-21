from util.openai_helper import OpenAIHelper

class Agent:
    def __init__(self, role, goal, openai_helper: OpenAIHelper):
        self.role = role
        self.goal = goal
        self.openai_helper = openai_helper

    def perform_task(self, task_description, inputs, use_json=True):
        # 生成OpenAI API的提示
        prompt = f"Role: {self.role}\nGoal: {self.goal}\nTask: {task_description}\nInput: {inputs}"
        
        if use_json:
            result = self.openai_helper.ask_openai_for_json(prompt)
        else:
            result = self.openai_helper.ask_openai_common(prompt)

        return result
