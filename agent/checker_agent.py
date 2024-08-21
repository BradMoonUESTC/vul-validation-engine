import json
from util.openai_helper import OpenAIHelper

class CheckerAgent:
    def __init__(self, openai_helper: OpenAIHelper):
        self.openai_helper = openai_helper
    
    def check_unresolved_steps(self, result):
        """
        判断JSON中是否有未解决的问题，并返回一个布尔值。
        """
        try:
            prompt = f"""
            以下是漏洞确认过程的结果：
            {result}
            
            请检查该结果中是否包含任何未解决的问题。使用“确实包含未解决的问题”或“不包含未解决的问题”来回答，并提供简短的解释。
            """
            response = self.openai_helper.ask_openai_common(prompt)
            return "确实包含未解决的问题" in response
        except Exception as e:
            print(f"Error checking unresolved steps: {e}")
            return False
