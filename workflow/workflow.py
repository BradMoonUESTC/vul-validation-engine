import csv
import json
from agent.agent import Agent
from agent.checker_agent import CheckerAgent
from task.task import Task
from rag.constructor import query_similar_functions

class Workflow:
    def __init__(self, agents, tasks, contracts_dir, csv_file, checker_agent: CheckerAgent):
        self.agents = agents
        self.tasks = tasks
        self.contracts_dir = contracts_dir
        self.csv_file = csv_file
        self.checker_agent = checker_agent

    def run(self):
        results = []
        for task, agent in zip(self.tasks, self.agents):
            inputs = self.prepare_inputs()
            result = self.execute_recursive(task, agent, inputs)
            results.append(result)
        return results

    def execute_recursive(self, task, agent, inputs, depth=0):
        """
        递归执行任务，并根据结果进行多层次检查。
        """
        result = task.execute(agent, inputs)
        
        # 检查是否有未解决的问题
        if self.checker_agent.check_unresolved_steps(result):
            next_step = self.extract_next_step(result)
            if next_step:
                print(f"{'  ' * depth}深入检查: {next_step}")
                # 生成新的输入并递归执行下一步
                new_inputs = self.generate_next_inputs(next_step)
                return self.execute_recursive(task, agent, new_inputs, depth + 1)
            else:
                print(f"{'  ' * depth}未能找到下一步操作，返回上一级")
        else:
            print(f"{'  ' * depth}所有检查步骤已完成")

        return result

    def prepare_inputs(self):
        inputs = ""
        with open(self.csv_file, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.reader(csvfile)
            header = next(csvreader)
            for row in csvreader:
                code_entry, vulnerability_result, associated_code = row
                inputs += f"漏洞描述: {vulnerability_result}\n"
                inputs += f"代码入口: {code_entry}\n"
                inputs += f"对应代码:\n{associated_code}\n"
                break
        return inputs

    def extract_next_step(self, result):
        try:
            result_json = json.loads(result)
            for step, content in result_json.items():
                if "下一步" in content:
                    return content["下一步"]
        except Exception as e:
            print(f"Error extracting next step: {e}")
        return None

    def generate_next_inputs(self, step):
        keyword = step.split(":")[1].strip() if ":" in step else step
        similar_functions = query_similar_functions(keyword)
        inputs = f"针对关键步骤 '{step}' 的检查:\n"
        for func in similar_functions:
            inputs += f"合约名: {func['contract_name']}\n"
            inputs += f"函数名: {func['function_name']}\n"
            inputs += f"相似度: {func['similarity']:.4f}\n"
            inputs += f"代码内容:\n{func['content']}\n\n"
        return inputs
