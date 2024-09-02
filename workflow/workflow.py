import json
import csv
import hashlib
import traceback
from datetime import datetime
from rag.constructor import query_similar_functions
from task.task import Task

class Workflow:
    def __init__(self, agents, tasks, csv_data, checker_agent, max_depth=3):
        self.agents = agents
        self.tasks = tasks
        self.csv_data = csv_data
        self.checker_agent = checker_agent
        self.log_file = f"workflow_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.initialize_log_file()
        self.max_depth = max_depth

    def initialize_log_file(self):
        with open(self.log_file, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Hash", "Step", "Input", "Output"])

    def log_to_csv(self, step, input_data, output_data, hash_value):
        with open(self.log_file, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                hash_value,
                step,
                self.encode_unicode(input_data),
                self.encode_unicode(output_data)
            ])

    def encode_unicode(self, data):
        if isinstance(data, str):
            return data  # 直接返回原始字符串，不进行 Unicode 转义
        elif isinstance(data, dict):
            return json.dumps(data, ensure_ascii=False)  # 使用 json.dumps 并设置 ensure_ascii=False
        elif isinstance(data, list):
            return json.dumps(data, ensure_ascii=False)  # 同上
        else:
            return str(data)  # 对于其他类型，转换为字符串

    def generate_hash(self, data):
        return hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def run(self):
        results = []
        for task in self.tasks:
            for row in self.csv_data:
                try:
                    hash_value = self.generate_hash(row)
                    result = self.execute_task(task, row, hash_value)
                    results.append(result)
                    self.log_final_result(row, result, hash_value)
                except Exception as e:
                    error_message = f"Error processing vulnerability ID {row.get('id', 'Unknown')}: {str(e)}"
                    print(error_message)
                    self.log_to_csv("Error", json.dumps(row), error_message, self.generate_hash(row))
                    traceback.print_exc()  # 打印详细的错误堆栈
                    continue  # 跳过这个漏洞，继续下一个
        return results

    def execute_task(self, task: Task, row, hash_value):
        print(f"\n===== Executing task for row: {row} =====")
        try:
            initial_result = task.execute(self.agents[0], json.dumps(row))
            print(f"Initial result:\n{initial_result}")
            self.log_to_csv("Initial Task Execution", json.dumps(row), initial_result, hash_value)
            steps = json.loads(initial_result)
        except json.JSONDecodeError as json_error:
            print(f"JSON Decode Error: {json_error}")
            print(f"Problematic JSON: {initial_result[:1000]}...")  # 打印前1000个字符用于调试
            raise  # 重新抛出异常，让上层的 run 方法捕获

        final_result = {"漏洞描述": row['漏洞结果'], "漏洞": True, "检查步骤": []}
        self.execute_steps(steps, final_result, hash_value)
        return final_result

    def execute_steps(self, steps, final_result, hash_value, depth=0):
        if depth >= self.max_depth:
            print(f"Reached maximum depth of {self.max_depth}. Considering as potential vulnerability.")
            self.log_to_csv("Max Depth Reached", "", f"Depth: {depth}, Potential vulnerability", hash_value)
            final_result["漏洞"] = True  # 达到最大深度时，视为潜在漏洞
            return

        for step_name, step_data in steps.items():
            print(f"\n----- Executing step: {step_name} (Depth: {depth}) -----")
            print(f"Step data:\n{json.dumps(step_data, indent=2, ensure_ascii=False)}")
            self.log_to_csv(f"Step Data: {step_name}", json.dumps(step_data, ensure_ascii=False), "", hash_value)
            
            if not isinstance(step_data, dict):
                print(f"Warning: Invalid step data type for {step_name}. Considering as potential vulnerability.")
                final_result["漏洞"] = True  # 如果步骤数据无效，视为潜在漏洞
                continue

            step_result = self.check(step_data, hash_value)
            final_result["检查步骤"].append(step_result)
            print(f"Step result:\n{json.dumps(step_result, indent=2, ensure_ascii=False)}")
            self.log_to_csv(f"Step Result: {step_name}", "", json.dumps(step_result, ensure_ascii=False), hash_value)

            if step_result["检查结果"] == "确认为误报":
                final_result["漏洞"] = False
                print("Confirmed as false positive. Stopping execution.")
                self.log_to_csv("Execution Result", "", "Confirmed as false positive", hash_value)
                return
            elif step_result["检查结果"] == "需要进行更深入的内层检查" and depth < self.max_depth:
                print("Generating inner steps for deeper check...")
                inner_steps = self.generate_inner_steps(step_result, hash_value)
                print(f"Generated inner steps:\n{json.dumps(inner_steps, indent=2, ensure_ascii=False)}")
                self.log_to_csv("Generated Inner Steps", json.dumps(step_result, ensure_ascii=False), json.dumps(inner_steps, ensure_ascii=False), hash_value)
                self.execute_steps(inner_steps, final_result, hash_value, depth + 1)
            elif step_result["检查结果"] == "需要继续检查":
                next_steps = step_data.get("需要继续检查")
                if isinstance(next_steps, dict):
                    print("Continuing to next steps...")
                    self.log_to_csv("Continue to Next Steps", json.dumps(step_data, ensure_ascii=False), "", hash_value)
                    self.execute_steps(next_steps, final_result, hash_value, depth)
                else:
                    print(f"Next step suggestion: {next_steps}")
                    self.log_to_csv("Next Step Suggestion", "", str(next_steps), hash_value)
            else:
                raise ValueError(f"Invalid check result: {step_result['检查结果']}")
                # final_result["漏洞"] = True
                # print("Vulnerability confirmed. Stopping execution.")
                # self.log_to_csv("Execution Result", "", "Vulnerability confirmed", hash_value)
                # return

        # 如果所有步骤都执行完毕，但没有明确结论，则视为潜在漏洞
        # if final_result["漏洞"] is False:
        #     final_result["漏洞"] = True
        #     print("All steps completed without confirming false positive. Considering as potential vulnerability.")
        #     self.log_to_csv("Execution Result", "", "Potential vulnerability - no clear false positive confirmation", hash_value)

    def generate_inner_steps(self, step_result, hash_value):
        prompt = f"""
        基于以下信息，生成更深入的内层检查步骤：

        上一步步骤描述: {step_result['步骤描述']}\n
        上一步检查结果: {step_result['检查结果']}\n
        上一步详细信息: {step_result['详细结果']}\n
        上一步相关代码：{json.dumps(step_result['相关代码'], ensure_ascii=False)}
        
        注意：生成的步骤不应包含"需要进行更深入的内层检查"选项，以避免无限循环。
        请确保生成的步骤能够得出明确的结论（"确认为误报"或"需要继续检查"）。

        {{"步骤N": {{
            "检查描述（不少于200个字）": "",
            "检查目标（不少于200个字）":"",
            "具体检查步骤（不少于200个字）":"",
            "检查关键点（不少于200个字）":"",
            "检查结论参考（不少于200个字）":"",
            "需要继续检查": {{
                "步骤N+1": {{
                    "检查描述（不少于200个字）": "",
                    "检查目标（不少于200个字）":"",
                    "具体检查步骤（不少于200个字）":"",
                    "检查关键点（不少于200个字）":"",
                    "检查结论参考（不少于200个字）":"",
                    "需要继续检查": {{
                        "...": "可能的后续步骤"
                    }},
                    "确认为误报": {{
                        "结果": "确认为误报"
                    }}
                }}
            }},
            "确认为误报": {{
                "结果": "确认为误报"
            }}
        }}}}

        输出格式使用json格式，用中文输出
        """
        print(f"Generate inner steps prompt:\n{prompt}")
        self.log_to_csv("Generate Inner Steps Prompt", prompt, "", hash_value)
        inner_steps_json = self.agents[0].perform_task("生成内层检查步骤", prompt, use_json=True)
        print(f"Generated inner steps JSON:\n{inner_steps_json}")
        self.log_to_csv("Generated Inner Steps JSON", "", inner_steps_json, hash_value)
        return json.loads(inner_steps_json)

    def check(self, step, hash_value):
        if not isinstance(step, dict):
            print(f"Warning: Invalid step data type. Expected dict, got {type(step)}")
            return {
                "步骤描述": "Invalid step data",
                "检查结果": "需要继续检查",
                "详细结果": "Step data is not in the expected format",
                "相关代码": []
            }

        query_res = query_similar_functions(step.get("检查目标（不少于200个字）", ""), top_k=5)
        relevant_code = [x['content'] for x in query_res if x['similarity'] > 0.01]
        print(f"Relevant code:\n{json.dumps(relevant_code, indent=2, ensure_ascii=False)}")
        self.log_to_csv("Relevant Code", step.get("检查目标（不少于200个字）", ""), json.dumps(relevant_code, ensure_ascii=False), hash_value)

        prompt = f"""
        检查描述: {step.get('检查描述（不少于200个字）', '')}
        检查目标: {step.get('检查目标（不少于200个字）', '')}
        检查步骤: {step.get('具体检查步骤（不少于200个字）', '')}
        检查关键点: {step.get('检查关键点（不少于200个字）', '')}
        检查结论参考: {step.get('检查结论参考（不少于200个字）', '')}
        
        相关代码:
        {json.dumps(relevant_code, ensure_ascii=False)}
        """
        prompt += """
        基于检查相关的描述、目标、步骤、关键点和结论参考，判断此代码是否满足检查目标和检查步骤的要求。
        注意，仅返回面对检查相关信息的结果，不要有任何其它主观附加的建议。
        注意，检查结果必须是"确认为误报"、"需要继续检查"或"需要进行更深入的内层检查"之一，不能是其它任何结果。
        必须严格按照以下 JSON 格式返回结果，使用中文键名：
        {
            "检查结果": "需要继续检查" / "确认为误报" / "需要进行更深入的内层检查",
            "详细结果": "详细解释检查结果的原因，不少于200个字"
        }
        请确保完全使用中文输出，包括 JSON 的键名。
        """
        print(f"Check prompt:\n{prompt}")
        self.log_to_csv("Check Prompt", prompt, "", hash_value)

        result = self.agents[1].perform_task("判断代码是否满足要求", prompt, use_json=True)
        print(f"Check result:\n{result}")
        self.log_to_csv("Check Result", "", result, hash_value)
        result = json.loads(result)
        return {
            "步骤描述": step.get('检查描述（不少于200个字）', "Missing description"),
            "检查结果": result["检查结果"],
            "详细结果": result["详细结果"],
            "相关代码": relevant_code
        }

    def log_final_result(self, row, result, hash_value):
        is_false_positive = "是" if not result["漏洞"] else "否"
        summary = f"漏洞ID: {row.get('id', 'Unknown')}, 是否误报: {is_false_positive}, 最终结论: {'误报' if not result['漏洞'] else '真实漏洞'}"
        self.log_to_csv("Final Result", json.dumps(row, ensure_ascii=False), summary, hash_value)
        print(f"Final result: {summary}")