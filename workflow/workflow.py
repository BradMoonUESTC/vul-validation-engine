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
            return data
        elif isinstance(data, dict):
            return json.dumps(data, ensure_ascii=False)
        elif isinstance(data, list):
            return json.dumps(data, ensure_ascii=False)
        else:
            return str(data)

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
                    traceback.print_exc()
                    continue
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
            print(f"Problematic JSON: {initial_result[:1000]}...")
            raise

        final_result = {"漏洞描述": row['漏洞结果'], "漏洞": None, "检查步骤": []}
        self.execute_steps(steps, final_result, hash_value)
        return final_result

    def execute_steps(self, steps, final_result, hash_value, depth=0):
        if depth >= self.max_depth:
            print(f"Reached maximum depth of {self.max_depth}. Considering as confirmed vulnerability.")
            self.log_to_csv("Max Depth Reached", "", f"Depth: {depth}, Confirmed vulnerability", hash_value)
            final_result["漏洞"] = True
            return

        for step_name, step_data in steps.items():
            print(f"\n----- Executing step: {step_name} (Depth: {depth}) -----")
            print(f"Step data:\n{json.dumps(step_data, indent=2, ensure_ascii=False)}")
            self.log_to_csv(f"Step Data: {step_name}", json.dumps(step_data, ensure_ascii=False), "", hash_value)
            
            if not isinstance(step_data, dict):
                print(f"Warning: Invalid step data type for {step_name}. Considering as confirmed vulnerability.")
                final_result["漏洞"] = True
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
            elif step_result["检查结果"] == "确认漏洞存在":
                final_result["漏洞"] = True
                print("Vulnerability confirmed. Stopping execution.")
                self.log_to_csv("Execution Result", "", "Vulnerability confirmed", hash_value)
                return
            elif step_result["检查结果"] == "需要继续检查":
                if "内部检查结论" in step_result and step_result["内部检查结论"]:
                    print("Internal check performed. Logging result.")
                    self.log_to_csv("Internal Check Result", "", step_result["内部检查结论"], hash_value)
                
                next_step = step_data.get("检查结果", {}).get("后续操作", {}).get("如果需要继续检查", {}).get("下一步")
                if next_step and next_step in steps:
                    print(f"Continuing to next step: {next_step}")
                    self.log_to_csv("Continue to Next Step", json.dumps(steps[next_step], ensure_ascii=False), "", hash_value)
                    self.execute_steps({next_step: steps[next_step]}, final_result, hash_value, depth + 1)
                else:
                    print("All checks completed. Confirming vulnerability.")
                    self.log_to_csv("All Checks Completed", "", "Confirming vulnerability", hash_value)
                    final_result["漏洞"] = True
                    return
            else:
                raise ValueError(f"Invalid check result: {step_result['检查结果']}")

        # 如果所有步骤都执行完毕但没有明确结论，视为确认漏洞
        if final_result["漏洞"] is None:
            final_result["漏洞"] = True
            print("All steps completed without a clear conclusion. Confirming vulnerability.")
            self.log_to_csv("Execution Result", "", "Confirmed vulnerability - all steps completed", hash_value)

    def generate_and_check_inner_steps(self, step_result, hash_value):
        prompt = f"""

        上一步步骤描述: {step_result['步骤描述']}\n
        上一步检查结果: {step_result['检查结果']}\n
        上一步详细信息: {step_result['详细结果']}\n
        上一步相关代码：{json.dumps(step_result['相关代码'], ensure_ascii=False)}
        内部检查理由:{step_result['内部检查理由']}\n
        内部检查目标:{step_result['内部检查目标']}\n 
        """
        print(f"Generate inner steps prompt:\n{prompt}")
        self.log_to_csv("Generate Inner Steps Prompt", prompt, "", hash_value)
        result=self.check_inner_step(prompt,hash_value)
        return result
    def check_inner_step(self, inner_prompt,hash_value):
        # 根据inner prompt，到全局代码中提问，获取结果，返回
        query_res = query_similar_functions(inner_prompt, top_k=5)
        relevant_code = [x['content'] for x in query_res if x['similarity'] > 0.01]
        print(f"Relevant code:\n{json.dumps(relevant_code, indent=2, ensure_ascii=False)}")
        self.log_to_csv("Relevant Code", inner_prompt, json.dumps(relevant_code, ensure_ascii=False), hash_value)
        prompt=inner_prompt+"要检查的代码为\n"+"\n".join(relevant_code)

        print(f"Inner step prompt:\n{prompt}")
        self.log_to_csv("Inner Step Prompt", prompt, "", hash_value)
        result=self.agents[1].perform_task("基于内部检查理由和内部检查目标检查整个代码，获得一个结论", prompt, use_json=False)
        return result
    def check(self, step, hash_value):
        if not isinstance(step, dict):
            print(f"Warning: Invalid step data type. Expected dict, got {type(step)}")
            return {
                "步骤描述": "Invalid step data",
                "检查结果": "需要继续检查",
                "详细结果": "Step data is not in the expected format",
                "相关代码": []
            }

        query_res = query_similar_functions(step.get("检查目标", ""), top_k=5)
        relevant_code = [x['content'] for x in query_res if x['similarity'] > 0.01]
        print(f"Relevant code:\n{json.dumps(relevant_code, indent=2, ensure_ascii=False)}")
        self.log_to_csv("Relevant Code", step.get("检查目标", ""), json.dumps(relevant_code, ensure_ascii=False), hash_value)

        prompt = f"""
        检查描述: {step.get('检查描述', '')}
        检查目标: {step.get('检查目标', '')}
        具体检查步骤: {step.get('具体检查步骤', '')}
        检查关键点: {step.get('检查关键点', '')}
        检查结论参考: 
        {json.dumps(step.get('检查结论参考', {}), ensure_ascii=False, indent=2)}
        
        相关代码:
        {json.dumps(relevant_code, ensure_ascii=False)}
        
        基于检查相关的描述、目标、步骤、关键点和结论参考，判断此代码是否满足检查目标和检查步骤以及检查结论参考的要求。
        注意，仅返回面对检查相关信息的结果，不要有任何其它主观附加的建议。
        
        必须严格按照以下 JSON 格式返回结果，使用键名：
        {{
        "检查结果": {{
            "结果类型": "需要继续检查" / "确认漏洞存在" / "确认为误报",
            "结果说明": "详细解释得出此结论的原因，包括相关的代码分析证据",
        }}
        }}
        请确保完全使用中文输出，包括 JSON 的键名。
        """
        print(f"Check prompt:\n{prompt}")
        self.log_to_csv("Check Prompt", prompt, "", hash_value)

        result = self.agents[1].perform_task("判断代码是否满足要求", prompt, use_json=True)
        print(f"Check result:\n{result}")
        self.log_to_csv("Check Result", "", result, hash_value)
        result = json.loads(result)

        inner_check_conclusion = None
        if result["检查结果"]["结果类型"] == "需要继续检查":
            inner_check_prompt = f"""
            基于以下信息：

            初始检查信息：
            检查描述: {step.get('检查描述', '')}
            检查目标: {step.get('检查目标', '')}
            具体检查步骤: {step.get('具体检查步骤', '')}
            检查关键点: {step.get('检查关键点', '')}

            检查结果：
            结果类型: {result["检查结果"]["结果类型"]}
            结果说明: {result["检查结果"]["结果说明"]}

            相关代码:
            {json.dumps(relevant_code, ensure_ascii=False)}

            基于这个结果判断，单就代码而言是否能够得出准确结论，是否需要再去看更内部的代码逻辑进行检查，并返回json 是或否

            请以以下格式返回结果：
            {{
            "需要内部检查": "是" / "否",
            "理由": "详细解释为什么需要或不需要内部检查"
            "内部检查目标":"具体的目标描述"/"不需要内部检查"
            }}
            """
            print(f"Inner check prompt:\n{inner_check_prompt}")
            inner_check_result = self.agents[1].perform_task("判断是否需要内部检查", inner_check_prompt, use_json=True)
            
            inner_check_result = json.loads(inner_check_result)
            print(f"Inner check result:\n{inner_check_result}")
            if inner_check_result["需要内部检查"] == "是":
                inner_steps_conclusion = self.generate_and_check_inner_steps({
                    "检查结果": "需要内部检查",
                    "详细结果": result["检查结果"]["结果说明"],
                    "相关代码": relevant_code,
                    "内部检查理由": inner_check_result["理由"],
                    "内部检查目标": inner_check_result["内部检查目标"],
                    "步骤描述": step.get('检查描述', ''),
                }, hash_value)
                inner_check_conclusion = self.check_inner_step(inner_steps_conclusion, hash_value)

        return {
            "检查结果": result["检查结果"]["结果类型"],
            "详细结果": result["检查结果"]["结果说明"],
            "相关代码": relevant_code,
            "内部检查结论": inner_check_conclusion
        }


    def log_final_result(self, row, result, hash_value):
        is_false_positive = "是" if not result["漏洞"] else "否"
        summary = f"漏洞ID: {row.get('id', 'Unknown')}, 是否误报: {is_false_positive}, 最终结论: {'误报' if not result['漏洞'] else '真实漏洞'}"
        self.log_to_csv("Final Result", json.dumps(row, ensure_ascii=False), summary, hash_value)
        print(f"Final result: {summary}")