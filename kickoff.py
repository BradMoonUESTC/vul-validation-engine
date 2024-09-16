from graph_of_thoughts import controller, language_models, operations
from typing import Dict, List
import os
import json
import logging

# 设置环境变量
os.environ["OPENAI_API_KEY"] = "sk-hQfski4aO06WQD0jF442Da78D4Ef4f758c678aC095Dc0a9b"
os.environ["OPENAI_API_BASE"] = "https://apix.ai-gaochao.cn/v1"

print("环境变量设置完成")

class VulnerabilityPrompter(operations.Prompter):
    def generate_prompt(self, **kwargs) -> str:
        print(f"生成初始 prompt，参数：{kwargs}")
        prompt = """
        这个漏洞结果可能是一个误报，但是由于上下文不全无法得出结论，现在我想让你给出一个完整的漏洞验证流程，你的任务如下：

        1. 根据这个漏洞结果整理出：确认漏洞是否真实存在时所需要的代码层面的确认步骤。
        2. 基于确认步骤，需要根据确认结果进行什么样的的分支决策。
        3. 漏洞验证流程应该是一个树状图或树状结构，每个步骤都应该有明确的后续行动。
        4. 你输出的漏洞验证流程应仅基于代码判断，而不应该依赖运行时状态进行判断。
        5. 注意，你的漏洞验证流程输出必须要详细，准确性高，可操作性必须非常强，不能有任何的模糊性词语和形容词。
        6. 输出一个决策树状图，这个决策树用来验证给定的漏洞是否存在，以JSON形式输出。
          - 决策树状图JSON必须详细，每个描述都要包含具体进行怎样的检查操作。
        7. 你必须输出可操作性非常强的漏洞验证流程，并明确【检查描述】【检查目标】【具体检查步骤】【检查关键点】【检查结论参考】，保证任何实体都可以使用你的漏洞验证流程而不需要猜测，任何形容词和任何动词都必须有相应的充分解释如"正确"，"错误"，"评估"。
        8. 步骤数量至少要5条，但不要被5所限制，无上限。
        9. 用中文输出，必须包含所有JSON要求的格式。

        漏洞信息：{vulnerability_info}
        """
        print(f"生成的 prompt：\n{prompt}")
        return prompt

    def improve_prompt(self, **kwargs) -> str:
        print(f"生成改进 prompt，参数：{kwargs}")
        prompt = """
        请根据以下反馈改进你的漏洞验证流程：

        当前验证流程：{current_process}
        反馈：{feedback}

        请提供改进后的验证流程，保持原有的JSON格式。
        """
        print(f"生成的改进 prompt：\n{prompt}")
        return prompt

class VulnerabilityParser(operations.Parser):
    def parse_generate_answer(self, state: Dict, texts: List[str]) -> List[Dict]:
        print(f"解析生成的答案，状态：{state}")
        parsed = [json.loads(text) for text in texts]
        print(f"解析结果：{parsed}")
        return parsed

    def parse_improve_answer(self, state: Dict, texts: List[str]) -> Dict:
        print(f"解析改进的答案，状态：{state}")
        parsed = json.loads(texts[0])
        print(f"解析结果：{parsed}")
        return parsed

def vulnerability_score(verification_process):
    print(f"评分函数被调用，验证流程：{verification_process}")
    score = 0.8  # 这里应该实现一个真正的评分函数
    print(f"评分结果：{score}")
    return score

def validate_vulnerability(verification_process):
    print(f"验证函数被调用，验证流程：{verification_process}")
    result = True  # 这里应该实现一个真正的验证函数
    print(f"验证结果：{result}")
    return result

def vulnerability_got() -> operations.GraphOfOperations:
    print("创建漏洞分析的操作图")
    operations_graph = operations.GraphOfOperations()
    
    print("添加 Generate 操作")
    operations_graph.append_operation(operations.Generate(1, 1))
    print("添加 Score 操作")
    operations_graph.append_operation(operations.Score(1, False, vulnerability_score))
    
    print("添加 Improve 操作")
    improve = operations.Improve()
    operations_graph.append_operation(improve)
    
    print("添加第二次 Score 操作")
    operations_graph.append_operation(operations.Score(1, False, vulnerability_score))
    print("添加 KeepBestN 操作")
    operations_graph.append_operation(operations.KeepBestN(1, False))
    
    print("添加 GroundTruth 操作")
    operations_graph.append_operation(operations.GroundTruth(validate_vulnerability))
    
    print("操作图创建完成")
    return operations_graph

def run_vulnerability_analysis(vulnerability_info: str):
    print(f"开始运行漏洞分析，漏洞信息：{vulnerability_info}")
    
    print("初始化语言模型")
    lm = language_models.ChatGPT(
        os.path.join(os.path.dirname(__file__), "config.json"),
        model_name="chatgpt",
        cache=True,
    )
    
    print("创建操作图")
    operations_graph = vulnerability_got()
    
    print("初始化控制器")
    executor = controller.Controller(
        lm,
        operations_graph,
        VulnerabilityPrompter(),
        VulnerabilityParser(),
        {
            "vulnerability_info": vulnerability_info,
            "current": "",
            "phase": 0,
        },
    )
    
    print("开始执行")
    executor.run()
    
    print("执行完成，返回结果")
    return executor.output_result()

if __name__ == "__main__":
    print("程序开始执行")
    logging.basicConfig(level=logging.INFO)
    
    vulnerability_info = "可能存在SQL注入漏洞的函数：def get_user(user_id): cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    print(f"漏洞信息：{vulnerability_info}")
    
    print("开始漏洞分析")
    result = run_vulnerability_analysis(vulnerability_info)
    
    print("漏洞分析完成")
    logging.info("Vulnerability analysis result:")
    logging.info(json.dumps(result, indent=2, ensure_ascii=False))
    
    print("程序执行结束")