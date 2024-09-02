from agent.agent import Agent
from agent.checker_agent import CheckerAgent
from task.task import Task
from util.openai_helper import OpenAIHelper
from workflow.workflow import Workflow
import csv

if __name__ == "__main__":

    # 初始化 OpenAI 帮助类
    # api_key = "sk-d3i9QpUjDpMo7Qt1C6764388Eb784f7c94D70c904f121435"
    api_key = "sk-hQfski4aO06WQD0jF442Da78D4Ef4f758c678aC095Dc0a9b"
    api_base="apix.ai-gaochao.cn"
    openai_helper = OpenAIHelper(api_key,api_base)

    # 定义基准任务Prompt
    BASE_PROMPT = """
    这个漏洞结果可能是一个误报，但是由于上下文不全无法得出结论，现在我想让你给出一个完整的误报确认流程，你的任务如下：
    1. 根据这个漏洞结果整理出：确认漏洞是否真实存在（漏洞是否为误报）时所需要的代码层面的确认步骤  
    2. 基于确认步骤，需要根据确认结果进行什么样的的分支决策，
    3. 误报确认流程应该是一个树状图或树状结构，如当步骤1满足时，则进行步骤2，否则为误报，步骤2满足时，则进行步骤3，否则为误报   
    4. 你输出的误报确认流程应仅基于代码判断，而不应该依赖状态进行判断。
    5. 注意，你的误报确认流程输出必须要详细，准确性高，可操作性必须非常强，否则你会受到惩罚，不能有任何的模糊性词语和形容词
    6. 输出一个决策树状图来，这个决策树应仅用来确认我给你的漏洞是否存在，以json形式输出
        1. 决策树状图json必须详细，每个描述都要包含具体进行怎样的检查操作
    7. 你必须输出可操作性非常强的误报确认流程，并明确【检查描述（不少于200个字）】【检查目标（不少于200个字）】【具体检查步骤（不少于200个字）】【检查关键点（不少于200个字）】【检查结论参考（不少于200个字）】，保证任何实体都可以使用你的误报确认流程而不需要猜测，任何形容词和任何动词都必须有相应的充分解释如”正确“，”错误“,”评估“
    8. 步骤数量至少要5条，但不要被5所限制，无上限
    9. 用中文输出，必须包含所有json要求的格式
    10. json格式如下：{
      "步骤N": {
        "检查描述（不少于200个字）": "",
        "检查目标（不少于200个字）":"",
        "具体检查步骤（不少于200个字）":"",
        "检查关键点（不少于200个字）":"",
        "检查结论参考（不少于200个字）":"",
        "需要继续检查": {
          "步骤N+1": {
            "检查描述（不少于200个字）": "",
            "检查目标（不少于200个字）":"",
            "具体检查步骤（不少于200个字）":"",
            "检查关键点（不少于200个字）":"",
            "检查结论参考（不少于200个字）":"",
            "需要继续检查": {
              "...": "可能的后续步骤"
            },
            "确认为误报": {
              "结果": "确认为误报"
            }
          }
        },
        "确认为误报": {
          "结果": "确认为误报"
        }
      }
    }
    11. 每个描述不应少于200个字，每个具体操作不应少于200个字
    """
    print("创建角色与任务")
    # 创建角色与任务
    analyzer = Agent(role="Analyzer", goal="生成详细的漏洞确认流程", openai_helper=openai_helper)
    investigator = Agent(role="Investigator", goal="根据确认流程检查漏洞是否存在", openai_helper=openai_helper)
    print("定义task，生成确认流程")
    # 基于漏洞信息生成误报确认流程
    base_task = Task(description=BASE_PROMPT, expected_output="详细的JSON格式的确认流程")
    
    # 读取CSV文件
    def read_csv(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)

    # 初始化工作流
    csv_data = read_csv("vul_result.csv")
    workflow = Workflow(agents=[analyzer, investigator], tasks=[base_task], csv_data=csv_data, checker_agent=CheckerAgent(openai_helper))

    # 执行工作流并打印结果
    final_results = workflow.run()

    # 输出最终结果
    for i, result in enumerate(final_results):
        print(f"\n步骤 {i+1} 的结果:\n{result}")