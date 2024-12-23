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
    10. JSON格式如下：
    {
  "步骤1": {
    "检查描述": "",
    "检查目标": "",
    "具体检查步骤": "",
    "检查关键点": "",
    "检查结论参考": {
      "判断标准(具体到代码)": {
        "需要继续检查的条件": "",
        "确认漏洞存在的条件": "",
        "确认为误报的条件": ""
      }
    },
    "检查结果后续操作": {
      "如果需要继续检查": {
        "下一步": "步骤2"
      },
      "如果确认漏洞存在": {
        "漏洞详情": "描述已确认的漏洞细节",
        "建议修复方案": "提供修复建议"
      },
      "如果确认为误报": {
        "误报原因": "详细解释为什么判定为误报",
        "相关代码分析": "提供支持误报判断的代码分析"
      }
    }
  },
  "步骤2": {
    "检查描述": "",
    "检查目标": "",
    "具体检查步骤": "",
    "检查关键点": "",
    "检查结论参考": {
      "判断标准(具体到代码)": {
        "需要继续检查的条件": "",
        "确认漏洞存在的条件": "",
        "确认为误报的条件": ""
      }
    },
    "检查结果后续操作": {
      "如果需要继续检查": {
        "下一步": "步骤3"
      },
      "如果确认漏洞存在": {
        "漏洞详情": "描述已确认的漏洞细节",
        "建议修复方案": "提供修复建议"
      },
      "如果确认为误报": {
        "误报原因": "详细解释为什么判定为误报",
        "相关代码分析": "提供支持误报判断的代码分析"
      }
    }
  },
  "步骤3": {
    "检查描述": "",
    "检查目标": "",
    "具体检查步骤": "",
    "检查关键点": "",
    "检查结论参考": {
      "判断标准(具体到代码)": {
        "需要继续检查的条件": "",
        "确认漏洞存在的条件": "",
        "确认为误报的条件": ""
      }
    },
    "检查结果后续操作": {
      "如果需要继续检查": {
        "下一步": "步骤4"
      },
      "如果确认漏洞存在": {
        "漏洞详情": "描述已确认的漏洞细节",
        "建议修复方案": "提供修复建议"
      },
      "如果确认为误报": {
        "误报原因": "详细解释为什么判定为误报",
        "相关代码分析": "提供支持误报判断的代码分析"
      }
    }
  }
  ....步骤4，步骤5.....
}

    11. 每个描述字段不应少于200个字，每个具体操作不应少于200个字。
    12. "检查结论参考"中的"判断标准"应详细说明在何种情况下应得出何种结论，确保与"检查描述"、"检查目标"和"检查关键点"保持逻辑一致性。
    13. "检查结果后续操作"必须完整的包含"如果需要继续检查"，"如果确认漏洞存在"，"如果确认为误报"的后续操作，否则你会受到惩罚。
    14. 步骤和步骤必须是同级别关系，否则你会受到惩罚
    15. 步骤必须完整，如果你在下一步提到了某一个步骤，那么步骤详情必须输出，如果你认为下一步已经完成了确认，就不需要输出步骤xxx
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