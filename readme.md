# 漏洞确认系统

## 项目简介

这是一个基于多智能代理和工作流的agent漏洞确认系统。系统通过多个智能代理协作完成代码漏洞的确认工作,支持多步骤检查和内部深入分析。

## 主要功能

1. **漏洞确认工作流**
- 支持多步骤漏洞确认流程
- 可配置最大检查深度
- 自动记录确认日志
- 支持内部深入检查

2. **智能代理系统** 
- 多个专业代理协作
- 基于角色和目标的任务执行
- 支持自然语言交互

3. **代码分析能力**
- 相似代码检索(RAG系统)
- 多语言代码解析(Solidity/Python/Rust等)
- 代码上下文分析
- 智能代码理解

## 核心组件

### Workflow
工作流引擎,负责:
- 执行多步骤确认流程
- 调度智能代理
- 记录确认日志

关键代码:

```9:17:workflow/workflow.py
class Workflow:
    def __init__(self, agents, tasks, csv_data, checker_agent, max_depth=3):
        self.agents = agents
        self.tasks = tasks
        self.csv_data = csv_data
        self.checker_agent = checker_agent
        self.log_file = f"workflow_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.initialize_log_file()
        self.max_depth = max_depth
```


### Agent
智能代理,负责:
- 执行具体确认任务
- 与OpenAI API交互
- 生成分析结果

关键代码:

```3:18:agent/agent.py
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
```


### RAG系统
检索增强生成系统,负责:
- 代码相似度检索
- 代码解析和分析
- 向量数据库管理

关键代码:

```15:35:rag/constructor.py
def process_contracts(folder_path):
    all_functions = []
    all_functions,_=parse_project(folder_path)
    return all_functions

def fetch_embedding(text):
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    data = {"input": text, "model": MODEL}
    try:
        response = requests.post(f'https://{API_BASE}/v1/embeddings', json=data, headers=headers)
        response.raise_for_status()
        return response.json()['data'][0]['embedding']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching embedding: {e}")
        return np.zeros(3072).tolist()  # Adjust the size based on your model's output

def generate_embeddings(functions):
    embeddings = {}
    metadata = []
    
    for func in tqdm(functions, desc="Generating embeddings"):
```


## 工作流程

1. **初始化检查**
- 加载待确认漏洞数据
- 初始化智能代理
- 准备日志记录

2. **多步骤确认**
- 执行初始检查
- 根据结果决定是否需要深入检查
- 记录每步确认结果

3. **内部深入检查**
- 分析代码内部逻辑
- 检索相似代码片段
- 生成深入分析结论

4. **结果输出**
- 生成最终确认结果
- 记录详细分析过程
- 输出漏洞确认报告

## 系统要求

- Python 3.8+
- OpenAI API密钥
- 足够的计算资源和存储空间

## 配置说明

1. OpenAI API配置

```4:8:util/openai_helper.py
class OpenAIHelper:
    def __init__(self, api_key, api_base="api.openai.one"):
        self.api_key = api_key
        self.api_base = api_base

```


2. 向量数据库配置

```10:13:rag/constructor.py
API_KEY = "sk-d3i9QpUjDpMo7Qt1C6764388Eb784f7c94D70c904f121435"
API_BASE = "apix.ai-gaochao.cn"
MODEL = "text-embedding-3-large"
EMBEDDINGS_FILE = "vector_database.pkl"
```


## 注意事项

1. 请确保OpenAI API配置正确
2. 建议合理设置最大检查深度
3. 定期备份确认日志
4. 注意代码解析的语言支持情况

## 贡献指南

欢迎提交Issue和Pull Request来帮助改进系统。提交代码时请遵循以下规范:

1. 遵循Python代码规范
2. 添加必要的注释
3. 更新相关文档
4. 编写测试用例

## 许可证

本项目采用MIT许可证。
