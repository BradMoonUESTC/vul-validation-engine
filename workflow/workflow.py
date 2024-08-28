import json
from rag.constructor import query_similar_functions
from task.task import Task

class Workflow:
    def __init__(self, agents, tasks, csv_data, checker_agent):
        self.agents = agents
        self.tasks = tasks
        self.csv_data = csv_data
        self.checker_agent = checker_agent

    def run(self):
        results = []
        for task in self.tasks:
            for row in self.csv_data:
                result = self.execute_task(task, row)
                results.append(result)
        return results

    def execute_task(self, task: Task, row):
        # 生成初始的漏洞确认流程
        initial_result = task.execute(self.agents[0], json.dumps(row))
        
        # 解析JSON结果
        steps = json.loads(initial_result)
        
        final_result = {"漏洞描述": row['漏洞结果'], "是否误报": True, "检查步骤": []}
        
        # 递归执行步骤
        self.execute_steps(steps, final_result)
        
        return final_result

    def execute_steps(self, steps, final_result):
        for step_name, step_data in steps.items():
            step_result = self.check(step_data)
            final_result["检查步骤"].append(step_result)
            # 这里的step_result结果例子为：
            # {'步骤描述': 'xxxx', '通过': True, '详细结果': 'xxxx'}
            if not step_result["通过"]:
                final_result["是否误报"] = False
                break
            
            # 如果有子步骤且通过了当前步骤，继续执行子步骤
            if "是" in step_data and isinstance(step_data["是"], dict):
                self.execute_steps(step_data["是"], final_result)
            
            # 如果执行到这里，说明所有步骤都通过了1
            if step_name == list(steps.keys())[-1]:
                final_result["是否误报"] = True

    def check(self, step):
        # 1. 提取代码
        # 2. 构建prompt
        # 3. 检查
        # 使用RAG获取相关代码
        # TODO: 这里的step["检查目标"]的例子为：'目标是确定在上述漏洞场景中，`migrationMode`变量的状态。由于该变量状态直接影响到合约内的`_calcClaimAmount`函数的行为逻辑，因此准确获取该变量的状态是分析潜在漏洞和误报的关键第一步。'
        # 目的是根据检查目标，提取跟检查目标最接近的code
        # TODO: 这里面可能不光拿1个，可能拿多个
        relevant_code = query_similar_functions(step["检查目标（不少于200个字）"], top_k=1)[0]['content']
        # 提取code的例子为：'function _calcClaimAmount(uint256 id)\n        internal\n        view\n        returns (uint256 amount, uint256 heuAmount)\n    {\n        VestInfo storage info = vestInfo[msg.sender][id];\n\n        amount = info.amount;\n\n        if (amount == 0) {\n            revert StHEU__NoVestForId();\n        }\n        if (block.timestamp < info.end && !migrationMode) {\n            revert StHEU__CanNotClaimEarlier();\n        }\n\n        heuAmount = amount * _exchangeRate() / 1e18;\n    }'
        # 这里最好再加一个相似度度量，避免retrive了过低相似度的code
        # # 构建提示
        # prompt例子：
        # 检查目标: 目标是确定在上述漏洞场景中，migrationMode变量的状态。由于该变量状态直接影响到合约内的_calcClaimAmount函数的行为逻辑，因此准确获取该变量的状态是分析潜在漏洞和误报的关键第一步。
        # 检查步骤: 首先需要确保能够查看或调用智能合约的相关函数来获取migrationMode变量的当前状态。这通常包括但不限于使用区块链浏览器检查已经部署的智能合约的交易和状态、使用智能合约IDE（如Remix）通过调用相关的getter函数（如果合约中存在此类函数）获取状态值，或通过编写脚本直接与智能合约交互查询状态。
        # 相关代码: xxxxx
        prompt = f"""
        检查目标: {step['检查目标（不少于200个字）']}
        检查步骤: {step['具体检查步骤（不少于200个字）']}
        xxxx加一些具体的检查内容（步骤，关键点，结论参考）
        相关代码:
        {relevant_code}
        
        请判断此代码是否满足检查目标和检查步骤的要求。
        返回结果以下面形式：
        {{
            "通过": true/false,
            "详细结果": "xxxx"

        }}
        
        """
        
        # 使用investigator agent进行判断
        result = self.agents[1].perform_task("判断代码是否满足要求", prompt, use_json=True)
        # result例子：'根据提供的检查目标和检查步骤，目标是要确定`migrationMode`变量的状态，因为此变量影响`_calcClaimAmount`函数的行为逻辑。从提供的代码可以看出，代码确实依赖于`migrationMode`变量的状态来决定是否应该允许提前索赔。如果`migrationMode`为`false`且当前时间小于End时间，则无法提前领取，这意味着`migrationMode`的状态对函数行为至关重要。\n\n然而，提供的代码不包括任何显示或获取`migrationMode`的getter函数或其他方法，这意味着我们无法直接从代码中看到这个变量的状态。如果此智能合约没有公开的获取或查看`migrationMode`状态的方式（如getter函数），那么将无法仅通过代码进行审核来满足检查步骤，因为我们不能仅从代码中判断出`migrationMode`的当前值。\n\n总结：当前提供的代码片段本身无法满足检查目标和检查步骤的要求，因为它没有包含或说明如何可以查看或获取`migrationMode`变量的状态。需要进一步的代码或访问智能合约的完整实现才能确切地判断其是否有公开的访问方法。如果合约中存在相应的getter函数或其他访问method来检查`migrationMode`，那么使用这些方法可以满足需求。'
        # TODO:这个result中并没有一个明确的答案，需要让gpt给出一个明确的答案，是或者否/或者是“满足检查”或者“不满足检查”，或者其他的答案
        # TODO: 如果上面是few shot的形式，这里加一个json的解析，提取“通过”的字段内容
        return {
            "步骤描述": step['检查描述（不少于200个字）'],
            "通过": "是" in result.lower(),
            "详细结果": result
        }