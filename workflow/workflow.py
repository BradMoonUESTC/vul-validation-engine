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
        
        final_result = {"漏洞描述": row['漏洞结果'], "漏洞": False, "检查步骤": []}


        
        # 递归执行步骤
        self.execute_steps(steps, final_result)
        
        return final_result

    def execute_steps(self, steps, final_result):
        for step_name, step_data in steps.items():
            step_result = self.check(step_data)
            final_result["检查步骤"].append(step_result)
            # 这里的step_result结果例子为：
            # {'步骤描述': 'xxxx', '通过': True, '详细结果': 'xxxx'}
            # 通过安全检查，不意味着没有漏洞，但是没有通过安全检查，一定有漏洞
            # 因为这个是误报确认，所以检查点如果说通过了，或者说结论是否，一定没有漏洞；结论是是，则不一定有漏洞
            if not step_result["是否要继续检查"]: # 如果是false，说明之前返回的是“确认是误报”
                final_result["漏洞"] = True
                return

            # 处理子步骤
            next_steps = step_data.get("是")
            if isinstance(next_steps, dict):
                self.execute_steps(next_steps, final_result)

    def check(self, step):
        # 1. 提取代码
        # 2. 构建prompt
        # 3. 检查
        # 使用RAG获取相关代码
        # 这里的step["检查目标"]的例子为：'目标是确定在上述漏洞场景中，`migrationMode`变量的状态。
        # 由于该变量状态直接影响到合约内的`_calcClaimAmount`函数的行为逻辑，因此准确获取该变量的状态是分析潜在漏洞和误报的关键第一步。'
        # 目的是根据检查目标，提取跟检查目标最接近的code

        query_res = query_similar_functions(step["检查目标（不少于200个字）"], top_k=5)
        relevant_code = [x['content'] for x in query_res if x['similarity'] > 0.3]
        # 提取code的例子为：'function _calcClaimAmount(uint256 id)\n        internal\n        view\n        returns (uint256 amount, uint256 heuAmount)\n    {\n        VestInfo storage info = vestInfo[msg.sender][id];\n\n        amount = info.amount;\n\n        if (amount == 0) {\n            revert StHEU__NoVestForId();\n        }\n        if (block.timestamp < info.end && !migrationMode) {\n            revert StHEU__CanNotClaimEarlier();\n        }\n\n        heuAmount = amount * _exchangeRate() / 1e18;\n    }'
        # 这里最好再加一个相似度度量，避免retrive了过低相似度的code
        # # 构建提示
        # prompt例子：
        # 检查目标: 目标是确定在上述漏洞场景中，migrationMode变量的状态。由于该变量状态直接影响到合约内的_calcClaimAmount函数的行为逻辑，因此准确获取该变量的状态是分析潜在漏洞和误报的关键第一步。
        # 检查步骤: 首先需要确保能够查看或调用智能合约的相关函数来获取migrationMode变量的当前状态。这通常包括但不限于使用区块链浏览器检查已经部署的智能合约的交易和状态、使用智能合约IDE（如Remix）通过调用相关的getter函数（如果合约中存在此类函数）获取状态值，或通过编写脚本直接与智能合约交互查询状态。
        # 相关代码: xxxxx
        prompt = f"""
        检查描述: {step['检查描述（不少于200个字）']}
        检查目标: {step['检查目标（不少于200个字）']}
        检查步骤: {step['具体检查步骤（不少于200个字）']}
        检查关键点: {step['检查关键点（不少于200个字）']}
        检查结论参考: {step['检查结论参考（不少于200个字）']}
        
        相关代码:
        {{{relevant_code}}}
        
        请判断此代码是否满足检查目标和检查步骤的要求。
        返回结果以下面形式：
        {{
            "结果": 需要继续检查/确认为误报
            "详细结果": "xxxx"
        }}
        
        """
        # TODO: 这里的结果和详细结果最关键，有时候详细结果返回如下：
        # "从提供的代码中可以看到，在'migrationMode'为true时，'vest'函数确实将'period'设置为0，符合验证目标的要求。
        # 但是为了确保功能完整和安全，建议对合约的各种状态 (特别是'migrationMode'状态切换) 进行综合测试，验证系统在不同状态下都能正确地处理'period'。此外，还需验证'nonReentrant'修饰符能有效防止重入攻击，确保合约的稳定性和安全性。目前的代码审计基于提供的代码片段，对于完整合约的其他部分和潜在交互也应进行仔细检查，以排除任何其他潜在的安全风险。"
        
        # 可以发现，检查实际上是满足了要求，但是需要确认结果是不是需要继续检查，gpt认为虽然满足要求但还是要继续检查，这里我倾向于不限制他输出，尽量发挥gpt自己的判断能力
        # 因此，这里我改了结果类型，所以尽量在kickoff的那个prompt里也改一下，把这两个prompt争取连在一起
        
        
        # 使用investigator agent进行判断
        result = self.agents[1].perform_task("判断代码是否满足要求", prompt, use_json=True)
        result = json.loads(result)
        # result例子：'根据提供的检查目标和检查步骤，目标是要确定`migrationMode`变量的状态，因为此变量影响`_calcClaimAmount`函数的行为逻辑。从提供的代码可以看出，代码确实依赖于`migrationMode`变量的状态来决定是否应该允许提前索赔。如果`migrationMode`为`false`且当前时间小于End时间，则无法提前领取，这意味着`migrationMode`的状态对函数行为至关重要。\n\n然而，提供的代码不包括任何显示或获取`migrationMode`的getter函数或其他方法，这意味着我们无法直接从代码中看到这个变量的状态。如果此智能合约没有公开的获取或查看`migrationMode`状态的方式（如getter函数），那么将无法仅通过代码进行审核来满足检查步骤，因为我们不能仅从代码中判断出`migrationMode`的当前值。\n\n总结：当前提供的代码片段本身无法满足检查目标和检查步骤的要求，因为它没有包含或说明如何可以查看或获取`migrationMode`变量的状态。需要进一步的代码或访问智能合约的完整实现才能确切地判断其是否有公开的访问方法。如果合约中存在相应的getter函数或其他访问method来检查`migrationMode`，那么使用这些方法可以满足需求。'


        return {
            "步骤描述": step['检查描述（不少于200个字）'],
            "是否要继续检查": result["结果"] == "需要继续检查",
            "详细结果": result
        }