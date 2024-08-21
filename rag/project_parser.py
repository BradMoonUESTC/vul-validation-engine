

from library.sgp.sgp_parser import get_antlr_parsing
from library.parsing.callgraph import CallGraph
import os
import re
class Function(dict):
    def __init__(self, file, contract, func):
        self.file = file
        self.contract = contract
        self.update(func)


def parse_project_cg(project_path):
    cg = CallGraph(project_path)
    
    function_list = []
    for file, contract, func in cg.functions_iterator():
        func_text = cg.get_function_src(file, func)
        # print(file, contract['name'], func['name'], func_text)

        f = Function(file, contract, func)
        f['name'] = contract['name'] + '.' + func['name']
        f['content'] = func_text
        function_list.append(f)

    function_list = [result for result in function_list if result['kind'] == 'function']

    return function_list

def is_path_in_white_list(haystack, white_list, partial):
    if partial:
        for item in white_list:
            if item in haystack:
                return True
    else:
        for p in haystack.split("/"):
            ds = filter(lambda x: x == p, white_list)
            if len(list(ds)) > 0:
                return True
    return False
            

class BaseProjectFilter(object):

    def __init__(self, white_files = [], white_functions = []):
        self.white_files = white_files
        self.white_functions = white_functions
        pass

    def check_function_code_if_statevar_assign(self, function_code,contract_code):
        state_vars=extract_state_variables_from_code(contract_code)
        nodes = function_code.split(';')
        # 判断每个操作是否是对状态变量的赋值
        for node in nodes:
            if '=' in node:
                # 获取等号左边的内容
                left_side = node.split('=')[0].strip()
                # 检查是否有状态变量
                for var in state_vars:
                    if re.search(r'\b' + re.escape(var) + r'\b', left_side):
                        return True
        return False
def parse_project(project_path, project_filter = None):

    if project_filter is None:
        project_filter = BaseProjectFilter([], [])

    ignore_folders = set()
    if os.getenv('IGNORE_FOLDERS'):
        ignore_folders = set(os.getenv('IGNORE_FOLDERS').split(','))
    ignore_folders.add('.git')
    all_results = []
    for dirpath, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in ignore_folders]
        for file in files:
            to_scan = True
            sol_file = os.path.join(dirpath, file) # relative path
            absolute_path = os.path.abspath(sol_file)  # absolute path
            print("parsing file: ", sol_file, " " if to_scan else "[skipped]")
            
            if to_scan:
                results = get_antlr_parsing(sol_file)
                for result in results:
                    result['relative_file_path'] = sol_file
                    result['absolute_file_path'] = absolute_path
                all_results.extend(results)
    
    functions = [result for result in all_results if result['type'] == 'FunctionDefinition']
    # fix func name 
    fs = []
    for func in functions:
        name = func['name'][8:]
        func['name'] = "%s.%s" % (func['contract_name'], name)
        fs.append(func)

    fs_filtered = fs[:]
    # 2. filter contract 
    fs_filtered = [func for func in fs_filtered]

    # 3. filter functions 
    fs_filtered = [func for func in fs_filtered]

    return fs, fs_filtered 


if __name__ == '__main__':
    project_path="contract_files/decompiled"
    functions, functions_to_check = parse_project(project_path)
    # extract_state_variables_from_code