import os
import subprocess
import networkx as nx
import re
from ast_parser import ASTParser


def joern_export(package_name: str, package_code_path: str, joern_workspace_path: str, language: str,
                 overwrite: bool = False):
    """
    export cpg and pdg, save in joern_workspace_path/package_name/cpg, joern_workspace_path/package_name/pdg,
    joern_workspace_path/package_name/cfg
    :param package_name: package name
    :param package_code_path: path to the package
    :param joern_workspace_path: joern workspace path
    :param language: language (javascript)
    :param overwrite: overwrite previous output
    """
    package_joern_path = os.path.abspath(os.path.join(joern_workspace_path, package_name))
    if os.path.exists(package_joern_path) and not overwrite:
        return
    else:
        if os.path.exists(package_joern_path):
            subprocess.run(['rm', '-rf', package_joern_path])
    pdg_dir = os.path.join(package_joern_path, 'pdg')
    cfg_dir = os.path.join(package_joern_path, 'cfg')
    cpg_dir = os.path.join(package_joern_path, 'cpg')
    os.makedirs(package_joern_path, exist_ok=True)
    subprocess.run(['joern-parse', '--language', language, os.path.abspath(package_code_path)], cwd=package_joern_path,
                   timeout=20)
    subprocess.run(['joern-export', '--repr', 'pdg', '--out', os.path.abspath(pdg_dir)], cwd=package_joern_path,
                   timeout=20)
    subprocess.run(['joern-export', '--repr', 'cfg', '--out', os.path.abspath(cfg_dir)], cwd=package_joern_path,
                   timeout=20)
    subprocess.run(['joern-export', '--repr', 'all', '--out', os.path.abspath(cpg_dir)], cwd=package_joern_path,
                   timeout=20)


def joern_preprocess(package_dir: str, pdg_dir: str, cfg_dir: str, cpg_dir: str):
    cpg = nx.nx_agraph.read_dot(os.path.join(cpg_dir, 'export.dot'))
    for pdg_file in os.listdir(pdg_dir):
        file_id = pdg_file.split('-')[0]
        pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_file))
        cfg: nx.MultiDiGraph = nx.nx_agraph.read_dot(os.path.join(cfg_dir, f'{file_id}-cfg.dot'))

        ddg_null_edges = []
        for u, v, k, d in pdg.edges(data=True, keys=True):
            if d['label'] in ['DDG: ', 'CDG: ', 'DDG: this']:
                ddg_null_edges.append((u, v, k, d))
        pdg.remove_edges_from(ddg_null_edges)

        pdg: nx.MultiDiGraph = nx.compose(pdg, cfg)
        for u, v, k, d in pdg.edges(data=True, keys=True):
            if 'label' not in d:
                pdg.edges[u, v, k]['label'] = 'CFG'

        method_node = None
        param_nodes = []
        for node in pdg.nodes:
            for key, value in cpg.nodes[node].items():
                pdg.nodes[node][key] = value
            pdg.nodes[node]['NODE_TYPE'] = pdg.nodes[node]['label']
            node_type = pdg.nodes[node]['NODE_TYPE']
            if node_type == 'METHOD':
                method_node = node
            if node_type == 'METHOD_PARAMETER_IN':
                param_nodes.append(node)
            if 'CODE' not in pdg.nodes[node]:
                pdg.nodes[node]['CODE'] = ''
            node_code = pdg.nodes[node]['CODE'].replace("\n", "\\n")
            pdg.nodes[node]['CODE'] = pdg.nodes[node]['CODE'].replace("\n", "\\n")
            node_line = pdg.nodes[node]['LINE_NUMBER'] if 'LINE_NUMBER' in pdg.nodes[node] else 0
            node_column = pdg.nodes[node]['COLUMN_NUMBER'] if 'COLUMN_NUMBER' in pdg.nodes[node] else 0
            pdg.nodes[node]['label'] = f"[{node}][{node_line}:{node_column}][{node_type}]: {node_code}"
            if pdg.nodes[node]['NODE_TYPE'] == 'METHOD_RETURN':
                pdg.remove_edges_from(list(pdg.in_edges(node)))

        add_edge(pdg, package_dir, method_node, param_nodes)

        nx.nx_agraph.write_dot(pdg, os.path.join(pdg_dir, pdg_file))


def add_edge(pdg: nx.MultiDiGraph, package_dir, method_node, param_nodes):
    if len(param_nodes) > 0:
        method_name = pdg.nodes[method_node]['NAME']
        if re.search(r'<lambda>\d*', method_name):

            js_file_path = os.path.join(package_dir, pdg.nodes[method_node]['FILENAME'])
            start_line = int(pdg.nodes[method_node]['LINE_NUMBER'])
            start_column = int(pdg.nodes[method_node]['COLUMN_NUMBER'])
            end_line = int(pdg.nodes[method_node]['LINE_NUMBER_END'])
            end_column = int(pdg.nodes[method_node]['COLUMN_NUMBER_END'])
            code_snippet = ""
            with open(js_file_path, 'r') as file:
                current_line_number = 1
                for line in file:
                    if current_line_number == start_line:
                        code_snippet += line[start_column - 1:]  # Adjust for 0-indexing
                    elif start_line < current_line_number < end_line:
                        code_snippet += line
                    elif current_line_number == end_line:
                        code_snippet += line[:end_column]  # Adjust for 0-indexing
                        break
                    current_line_number += 1

            # formal parameter in lambda function
            ast_parser = ASTParser(code_snippet, 'javascript')
            formal_parameter_query = '(formal_parameters)@formal'
            query_result = ast_parser.query_oneshot(formal_parameter_query)
            formal_parameter_list = []
            if query_result:
                named_children = query_result.named_children
                for child in named_children:
                    formal_parameter_list.append(child.text.decode())

            # param in arrow function
            arrow_function_parameters_query = """
            (arrow_function
	            parameter: (identifier)@identifier
            )
            """
            query_result = ast_parser.query_oneshot(arrow_function_parameters_query)
            if query_result:
                formal_parameter_list.append(query_result.text.decode())
            for param_node in param_nodes:
                param_code = pdg.nodes[param_node]['CODE']
                if param_code in formal_parameter_list:
                    pdg.add_edge(method_node, param_node, label='DDG')
        else:
            for param_node in param_nodes:
                pdg.add_edge(method_node, param_node, label='DDG')
