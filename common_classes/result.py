import json
import pickle
from common_classes.pdg_node import PDGNode
from common_classes.cpg_pdg_edge import Edge
import os
import copy
import networkx as nx
from common_classes.pattern import Pattern
from common_classes.report import Report
from category import category_doc
import llm
import re
import shutil
from ast_parser import ASTParser
from common_classes.cpg import CPG
from common_classes.pdg import PDG
from common_classes.cpg_pdg_edge import Edge
from common_classes.sensitive_graph import SensitiveGraph
from common_classes.dynamic_eval import docker_eval


class PatternList:
    def __init__(self):
        self.pattern_list = []
        file_path = '../pattern_list.pickle'
        with open(file_path, 'rb') as binary:
            self.pattern_list = pickle.load(binary)

    def get_pattern_list(self):
        return self.pattern_list

class Result:
    def __init__(self, cpg: CPG, pdg_dict: dict[int, PDG], package_dir, package_name):
        self.entrance_node = None  # entrance of the Result
        self.return_node: list[PDGNode] = []  # return value of the result
        self.nodes: dict[int, PDGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, set[int]] = {}
        self.in_edges: dict[int, set[int]] = {}
        self.node_on_path = []
        self.visited = set()
        self.adjacent_matrix: dict[tuple[int, int], str] = {}  # adjacent matrix
        self.sensitive_behavior: SensitiveGraph = SensitiveGraph()  # sensitive info
        self.mapping_dict = {}  # mapping info
        self.package_report = None
        self.cpg = cpg
        self.pdg_dict = pdg_dict
        self.package_dir = package_dir
        self.package_name = package_name

    def pattern_further_analysis(self, pattern: Pattern, one_match: dict):

        # further analysis
        if pattern.get_pattern_desc() == 'execute a command':
            command_node_id = one_match['execute a command'][0]
            execute_command_string = self.parameter_fetch(command_node_id)
            if execute_command_string is None:
                return True
            if execute_command_string != '':
                # judge whether the command is malicious or not
                if llm.llm_execute_command_analysis(execute_command_string):
                    return True
                else:
                    return False
            else:

                return False
        elif pattern.get_pattern_desc() == 'run an executable file':
            run_file_node_id = one_match['run an executable file'][0]
            file_path = self.parameter_fetch(run_file_node_id)
            if file_path is None:
                return True
            if file_path != '':
                if llm.llm_run_executable_file(file_path):
                    return True
                else:
                    return False
            else:
                return False
        elif pattern.get_pattern_desc() == 'read from file - execute dynamically created program' \
                or pattern.get_pattern_desc() == 'manipulate path - read local file - send through network communication' \
                or pattern.get_pattern_desc() == 'read local file - send through network communication' \
                or pattern.get_pattern_desc() == 'read local file - send through HTTP request':

            read_file_node_id = one_match['read data from a file'][0]
            file_path = self.parameter_fetch(read_file_node_id)
            if file_path is None:
                return True
            if file_path != '':
                # judge whether the command read sensitive files
                if llm.llm_read_file_command_analysis(file_path):
                    return True
                else:
                    return False
            else:
                return False

        elif pattern.get_pattern_desc() == 'search file - send through network':

            search_file_node_id = one_match['search for a file'][0]
            file_path = self.parameter_fetch(search_file_node_id)
            if file_path is None:
                return True
            if file_path != '':
                if llm.llm_read_file_command_analysis(file_path):
                    return True
                else:
                    return False
            else:
                return False

        elif pattern.get_pattern_desc() == 'spawn a new process':

            spawn_new_process_node_id = one_match['spawn a new process'][0]
            process_string = self.parameter_fetch(spawn_new_process_node_id)
            if process_string is None:
                return True
            if process_string != '':
                # judge whether the command
                if llm.llm_execute_command_analysis(process_string):
                    return True
                else:
                    return False
            else:
                return False
        elif pattern.get_pattern_desc() == 'execute a dynamically created program':

            # execute a dynamically created program
            dynamically_created_program = one_match['execute a dynamically created program'][0]
            function_string = self.parameter_fetch(dynamically_created_program)
            if function_string is None:
                return True
            if function_string != '':
                # judge the code executed
                if llm.llm_dynamically_created_program_analysis(function_string):
                    return True
                else:
                    return False
            else:
                return False

        elif pattern.get_pattern_desc() == 'make HTTP request - write data to local sensitive path' \
                or pattern.get_pattern_desc() == 'change file mode - write data to file' \
                or pattern.get_pattern_desc() == 'read file - write data to file':

            write_file_node_id = one_match['write data to a file'][0]
            file_path = self.parameter_fetch(write_file_node_id)
            if file_path is None:
                return True
            if file_path != '':
                if llm.llm_write_file_command_analysis(file_path):
                    return True
                else:
                    return False
            else:
                return False
        elif pattern.get_pattern_desc() == 'encode data - data rep - send through network communication' \
                or pattern.get_pattern_desc() == 'encode data - send through network communication':
            if self.package_report.contain_information_stealing():
                return False
            network_communication_node_id = one_match['create a network server or communication'][0]
            network_options = self.parameter_fetch(network_communication_node_id)
            if network_options is None:
                return True
            if network_options != '':

                if llm.llm_suspicious_url(network_options):
                    return True
                else:
                    return False
            else:
                return False
        else:
            return True

    @staticmethod
    def extract_code(file_path, start_line, start_column):
        with open(file_path, 'r') as file:
            lines = file.readlines()
        extracted_code = []
        extracted_code.append(lines[start_line - 1][start_column:])
        extracted_code.extend(lines[start_line:])

        return ''.join(extracted_code)

    def parameter_fetch(self, function_id):
        function_pdg_node = self.nodes[function_id]  # get the corresponding pdg
        line_number = function_pdg_node.get_line_number()  # line number
        column_number = function_pdg_node.get_column_number()  # column number
        argument_identifier_list = []
        code_path = os.path.join(self.package_dir, function_pdg_node.get_file_name())
        part_code = self.extract_code(code_path, line_number, column_number)

        # tree-sitter query
        new_argument_query = """
                                (new_expression
                                    constructor:(member_expression)
                                    arguments: (arguments)@arguments
                                )
        """
        arguments_query = """
                            (call_expression
                                (arguments)@arguments
                            )
        """

        require_expression_argument_query = """
                                            (call_expression
	                                            function: (member_expression
    	                                            object: (call_expression
        	                                            function: (identifier)@identifier
        	                                            (#eq? @identifier "require")
                                                    )
                                                    property: (property_identifier)
                                                 )
	                                            arguments:(arguments)@arguments
                                            )
        """
        parser = ASTParser(part_code, 'javascript')
        new_expression_arguments = parser.query_oneshot(new_argument_query)
        require_expression_arguments = parser.query(require_expression_argument_query)
        arguments = parser.query_oneshot(arguments_query)
        arguments_to_eval = None
        if new_expression_arguments:
            arguments_to_eval = new_expression_arguments
        elif require_expression_arguments:
            arguments_list = [r[0] for r in require_expression_arguments if r[1] == 'arguments']
            arguments_to_eval = arguments_list[0]
        elif arguments:
            arguments_to_eval = arguments
        if arguments_to_eval:
            named_children_list = arguments_to_eval.named_children
            for named_children in named_children_list:
                if named_children.type == 'string':
                    argument_identifier_list.append(('literal', True, named_children.text.decode()))
                elif named_children.type == 'arrow_function':
                    pass
                elif named_children.type == 'function_expression':
                    pass
                else:
                    argument_identifier_list.append(('other', False, named_children.text.decode()))
        else:
            return ''

        num = 1
        dynamic_value = []
        for index, argument_identifier in enumerate(argument_identifier_list):
            if argument_identifier[1] is False:
                dynamic_value.append((index, argument_identifier[2], f"#{num}"))
                argument_identifier_list[index] = ('other', False, f"#{num}")
                num += 1

        if dynamic_value:

            function_pdg_node = self.nodes[function_id]
            line_number = function_pdg_node.get_line_number()
            column_number = function_pdg_node.get_column_number()

            # insert based on the ast
            with open(code_path, 'r') as code_file:
                code = code_file.read()
            ast_parser = ASTParser(code, 'javascript')
            expression_statement_position = ast_parser.get_first_expression(line_number=line_number - 1,
                                                                            column_number=column_number)
            if expression_statement_position is None:
                return ''
            else:
                line_number = expression_statement_position[0] + 1
                column_number = expression_statement_position[1]
            new_code = []
            for value in dynamic_value:
                insert_code_line = fr"""require('fs').appendFileSync("log.log", "{value[2]}:" + {value[1]} + "\n");"""
                new_code.append(' ' * column_number + insert_code_line + '\n')
            new_code.append(' ' * column_number + 'exit(1);\n')

            # move the target folder
            # set the path of the folder you want
            dock_env_path = ''
            os.makedirs(dock_env_path, exist_ok=True)
            source = self.package_dir
            target = os.path.join(dock_env_path, self.package_name)

            # move
            if os.path.exists(target):
                shutil.rmtree(target)
            shutil.copytree(source, target)
            js_code_path = os.path.join(target, function_pdg_node.get_file_name())
            path_in_package_json = '/'.join(function_pdg_node.get_file_name().split('/')[1:])

            with open(js_code_path, 'r') as file:
                lines = file.readlines()
                lines[line_number - 1:line_number - 1] = ''.join(new_code)
            with open(js_code_path, 'w') as file:
                file.writelines(lines)

            package_json_in_docker_path = os.path.join(target, 'package', 'package.json')
            if not os.path.exists(package_json_in_docker_path):
                return ''

            else:
                value_dict = docker_eval(os.path.join(target, 'package'))
                if value_dict is not None:
                    argument_string = self.get_argument_string(argument_identifier_list, dynamic_value, value_dict)
                    shutil.rmtree(target)
                    return argument_string
                else:
                    with open(package_json_in_docker_path, 'r') as package_json_file:
                        package_json_data = json.load(package_json_file)
                    if 'scripts' not in package_json_data:
                        package_json_data['scripts'] = {}
                    if 'main' not in package_json_data:
                        package_json_data['scripts']['postinstall'] = "node" + 'index.js'
                    else:
                        package_json_data['scripts']['postinstall'] = "node " + package_json_data['main']
                    with open(package_json_in_docker_path, 'w') as file:
                        json.dump(package_json_data, file, indent=4)
                    value_dict = docker_eval(os.path.join(target, 'package'))

                    if value_dict is not None:
                        argument_string = self.get_argument_string(argument_identifier_list, dynamic_value, value_dict)
                        shutil.rmtree(target)
                        return argument_string
                    else:
                        with open(package_json_in_docker_path, 'r') as package_json_file:
                            package_json_data = json.load(package_json_file)
                        if 'scripts' not in package_json_data:
                            package_json_data['scripts'] = {}
                        package_json_data['scripts']['postinstall'] = "node " + path_in_package_json

                        with open(package_json_in_docker_path, 'w') as file:
                            json.dump(package_json_data, file, indent=4)
                        value_dict = docker_eval(os.path.join(target, 'package'))
                        if value_dict is not None:
                            argument_string = self.get_argument_string(argument_identifier_list, dynamic_value,
                                                                       value_dict)
                            shutil.rmtree(target)
                            return argument_string
                        else:
                            shutil.rmtree(target)
                            return ''

        else:
            argument_string = ''
            for argument_identifier in argument_identifier_list:
                argument_string += argument_identifier[2]
            return argument_string

    @staticmethod
    def get_argument_string(argument_identifier_list, dynamic_value, value_dict):
        for value in dynamic_value:
            value_name = value[2]
            for index, argument_identifier in enumerate(argument_identifier_list):
                if argument_identifier[2] == value_name:
                    argument_identifier_list[index] = ('other', True, value_dict[value_name])
            argument_string = ''
            for argument_identifier in argument_identifier_list:
                argument_string += argument_identifier[2]
            return argument_string

    def sensitive_subgraph_extraction(self, cpg: CPG, package_report: Report):
        """
        extract sensitive nodes
        """
        self.package_report = package_report
        sensitive_node_list: list[PDGNode] = []
        node_id_list = copy.deepcopy(list(self.nodes.keys()))

        for node_id in node_id_list:
            pdg_node = self.nodes[node_id]
            if pdg_node.is_sensitive_node():
                category_list = pdg_node.get_class_list()
                current_node_id = node_id

                for i in range(len(category_list)):
                    if i == 0:
                        pdg_node.set_class_list(category_list[i:i + 1])
                        pdg_node.set_category_description(category_doc[category_list[i]])
                        sensitive_node_list.append(pdg_node)
                    else:
                        new_node = PDGNode(cpg.get_max_node_id())
                        new_node.set_name(pdg_node.get_name())
                        new_node.set_sensitive_node(True)
                        new_node.set_line_number(pdg_node.get_line_number())
                        new_node.set_line_number_end(pdg_node.get_line_number_end())
                        new_node.set_column_number(pdg_node.get_column_number())
                        new_node.set_column_number_end(pdg_node.get_column_number_end())
                        new_node.set_belong_to_pdg(pdg_node.get_belong_to_pdg())
                        new_node.set_file_path(pdg_node.get_file_name())
                        new_node.set_node_type(pdg_node.get_node_type())
                        new_node.set_class_list(category_list[i:i + 1])
                        new_node.set_category_description(category_doc[category_list[i]])
                        self.nodes[new_node.get_id()] = new_node
                        self.out_edges[new_node.get_id()] = set()
                        if current_node_id in self.out_edges:

                            tails = self.out_edges[current_node_id]
                            for tail in tails:
                                self.out_edges[new_node.get_id()].add(tail)

                                old_edge = self.edges[(current_node_id, tail)]
                                old_edge_attr = old_edge.get_attr()
                                new_edge = Edge((new_node.get_id(), tail))
                                new_edge.change_attr(old_edge_attr)
                                self.edges[(new_node.get_id(), tail)] = new_edge
                                del self.edges[(current_node_id, tail)]

                            self.out_edges[current_node_id].clear()
                            self.out_edges[current_node_id].add(new_node.get_id())
                            edge = Edge((current_node_id, new_node.get_id()))
                            edge.set_attr('DDG')
                            self.edges[(current_node_id, new_node.get_id())] = edge
                        else:
                            self.out_edges[current_node_id] = set()
                            self.out_edges[current_node_id].add(new_node.get_id())
                            edge = Edge((current_node_id, new_node.get_id()))
                            edge.set_attr('DDG')
                            self.edges[(current_node_id, new_node.get_id())] = edge
                        current_node_id = new_node.get_id()
                        sensitive_node_list.append(new_node)

        if len(sensitive_node_list) == 0:
            return None

        for sensitive_node in sensitive_node_list:
            start_node = sensitive_node.get_id()
            self.sensitive_behavior.add_node(start_node, sensitive_node)
            self.visited.clear()
            self.visited.add(start_node)
            if start_node in self.out_edges:

                out_nodes = self.out_edges[start_node]
                self.node_on_path = []

                for out_node in out_nodes:
                    edge_type = self.get_type_of_edge(self.edges[(start_node, out_node)])
                    if edge_type == 'DDG':
                        self.subgraph_extraction_util_ddg(start_node, start_node, out_node)

                self.visited.clear()
                self.visited.add(start_node)
                for out_node in out_nodes:
                    self.subgraph_extraction_util_cfg(start_node, out_node)
        G = nx.DiGraph()
        for node in self.sensitive_behavior.get_nodes().keys():
            pdg_node = self.sensitive_behavior.get_node(node)
            G.add_node(node,
                       label=f"{node}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n"
                             f"{pdg_node.get_code()}\n"
                             f"{pdg_node.get_category_description()}")

        out_edges = self.sensitive_behavior.get_out_edges()
        edges = self.sensitive_behavior.get_edges()
        for head, tails in out_edges.items():
            for tail in tails:
                edge_type = edges[(head, tail)]
                if edge_type == 'DDG':
                    G.add_edge(head, tail, label=edge_type, color='red')
                else:
                    G.add_edge(head, tail, label=edge_type)

    def subgraph_extraction_util_ddg(self, start_node, former_node, current_node):
        edge_type = self.get_type_of_edge(self.edges[(former_node, current_node)])
        if edge_type == 'DDG':

            if current_node in self.visited and current_node != start_node:

                # node has already been traversed and is not the starting point. Update the edges between nodes
                if self.nodes[current_node].is_sensitive_node():
                    self.sensitive_behavior.update_node_on_path(start_node, current_node, self.node_on_path)
                else:
                    pass
            else:
                if self.nodes[current_node].is_sensitive_node():
                    self.visited.add(current_node)

                    # sensitive node
                    self.sensitive_behavior.add_node(current_node, self.nodes[current_node])
                    self.sensitive_behavior.add_edge(start_node, current_node, 'DDG')
                    self.sensitive_behavior.update_node_on_path(start_node, current_node, self.node_on_path)
                else:
                    self.visited.add(current_node)
                    self.node_on_path.append(current_node)
                    if current_node in self.out_edges:
                        next_nodes = self.out_edges[current_node]
                        for next_node in next_nodes:
                            edge_type = self.get_type_of_edge(self.edges[(current_node, next_node)])
                            if edge_type == 'DDG':
                                self.subgraph_extraction_util_ddg(start_node, current_node, next_node)
                    self.node_on_path.pop(-1)
                    self.visited.remove(current_node)

    def subgraph_extraction_util_cfg(self, start_node, current_node):
        if current_node not in self.visited:
            self.visited.add(current_node)
            if self.nodes[current_node].is_sensitive_node():
                edges = self.sensitive_behavior.get_edges()
                if (start_node, current_node) in edges:
                    # already meet
                    pass
                else:
                    # add cfg
                    self.sensitive_behavior.add_node(current_node, self.nodes[current_node])
                    self.sensitive_behavior.add_edge(start_node, current_node, 'CFG')
            else:
                if current_node in self.out_edges:
                    next_nodes = self.out_edges[current_node]
                    for next_node in next_nodes:
                        self.subgraph_extraction_util_cfg(start_node, next_node)

    def match_rule(self, phase: str, package_report: Report):
        """
        @param phase: execution phase
        @param package_report: output report
        """
        rule = PatternList()
        mal_pattern_list = rule.get_pattern_list()
        self.package_report = package_report
        if len(self.sensitive_behavior.get_nodes()) == 0:
            return None
        matched_pattern = []  # already matched pattern
        for pattern in mal_pattern_list:

            head_of_kpr = pattern.get_head_of_kpr()
            for node in self.sensitive_behavior.get_nodes().keys():

                # mapping dict is a direct mapping between nodes of the same type.
                self.mapping_dict.clear()
                pdg_node = self.sensitive_behavior.get_nodes()[node]
                if pdg_node.get_category_description() == head_of_kpr.get_class():

                    # starting point of KPR has the same type as the current point
                    if self.is_in_matched_pattern_list(pattern, matched_pattern):
                        # pattern is contained before
                        continue
                    matched_node_list = self.isomorphism_subgraph_match(pattern)  # list of matched node
                    if matched_node_list:

                        # add pattern to the list
                        matched_pattern.append(pattern)
                        for one_match in matched_node_list:

                            # in the offline phase, annotate this code
                            further_analysis_result = self.pattern_further_analysis(pattern, one_match)
                            if further_analysis_result:
                                file_and_line = self.line_number_file_location(one_match, pattern)
                                self.package_report.add_malicious_locality(phase,
                                                                           pattern.get_maliciousness(),
                                                                           pattern.get_pattern_desc(),
                                                                           file_and_line)

                                self.package_report.set_malicious(True)

    @staticmethod
    def is_in_matched_pattern_list(pattern: Pattern, matched_pattern: list[Pattern]):
        for pattern_in_list in matched_pattern:
            if pattern < pattern_in_list:
                return True
        return False

    def is_reachable(self, head, tail, adjacent):

        # recursively determine whether head and tail are connected in the adjacency matrix
        adjacent_nodes = adjacent[head]
        for node in adjacent_nodes:
            if node == tail:
                return True

        for node in adjacent_nodes:
            return self.is_reachable(node, tail, adjacent)
        return False

    def line_number_file_location(self, one_match, pattern):
        """
        get line and file info
        """
        adjacent = pattern.get_adjacent()
        file_and_line_number = []
        if len(pattern.get_class_list()) == 1:
            for desc in one_match.keys():
                matched_node_id = one_match[desc][0]
                pdg_node = self.nodes[matched_node_id]
                file_and_line_number.append((pdg_node.get_file_name(), pdg_node.get_line_number()))
        else:
            for head, tails in adjacent.items():
                for tail in tails:
                    head_id = one_match[head][0]
                    tail_id = one_match[tail[1]][0]
                    head_node = self.nodes[head_id]
                    tail_node = self.nodes[tail_id]
                    file_and_line_number.append((head_node.get_file_name(), head_node.get_line_number()))
                    file_and_line_number.append((tail_node.get_file_name(), tail_node.get_line_number()))
        return file_and_line_number

    def get_nodes_between_two_nodes(self, start_node, end_node):
        nodes = []
        node_list = []
        visited = set()
        visited.add(start_node)

        def recursive(former, current, end):
            if current not in visited:
                visited.add(current)
                node_list.append(self.sensitive_behavior.get_node_on_path(former, current))
                node_list.append(set(current))
                if current == end:
                    nodes.append(copy.deepcopy(node_list))
                else:
                    for next_node in self.sensitive_behavior.get_out_edges()[current]:
                        if self.sensitive_behavior.get_edges()[(current, next_node)] == 'DDG':
                            recursive(current, next_node, end)
                node_list.pop(-1)
                visited.remove(current)

        successive_node = self.sensitive_behavior.get_out_edges()[start_node]
        for successor in successive_node:
            edge_type = self.sensitive_behavior.get_edges()[(start_node, successor)]
            if edge_type == 'DDG':
                recursive(start_node, successor, end_node)

        all_nodes = set()
        for sub_list in nodes:
            for num_set in sub_list:
                all_nodes |= num_set
        return all_nodes

    def isomorphism_subgraph_match(self, pattern: Pattern):
        """
        graph matching
        :param pattern: graph pattern
        """
        node_id_and_class_list = self.get_node_id_and_class()
        visited = [False] * len(node_id_and_class_list)
        pattern_class_list = pattern.get_class_list()
        matched_node_list = []

        def recursive_match(index):
            if index == len(pattern_class_list):

                # a pair of mapping lists has been found where the number of matches is consistent with the number of pattern class lists
                if len(self.mapping_dict) == len(pattern_class_list) and \
                        self.is_isomorphism_subgraph(self.mapping_dict, pattern):
                    matched_node_list.append(copy.deepcopy(self.mapping_dict))
                return

            node_in_pattern = pattern_class_list[index]  # node in pattern
            if node_in_pattern in self.mapping_dict:
                recursive_match(index + 1)
            else:
                for i in range(len(node_id_and_class_list)):
                    node_in_behavior = node_id_and_class_list[i]
                    if node_in_pattern == node_in_behavior[1] and not visited[i]:
                        # same description
                        visited[i] = True
                        self.mapping_dict[node_in_pattern] = node_in_behavior
                        recursive_match(index + 1)
                        self.mapping_dict.pop(node_in_pattern)
                        visited[i] = False

        recursive_match(0)
        return matched_node_list

    def is_isomorphism_subgraph(self, mapping_dict: dict[str, tuple[int, str]], pattern: Pattern):

        # mapping_dict: dict[node_class[], tuple[node_id, node_class]]
        # verify mapping
        if len(pattern.get_class_list()) > 1:
            adjacent = pattern.get_adjacent()
            for head_class, edge_tail_list in adjacent.items():
                for edge_tail in edge_tail_list:
                    head_in_behavior = mapping_dict[head_class]
                    tail_in_behavior = mapping_dict[edge_tail[1]]
                    edge_type = edge_tail[0]
                    if not self.reachable(head_in_behavior[0], tail_in_behavior[0], edge_type):
                        return False
        else:
            return True

        return True

    def get_node_id_and_class(self) -> list[(int, str)]:
        node_id_and_description_list: list[(int, str)] = []
        for node_id in self.sensitive_behavior.get_nodes().keys():
            node_id_and_description_list.append((node_id, self.nodes[node_id].get_category_description()))
        return node_id_and_description_list

    def reachable(self, head: int, tail: int, edge_type):
        """
        check if there is a path between two nodes, and the path type is edge_type
        """
        out_edges = self.sensitive_behavior.get_out_edges()
        successive_nodes = set()
        if head in out_edges:
            successive_nodes = out_edges[head]
        visited = set()
        visited.add(head)

        def cfg_dfs(_node):

            # the type is cfg
            if _node not in visited:
                visited.add(_node)
                if _node == tail:
                    return True
                if _node in self.sensitive_behavior.get_out_edges():
                    for next_node in self.sensitive_behavior.get_out_edges()[_node]:
                        if cfg_dfs(next_node):
                            return True

        def ddg_dfs(_node):

            # the type is ddg
            if _node not in visited:
                visited.add(_node)
                if _node == tail:
                    return True
                if _node in self.sensitive_behavior.get_out_edges():
                    for next_node in self.sensitive_behavior.get_out_edges()[_node]:
                        _in_edge = self.sensitive_behavior.get_edges()[(_node, next_node)]
                        if _in_edge == 'DDG':
                            if ddg_dfs(next_node):
                                return True
                    visited.remove(_node)

        for i in successive_nodes:
            if edge_type == 'CFG':
                if cfg_dfs(i):
                    return True
            else:

                # the edge type is DDG, and it must also be connected by a DDG edge in the original graph.
                in_edge = self.sensitive_behavior.get_edges()[(head, i)]
                if in_edge == 'DDG':
                    if ddg_dfs(i):
                        return True
        return False

    @staticmethod
    def get_type_of_edge(edge: Edge):
        attr_list = edge.get_attr()
        for attr in attr_list:
            if 'DDG' in attr:
                return 'DDG'
        return 'CFG'

    def add_node(self, node: PDGNode):
        """
        add node to result
        """
        self.nodes[node.get_id()] = node

    def add_edge(self, head: int, tail: int, edge_attr: list):
        """
        add edge
        """
        if head in self.out_edges and tail in self.out_edges[head]:
            return
        if (head, tail) not in self.edges:

            edge = Edge((head, tail))
            for attr in edge_attr:
                edge.set_attr(attr)
            self.edges[(head, tail)] = edge
        if head in self.out_edges:
            self.out_edges[head].add(tail)
        else:
            self.out_edges[head] = set()
            self.out_edges[head].add(tail)

        if tail in self.in_edges:
            self.in_edges[tail].add(head)
        else:
            self.in_edges[tail] = set()
            self.in_edges[tail].add(head)

    def delete_edge(self, head: int, tail: int):
        if head in self.out_edges and tail in self.out_edges[head]:
            self.out_edges[head].remove(tail)
        if tail in self.in_edges and head in self.in_edges[tail]:
            self.in_edges[tail].remove(head)
        if (head, tail) in self.edges:
            self.edges.pop((head, tail))

    def get_out_edges(self) -> dict[int, set[int]]:
        return self.out_edges

    def get_in_edges(self) -> dict[int, set[int]]:
        return self.in_edges

    def node_is_in(self, node: PDGNode):
        return node.get_id() in self.nodes

    def set_entrance_node(self, node: PDGNode):
        self.entrance_node = node

    def get_entrance_node(self) -> PDGNode:
        return self.entrance_node

    def set_return_node(self, node: PDGNode):
        self.return_node.append(node)

    def get_return_value(self) -> list[PDGNode]:
        return self.return_node

    def get_nodes(self) -> dict[int, PDGNode]:
        return self.nodes

    def get_edges(self) -> dict[tuple[int, int], Edge]:
        return self.edges

    def add_batch_nodes(self, nodes: dict[int, PDGNode]):
        for key, value in nodes.items():
            if key not in self.nodes:
                self.nodes[key] = value

    def add_batch_edges(self, edges: dict[tuple[int, int], Edge]):
        for key, value in edges.items():
            if key not in self.edges:
                self.edges[key] = value

    def add_batch_in_edges(self, in_edges: dict[int, set[int]]):
        for key, value in in_edges.items():
            if key not in self.in_edges:
                self.in_edges[key] = value
            else:
                self.in_edges[key].update(value)

    def add_batch_out_edges(self, out_edges: dict[int, set[int]]):
        for key, value in out_edges.items():
            if key not in self.out_edges:
                self.out_edges[key] = value
            else:
                self.out_edges[key].update(value)

    @staticmethod
    def is_ddg_with_specific_name(edge: Edge, ddg_value: str):
        edge_attr = edge.get_attr()
        for attr in edge_attr:
            if attr == f'DDG: {ddg_value}':
                return True
        return False
