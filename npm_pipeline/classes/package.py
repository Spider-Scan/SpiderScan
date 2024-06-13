from __future__ import annotations

import copy
import os
from npm_pipeline.classes.package_json import PackageJson
from common_classes.cpg import CPG
from common_classes.pdg import PDG
from common_classes.pdg_node import PDGNode
from common_classes.cpg_node import CPGNode
from npm_pipeline.classes.depth_tree import DepthTree
from npm_pipeline.classes.file import File
from common_classes.cpg_pdg_edge import Edge
from npm_pipeline.classes.identifier import Identifier
from common_classes.result import Result
from ast_parser import ASTParser
import re
import npm_pipeline.database as db_query
from common_classes.report import Report
from script_further_analysis import analysis_shell_type_command
from status import *
from module2class import get_class
from category import category_doc


def joint(result: Result, sub_result: Result):
    sub_result_entrance = sub_result.get_entrance_node()
    if not result.node_is_in(sub_result_entrance):
        sub_result_nodes = sub_result.get_nodes()
        sub_result_in_edges = sub_result.get_in_edges()
        sub_result_out_edges = sub_result.get_out_edges()
        sub_result_edges = sub_result.get_edges()
        result.add_batch_nodes(sub_result_nodes)
        result.add_batch_in_edges(sub_result_in_edges)
        result.add_batch_out_edges(sub_result_out_edges)
        result.add_batch_edges(sub_result_edges)


class Package:
    def __init__(self, package_name, package_dir, pdg_dir, cpg_dir):
        self.package_name: str = package_name
        self.package_dir: str = package_dir
        self.pdg_dir = pdg_dir
        self.cpg_dir = cpg_dir
        self.js_file_number = 0
        self.install_time_behavior = None
        self.import_time_behavior = None
        self.runtime_time_behavior = None
        self.package_report = Report()
        self.program_behavior: dict[str, Result] = {}
        self.package_json = PackageJson(self.package_dir)
        self.js_file_list = self.__iterate_file()
        self.files: dict[str, File] = {}
        self.depth_trees: dict[str, DepthTree] = {}
        for js_file, raw_code in self.js_file_list.items():
            self.files[js_file] = File(js_file, raw_code)
            self.depth_trees[js_file] = DepthTree(js_file)
        self.cpg = CPG(self.cpg_dir)  # read the cpg dot
        self.__build_pdg_dict()  # read the pdg dot
        self.local_module_call_dict: dict[int, PDGNode] = {}
        self.function_call_dict: dict[int, PDGNode] = {}
        self.download_failed_package = set()

    def __iterate_file(self) -> dict[str, list]:
        """
        iterate all the .js files in the package
        :return: list containing package/index.js and other.js files
        """
        js_files = {}
        for root, dirs, files in os.walk(self.package_dir):
            for file in files:
                if file.endswith('.js'):
                    self.js_file_number += 1
                    raw_code = []
                    with open(os.path.join(root, file), 'r') as code_file:
                        for line in code_file:
                            raw_code.append(line.strip())
                    js_files[os.path.relpath(os.path.join(root, file), self.package_dir)] = raw_code
        return js_files

    def get_file_number(self):
        return self.js_file_number

    def __build_pdg_dict(self):
        dot_names = os.listdir(self.pdg_dir)

        # key: (first node id, name, full name, file)
        self.pdg_dict: dict[int, PDG] = {}
        self.pdg_analyzed: dict[int, bool] = {}
        for dot in dot_names:
            dot_path = os.path.join(self.pdg_dir, dot)
            pdg = PDG(pdg_path=dot_path, cpg=self.cpg)
            if pdg.is_empty():
                continue
            name = pdg.get_name()
            filename = pdg.get_file_name()
            if name is None or filename == '<empty>' or not filename.endswith('.js'):
                continue

            self.pdg_dict[pdg.get_first_node_id()] = pdg
            self.pdg_analyzed[pdg.get_first_node_id()] = False

    def analyse_script(self, report_dir: str, generate_report: bool):
        """
        analyze scripts in the package.json
        """
        report_path = os.path.join(report_dir, self.package_name)
        install_time_scripts = self.package_json.install_time_analyze(report_path)
        for phase, script in install_time_scripts.items():
            if script.get_script_type() == 'Shell Command':
                if script.is_malicious():
                    self.package_report.set_malicious(True)
                    self.package_report.add_phase_to_install_script(phase, script.to_dict_shell_command())
        if generate_report:
            self.package_report.write_to_file(report_path)
        if self.package_report.get_malicious():
            return STATUS_MALICIOUS
        else:
            return STATUS_BENIGN

    def analyse(self, report_dir: str, generate_report: bool):
        """
        install-time, import-time, run-time
        """

        def install_time_scripts_analysis():

            self.initialize_depth_trees()
            print("****Install Time Scripts Analysis****")
            install_time_scripts = self.package_json.install_time_analyze(report_path)
            for phase, script in install_time_scripts.items():
                analyzed_file = []
                if script.need_static():

                    files = script.get_running_files()
                    for file in files:
                        if file in analyzed_file and self.is_sensitive_file_extension(file):
                            if generate_report:
                                self.package_report.set_malicious(True)
                                self.package_report.add_phase_to_install_script(phase, script.to_dict_node())
                            continue
                        if not file.endswith('.js'):
                            continue
                        analyzed_file.append(file)
                        install_time_behavior = None
                        file_relative_path = os.path.normpath(os.path.join('package', file))

                        find_pdg = False
                        for key, value in self.pdg_dict.items():

                            if value.get_name() == ':program' and value.get_file_name() == file_relative_path:
                                find_pdg = True
                                if file_relative_path in self.program_behavior:
                                    install_time_behavior = self.program_behavior[file_relative_path]
                                else:
                                    install_time_behavior = self.behavior_gen(file_relative_path, value,
                                                                              desc='program')
                                    self.program_behavior[file_relative_path] = install_time_behavior
                                    self.pdg_analyzed[key] = True
                                break
                        if install_time_behavior is not None:
                            install_time_behavior.sensitive_subgraph_extraction(self.cpg, self.package_report)
                            if generate_report:
                                install_time_behavior.match_rule('INSTALL', self.package_report)
                else:
                    if script.get_script_type() == 'Shell Command':
                        res = analysis_shell_type_command(script)
                        if res is True:
                            self.package_report.set_malicious(True)
                            self.package_report.add_phase_to_install_script(phase, script.to_dict_shell_command())
            if generate_report:
                self.package_report.write_to_file(report_path)

        def import_time_analysis():
            self.initialize_depth_trees()
            print("****Import Time analysis****")
            main_js = self.package_json.get_main()
            main_relative_path = os.path.normpath(os.path.join('package', main_js))
            find_main_pdg = False
            for key, value in self.pdg_dict.items():
                if value.get_name() == ':program' and value.get_file_name() == main_relative_path:
                    find_main_pdg = True
                    if main_relative_path in self.program_behavior:
                        pass
                    else:
                        import_time_behavior = self.behavior_gen(main_relative_path, value, desc='program')
                        self.program_behavior[main_relative_path] = import_time_behavior
                        self.pdg_analyzed[key] = True
                        if import_time_behavior is not None:
                            import_time_behavior.sensitive_subgraph_extraction(self.cpg, self.package_report)
                            if generate_report:
                                import_time_behavior.match_rule('IMPORT', self.package_report)
                    break
            if generate_report:
                self.package_report.write_to_file(report_path)

        def run_time_analysis():
            print('****Run Time analysis****')
            for key, value in self.pdg_dict.items():
                if self.pdg_analyzed[key] is False:
                    self.pdg_analyzed[key] = True
                    self.initialize_depth_trees()
                    file_name = value.get_file_name()

                    file_pdg = [_value for key, _value in self.pdg_dict.items() if
                                _value.get_name() == ':program' and _value.get_file_name() == file_name]
                    if len(file_pdg) == 0:
                        return
                    file_pdg = file_pdg[0]
                    background = self.behavior_gen(file_name, file_pdg, 'program')
                    function_call_behavior = self.behavior_gen(file_name, value, 'function')
                    background_nodes = background.get_nodes()
                    function_nodes = function_call_behavior.get_nodes()

                    in_edges = copy.deepcopy(function_call_behavior.get_in_edges())
                    for tail, heads in in_edges.items():
                        for head in heads:
                            if head not in function_nodes and head in background_nodes:
                                function_call_behavior.add_node(background_nodes[head])
                                visited = set()

                                self.add_previous_util(head, background, function_call_behavior, visited)
                    if function_call_behavior is not None:
                        function_call_behavior.sensitive_subgraph_extraction(self.cpg, self.package_report)
                        if generate_report:
                            function_call_behavior.match_rule("RUN TIME", self.package_report)

            if generate_report:
                self.package_report.write_to_file(report_path)

        report_path = os.path.join(report_dir, self.package_name)
        install_time_scripts_analysis()
        import_time_analysis()
        run_time_analysis()
        if self.package_report.get_malicious():
            return STATUS_MALICIOUS
        else:
            return STATUS_BENIGN

    def add_previous_util(self, current_node: int, background: Result, result: Result, visited: set):
        if current_node not in visited:
            visited.add(current_node)
            if current_node in background.get_in_edges():

                heads = background.get_in_edges()[current_node]
                for head in heads:
                    result.add_node(background.get_nodes()[head])
                    edge = background.get_edges()[(head, current_node)]
                    result.add_edge(head, current_node, edge.get_attr())
                    self.add_previous_util(head, background, result, visited)

    def behavior_gen(self, filename: str, pdg: PDG, desc: str):
        """
        generate the behavior
        :param filename: pdg file
        :param pdg: PDG
        :param desc: current type
        :return: behavior
        """
        nodes = pdg.get_nodes()
        first_node = nodes[pdg.get_first_node_id()]
        visited = set()
        result = Result(self.cpg, self.pdg_dict, self.package_dir, self.package_name)
        result.set_entrance_node(first_node)
        self.behavior_gen_util(current_node=first_node,
                               former_node=first_node,
                               pdg=pdg,
                               filename=filename,
                               visited=visited,
                               result=result)
        return result

    def initialize_depth_trees(self):
        for file, tree in self.depth_trees.items():
            # empty the tree
            tree.clean()
        for key, value in self.pdg_dict.items():
            name = value.get_name()
            if not re.search(r'<lambda>\d*', name) and name != ':program':
                filename = value.get_file_name()
                if filename in self.files:
                    self.files[filename].add_function(name)
                    parameter_count = self.get_parameter_count(value)
                    function_identifier = Identifier(name=name, line_number=1,
                                                     type_='FUNCTION_DECLARE',
                                                     file=filename, node_id=None,
                                                     pdg=value, parameter_count=parameter_count)

                    # add to the root node
                    self.depth_trees[filename].add_identifier(function_identifier)

    @staticmethod
    def get_parameter_count(pdg: PDG):
        nodes = pdg.get_nodes()
        count = 0
        for node in nodes.values():
            label = node.get_node_type()
            if label == 'PARAM,this':
                pass
            elif 'PARAM,...' in label:
                return 1000
            elif 'PARAM' in label:
                count += 1
            else:
                pass
        return count

    def behavior_gen_util(self,
                          current_node: PDGNode,
                          former_node: PDGNode,
                          pdg: PDG,
                          filename: str,
                          visited: set,
                          result: Result):
        """
        behavior generation util
        """
        if former_node == current_node:
            in_edge = None
        else:
            in_edge = pdg.get_edges()[(former_node.get_id(), current_node.get_id())]
        if current_node.get_id() not in visited:
            result.add_node(current_node)

            visited.add(current_node.get_id())
            if current_node.is_entrance():
                pass
            elif current_node.get_node_type() == 'RETURN':

                result.set_return_node(current_node)
                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                current_node.set_is_return_value(True)
            elif current_node.get_node_type() == 'METHOD_PARAMETER_IN':

                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                parameter_name = current_node.get_name()
                if parameter_name != 'this':
                    identifier = Identifier(name=parameter_name,
                                            line_number=current_node.get_line_number(),
                                            type_='IDENTIFIER',
                                            node_id=current_node.get_id(),
                                            pdg=pdg,
                                            file=filename)
                    self.depth_trees[filename].add_identifier(identifier)

            elif current_node.get_node_type() == 'CALL':

                # call node process
                self.call_node_process(current_node=current_node, former_node=former_node, pdg=pdg, filename=filename,
                                       result=result, in_edge=in_edge)
            else:

                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                pass

            out_edges = pdg.get_out_edges()
            if current_node.get_id() in out_edges:

                successive_node_ids = out_edges[current_node.get_id()]
                node_id_list = []
                for successive_node_id in successive_node_ids:
                    out_edge = pdg.get_edges()[(current_node.get_id(), successive_node_id)]

                    if self.get_type_of_edge(out_edge) == 'CFG':
                        node_id_list.insert(0, ('CFG', successive_node_id))
                    else:
                        node_id_list.append(('DDG', successive_node_id))

                start_index = 0
                for tuple_ in node_id_list:
                    if tuple_[0] == 'CFG':
                        start_index += 1

                sorted_array = node_id_list[start_index:]
                sorted_array = sorted(sorted_array, key=lambda x: pdg.get_nodes()[x[1]].get_line_number())
                node_id_list = node_id_list[:start_index] + sorted_array

                for node_id in node_id_list:
                    self.behavior_gen_util(current_node=pdg.get_nodes()[node_id[1]], former_node=current_node, pdg=pdg,
                                           filename=filename, visited=visited, result=result)
        else:

            type_of_in_edge = self.get_type_of_edge(in_edge)
            if current_node.get_node_type() == '<operator>.formatString':

                if former_node.get_call_type() == 'FUNCTION_CALL' or former_node.get_call_type() == 'LOCAL_MODULE_CALL':

                    self.add_the_return_value_to_current_node(former_node, current_node, in_edge, result)
                else:

                    result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
            elif type_of_in_edge == 'DDG':

                if current_node.get_call_type() == 'ASSIGNMENT':

                    if (former_node.get_call_type() == 'FUNCTION_CALL' or
                            former_node.get_call_type() == 'LOCAL_MODULE_CALL'):
                        self.add_the_return_value_to_current_node(former_node, current_node, in_edge, result)
                    else:

                        result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                elif (current_node.get_call_type() == 'FUNCTION_CALL' or
                      current_node.get_call_type() == 'LOCAL_MODULE_CALL' or
                      current_node.get_call_type() == 'lambda'):

                    result_of_call = current_node.get_diagram_of_call()
                    if result_of_call:

                        entrance_of_result = result_of_call.get_entrance_node()
                        if entrance_of_result:

                            if (former_node.get_call_type() == 'FUNCTION_CALL' or
                                    former_node.get_call_type() == 'LOCAL_MODULE_CALL'):

                                self.add_the_return_value_to_current_node(former_node, current_node, in_edge, result)

                            else:

                                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

                            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

                        else:

                            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                else:
                    result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

            else:
                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def add_the_return_value_to_current_node(self, former_node: PDGNode, current_node: PDGNode, in_edge: Edge,
                                             result: Result):
        result_of_call = former_node.get_diagram_of_call()
        if result_of_call:
            return_value_list = result_of_call.get_return_value()
            if return_value_list:

                type_of_in_edge = self.get_type_of_edge(in_edge)
                if type_of_in_edge == 'DDG':
                    attr_list = in_edge.get_attr()
                else:
                    attr_list = ['DDG']
                for return_value in return_value_list:
                    result.add_edge(return_value.get_id(), current_node.get_id(), attr_list)
            else:

                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
        else:

            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    @staticmethod
    def get_type_of_edge(edge: Edge):
        attr_list = edge.get_attr()
        for attr in attr_list:
            if 'DDG' in attr:
                return 'DDG'
        return 'CFG'

    def is_local_js_file(self, filename, import_entity):
        if import_entity.startswith('.') or import_entity.startswith('/'):
            return True
        dir_name = os.path.dirname(filename)
        if import_entity.endswith('.js'):
            return True
        else:
            if re.search(r'\b\w+\.(\w+)\b$', import_entity):
                return True
            else:
                normpath = os.path.normpath(os.path.join(dir_name, import_entity)) + '.js'
                if normpath in self.files:
                    return True
                else:
                    return False

    def call_node_process(self,
                          current_node: PDGNode,
                          former_node: PDGNode,
                          pdg: PDG,
                          filename: str,
                          result: Result,
                          in_edge: Edge):

        depth_tree = self.depth_trees[filename]
        call_name = current_node.get_name()
        if call_name == '<operator>.assignment':
            self.assignment_process(current_node, former_node, pdg, filename, depth_tree, result, in_edge)

        if call_name == '<operator>.assignmentPlus':

            self.assignment_plus_process(current_node, former_node, pdg, filename, depth_tree, result, in_edge)

        elif call_name == '<operator>.formatString':

            if former_node.get_call_type() == 'FUNCTION_CALL' or former_node.get_call_type() == 'LOCAL_MODULE_CALL':
                self.add_the_return_value_to_current_node(former_node, current_node, in_edge, result)
            else:
                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
        elif call_name == '<operator>.new':
            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
            code = current_node.get_code()
            new_query = '(new_expression(identifier)@id)'
            ast_parser = ASTParser(code, 'javascript')
            new_object = ast_parser.query_oneshot(new_query)
            if new_object is not None:
                new_object = new_object.text.decode()
                if new_object == 'Function':
                    current_node.set_sensitive_node(True)
                    current_node.set_class_list(['39'])
        else:

            if call_name == 'require':
                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                self.require_process(current_node, pdg, filename, result)

            # function or method call
            elif call_name is not None \
                    and self.is_legal_js_function_call_name(call_name) \
                    and '<operator>' not in call_name \
                    and re.search(r'<lambda>\d*', call_name) is None:
                if call_name == 'then':
                    result.add_edge(former_node.get_id(), current_node.get_id(), ['DDG'])
                else:
                    result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
                self.function_or_method_call_process(current_node, pdg, call_name, depth_tree, result, in_edge)
            else:
                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

        # lambda function
        lambda_pdg = self.get_lambda_pdg(current_node)
        if lambda_pdg:
            self.lambda_function(current_node, depth_tree, lambda_pdg, result)

    @staticmethod
    def is_legal_js_function_call_name(call_name):
        if not re.match(r'^[a-zA-Z$_][a-zA-Z0-9$_]*$', call_name):
            return False
        else:
            return True

    def assignment_process(self,
                           current_node: PDGNode,
                           former_node: PDGNode,
                           pdg: PDG,
                           filename: str,
                           depth_tree: DepthTree,
                           result: Result,
                           in_edge: Edge,
                           ):
        ast = self.cpg.get_child_ast(current_node.get_id())
        current_node.set_call_type('ASSIGNMENT')
        left_ast_node = ast[0]  # left side
        right_ast_node = ast[1]  # right side
        identifier_name = left_ast_node.get_value('CODE')

        if right_ast_node.get_value('label') == 'METHOD_REF':
            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
            return

        identifier = Identifier(name=identifier_name,
                                line_number=current_node.get_line_number(),
                                type_='IDENTIFIER',
                                node_id=current_node.get_id(),
                                pdg=pdg,
                                file=filename)
        depth_tree.add_identifier(identifier)

        right_ast_type = right_ast_node.get_value('label')
        right_ast_name = right_ast_node.get_value('NAME')
        if right_ast_type == 'CALL':
            if right_ast_name == 'require':
                self.right_call_is_require(identifier, former_node, current_node, right_ast_node, result, in_edge)

            elif right_ast_name == '<operator>.addition':
                self.right_call_is_addition(former_node, current_node, result, in_edge)

            elif right_ast_name == '<operator>.fieldAccess' or right_ast_name == '<operator>.indexAccess':
                self.right_call_is_field_index_access(identifier, former_node, current_node, right_ast_node,
                                                      result, depth_tree, in_edge, pdg)

            elif self.is_local_module_call(right_ast_node.get_id()):
                self.right_call_is_local_module_call(identifier, former_node, current_node, right_ast_node, result)
            elif self.is_function_call(right_ast_node.get_id()):
                self.right_call_is_function_call(identifier, former_node, current_node, right_ast_node, result)
            elif right_ast_node.get_id() in pdg.get_nodes() and (
                    pdg.get_nodes()[right_ast_node.get_id()].get_call_type() == 'CALL'):

                right_call_pdg_node = pdg.get_nodes()[right_ast_node.get_id()]
                call_full_name = right_call_pdg_node.get_call_full_name()
                identifier.set_type('RETURN_OBJECT')
                if call_full_name:
                    identifier.set_full_name(call_full_name)
                if right_call_pdg_node.get_call_original_derivation() == 'builtin':
                    identifier.set_original_right_type('builtin')
                elif right_call_pdg_node.get_call_original_derivation() == 'third':
                    identifier.set_original_right_type('third')

                if right_call_pdg_node.is_sensitive_node():
                    # right call is sensitive
                    identifier.set_create_by_sensitive_call(True)
                    identifier.set_category_list_from_call(right_call_pdg_node.get_class_list())

                result.add_edge(former_node.get_id(), current_node.get_id(), ['DDG'])
            else:
                result.add_edge(former_node.get_id(), current_node.get_id(), ['DDG'])
        elif right_ast_type == 'IDENTIFIER':

            self.right_is_identifier(identifier, former_node, current_node, right_ast_node, depth_tree, result, in_edge,
                                     pdg)
        elif right_ast_type == 'BLOCK':

            self.right_is_block(identifier, former_node, current_node, right_ast_node, depth_tree, result, in_edge, pdg)
        else:

            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def assignment_plus_process(self,
                                current_node: PDGNode,
                                former_node: PDGNode,
                                pdg: PDG,
                                filename: str,
                                depth_tree: DepthTree,
                                result: Result,
                                in_edge: Edge):
        ast = self.cpg.get_child_ast(current_node.get_id())
        current_node.set_call_type('ASSIGNMENT')
        left_ast_node = ast[0]  # left side
        right_ast_node = ast[1]  # right side
        identifier_name = left_ast_node.get_value('CODE')
        identifier_found = depth_tree.find(identifier_name, current_node.get_line_number())
        if identifier_found:
            result.add_edge(current_node.get_id(), identifier_found.get_node_id(), [f'DDG: {identifier_name}'])
        result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def require_process(self, current_node: PDGNode, pdg: PDG, filename: str, result: Result):

        require_code = current_node.get_code()
        query_str = '(call_expression(arguments(string(string_fragment)@ar)))'
        ast_parser = ASTParser(require_code, 'javascript')
        parser_res = ast_parser.query_oneshot(query_str)
        import_entity = None
        if parser_res is not None:
            import_entity = parser_res.text.decode()
        else:
            pass

        if import_entity is not None:
            if db_query.find_in_database(import_entity, 'npm') == 'BUILTIN':
                return

            # get the import entity successfully
            is_local = self.is_local_js_file(filename, import_entity)
            if is_local:

                # local module
                dir_name = os.path.dirname(filename)
                if import_entity.endswith('.js'):
                    import_entity = import_entity[:-3]
                normpath = os.path.normpath(os.path.join(dir_name, import_entity)) + '.js'
                if normpath in self.files:

                    # local module process and connected use cfg
                    find_pdg = False
                    for key, pdg in self.pdg_dict.items():
                        if pdg.get_name() == ':program' and pdg.get_file_name() == normpath:
                            self.pdg_analyzed[key] = True
                            require_result = self.behavior_gen(normpath, pdg, 'program')
                            result.add_edge(current_node.get_id(), require_result.get_entrance_node().get_id(), ['CFG'])
                            joint(result, require_result)
                            find_pdg = True
                            break
                    if not find_pdg:
                        pass

    def function_or_method_call_process(self,
                                        current_node: PDGNode,
                                        pdg: PDG,
                                        call_name: str,
                                        depth_tree: DepthTree,
                                        result: Result,
                                        in_edge: Edge,
                                        ):
        current_node.set_call_type('CALL')
        code = current_node.get_code()
        ast_parser = ASTParser(code, 'javascript')

        # tree-sitter query
        call_expression = """
                            (expression_statement
	                            (call_expression
    	                            (identifier)@id
                                )
                            )@ex
        """

        subscript_expression = """
                                (expression_statement
	                                (call_expression
    	                                (subscript_expression)@su
                                    )
                                )@ex
        """

        member_expression_1 = """
                            (expression_statement
	                            (call_expression
		                            function: (member_expression
			                            object:(identifier)@identifier
			                            property:(property_identifier)@property
		                            )@member_expression
	                            )
                            )@ex
        """

        member_expression_2 = """
                            (expression_statement
	                            (call_expression
                                    function: (member_expression
                                        object:(call_expression
                                            (member_expression
                                                object: (identifier)@identifier
                                                property: (property_identifier)@pro_identifier
                                                )
                                            )@call_expression
                                        property:(property_identifier)@out_pro_identifier
                                    )@member_expression
                                )
                            )@ex
        """

        member_expression_3 = """
                            (expression_statement
                                (call_expression
                                    function: (member_expression
                                        object:(member_expression
                                            object:(identifier)@identifier
                                            property:(property_identifier)@inner_property_identifier
                                        )
                                        property:(property_identifier)@outer_property_identifier
                                    )@member_expression
                                )
                            )@ex
        """

        require_member_expression = """
                                    (expression_statement
                                        (call_expression
                                            (member_expression
                                                object: (call_expression
                                                    function: (identifier)@identifier
                                                    arguments: (arguments
                                                        (string)@string
                                                    )
                                                )
                                                property: (property_identifier)@property_identifier
                                            )
                                        )
                                    )@ex
        """

        error_member_call_expression = '(ERROR(member_expression(call_expression(identifier))@ca(property_identifier)@pro))'

        error_member_expression = """
                                (ERROR
                                    (member_expression
                                        object: (identifier)@identifier
                                        property: (property_identifier)@pro_identifier
                                    )
                                )@ex
        """

        matched_subscript = ast_parser.query(subscript_expression)
        matched_call_expression = ast_parser.query(call_expression)
        error_member_call_expression = ast_parser.query(error_member_call_expression)
        error_member_expression = ast_parser.query(error_member_expression)
        matched_member_expression_1 = ast_parser.query(member_expression_1)
        matched_member_expression_2 = ast_parser.query(member_expression_2)
        matched_member_expression_3 = ast_parser.query(member_expression_3)
        require_member_expression = ast_parser.query(require_member_expression)

        if matched_call_expression:
            ex = matched_call_expression[0][0]
            if not self.is_top_expression_statement(ex):
                matched_call_expression = None

        if matched_subscript:
            ex = matched_subscript[0][0]
            if self.is_top_subscript(ex):
                return
        if matched_call_expression:
            self.connect_by_param(current_node, depth_tree, result, pdg)
            self.single_call_name(current_node, call_name, depth_tree, result, in_edge)
        elif error_member_call_expression:
            call_expressions = [r[0].text.decode() for r in error_member_call_expression if r[1] == 'ca']
            properties = [r[0].text.decode() for r in error_member_call_expression if r[1] == 'pro']
            first_call_expression = call_expressions[0]
            first_property = properties[0]
            if first_property == call_name:
                qualifier = first_call_expression
            else:
                return

        elif error_member_expression:
            identifiers = [r[0].text.decode() for r in error_member_expression if r[1] == 'identifier']
            properties = [r[0].text.decode() for r in error_member_expression if r[1] == 'pro_identifier']
            first_identifier = identifiers[0]
            first_property = properties[0]
            if first_property == call_name:
                qualifier = first_identifier
                if qualifier == ' this':
                    return
                self.connect_by_param(current_node, depth_tree, result, pdg)
                qualifier_found = depth_tree.find(qualifier, current_node.get_line_number())
                if qualifier_found:

                    # qualifier found
                    original_identifier = qualifier_found.get_original_identifier()
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), qualifier_found.get_node_id(),
                                                          pdg):
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(),
                                        [f"DDG: {qualifier_found.get_name()}"])
                    else:
                        attr = pdg.get_edges()[(qualifier_found.get_node_id(), current_node.get_id())].get_attr()
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(), attr)
                    if original_identifier and original_identifier == 'this':
                        return
                    self.qualifier_found_process_with_call_name(call_name, current_node,
                                                                qualifier_found, result, in_edge, pdg)
                else:
                    # qualifier not found
                    # build-in type without require or other
                    self.qualifier_not_found_process_with_call_name(current_node, qualifier, call_name, pdg)
            else:
                return
        elif require_member_expression:

            expression_statement_list = [r[0] for r in require_member_expression if r[1] == 'ex']
            identifier_list = [r[0].text.decode() for r in require_member_expression if r[1] == 'identifier']
            string = [r[0].text.decode() for r in require_member_expression if r[1] == 'string']
            property_identifier = [r[0].text.decode() for r in require_member_expression if
                                   r[1] == 'property_identifier']
            if not self.is_top_expression_statement(expression_statement_list[0]):
                return

            # only for require type
            if identifier_list[0] != 'require':
                return

            if call_name != property_identifier[0]:
                return

            require_entity = string[0][1:-1]
            query_result = db_query.find_in_database(require_entity, 'npm')
            if query_result == 'BUILTIN':
                is_sensitive_call = db_query.is_sensitive_call(require_entity, call_name, 'npm', 'builtin')
                current_node.set_call_full_name(f"{require_entity}.{call_name}")
                current_node.set_call_original_derivation('builtin')
                if is_sensitive_call[0]:
                    current_node.set_sensitive_node(True)
                    current_node.set_class_list(is_sensitive_call[1])
        elif matched_member_expression_1:

            expression_statement_list = [r[0] for r in matched_member_expression_1 if r[1] == 'ex']
            identifier_list = [r[0].text.decode() for r in matched_member_expression_1 if r[1] == 'identifier']
            property_list = [r[0].text.decode() for r in matched_member_expression_1 if r[1] == 'property']
            if not self.is_top_expression_statement(expression_statement_list[0]):
                return
            qualifier = identifier_list[0]
            if call_name != property_list[0]:
                return
            else:

                if qualifier == 'this':
                    return
                self.connect_by_param(current_node, depth_tree, result, pdg)
                qualifier_found = depth_tree.find(qualifier, current_node.get_line_number())
                if qualifier_found:

                    # qualifier found
                    original_identifier = qualifier_found.get_original_identifier()
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), qualifier_found.get_node_id(),
                                                          pdg):
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(),
                                        [f"DDG: {qualifier_found.get_name()}"])
                    else:
                        attr = pdg.get_edges()[(qualifier_found.get_node_id(), current_node.get_id())].get_attr()
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(), attr)
                    if original_identifier and original_identifier == 'this':
                        return
                    self.qualifier_found_process_with_call_name(call_name, current_node,
                                                                qualifier_found, result, in_edge, pdg)
                else:
                    # qualifier not found
                    # build-in type without require or other
                    self.qualifier_not_found_process_with_call_name(current_node, qualifier, call_name, pdg)
        elif matched_member_expression_2:

            expression_statement_list = [r[0] for r in matched_member_expression_2 if r[1] == 'ex']
            identifier_list = [r[0].text.decode() for r in matched_member_expression_2 if r[1] == 'identifier']
            property_identifier_list = [r[0].text.decode() for r in matched_member_expression_2 if
                                        r[1] == 'pro_identifier']
            out_property_identifier_list = [r[0].text.decode() for r in matched_member_expression_2 if
                                            r[1] == 'out_pro_identifier']
            if not self.is_top_expression_statement(expression_statement_list[0]):
                return
            qualifier = identifier_list[0]
            property_name = property_identifier_list[0]
            if call_name != out_property_identifier_list[0]:
                return
            else:
                if qualifier == 'this':
                    return
                self.connect_by_param(current_node, depth_tree, result, pdg)
                qualifier_found = depth_tree.find(qualifier, current_node.get_line_number())
                if qualifier_found:
                    original_identifier = qualifier_found.get_original_identifier()
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), qualifier_found.get_node_id(),
                                                          pdg):
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(),
                                        [f"DDG: {qualifier_found.get_name()}"])
                    else:
                        attr = pdg.get_edges()[(qualifier_found.get_node_id(), current_node.get_id())].get_attr()
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(), attr)
                    if original_identifier and original_identifier == 'this':
                        return

                    # judge qualifier.property_name is a builtin call
                    if qualifier_found.is_builtin():
                        import_entity = qualifier_found.get_import_entity()
                        full_name = f"{import_entity}.{property_name}"
                        full_name_class = get_class(full_name)
                        current_node.set_call_full_name(f"{import_entity}.{property_name}.{call_name}")
                        if full_name_class:
                            is_sensitive_call = db_query.is_sensitive_call(full_name_class, call_name, 'npm', 'builtin')
                        else:
                            is_sensitive_call = db_query.is_sensitive_call(full_name, call_name, 'npm', 'builtin')
                        if is_sensitive_call and is_sensitive_call[0]:
                            current_node.set_sensitive_node(True)
                            current_node.set_class_list(is_sensitive_call[1])
        elif matched_member_expression_3:

            expression_statement_list = [r[0] for r in matched_member_expression_3 if r[1] == 'ex']
            identifier_list = [r[0].text.decode() for r in matched_member_expression_3 if r[1] == 'identifier']
            inner_property_identifier = [r[0].text.decode() for r in matched_member_expression_3 if
                                         r[1] == 'inner_property_identifier']
            outer_property_identifier = [r[0].text.decode() for r in matched_member_expression_3 if
                                         r[1] == 'outer_property_identifier']
            if not self.is_top_expression_statement(expression_statement_list[0]):
                return

            if call_name != outer_property_identifier[0]:
                return

            qualifier = f'{identifier_list[0]}.{inner_property_identifier[0]}'
            if qualifier == 'module.exports':
                return

            qualifier_found = depth_tree.find(qualifier, current_node.get_line_number())
            if qualifier_found:

                if not self.has_ddg_line_of_two_nodes(current_node.get_id(), qualifier_found.get_node_id(), pdg):
                    result.add_edge(qualifier_found.get_node_id(), current_node.get_id(),
                                    [f"DDG: {qualifier_found.get_name()}"])
                else:
                    attr = pdg.get_edges()[(qualifier_found.get_node_id(), current_node.get_id())].get_attr()
                    result.add_edge(qualifier_found.get_node_id(), current_node.get_id(), attr)
                self.qualifier_found_process_with_call_name(call_name, current_node,
                                                            qualifier_found, result, in_edge, pdg)
            else:

                if identifier_list[0] == 'this':
                    return

                self.connect_by_param(current_node, depth_tree, result, pdg)

                identifier_found = depth_tree.find(identifier_list[0], current_node.get_line_number())
                if identifier_found:
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), identifier_found.get_node_id(), pdg):
                        result.add_edge(identifier_found.get_node_id(), current_node.get_id(),
                                        [f"DDG: {identifier_found.get_name()}"])
                    else:
                        attr = pdg.get_edges()[(identifier_found.get_node_id(), current_node.get_id())].get_attr()
                        result.add_edge(identifier_found.get_node_id(), current_node.get_id(), attr)
                    original_identifier = identifier_found.get_original_identifier()
                    if original_identifier and original_identifier == 'this':
                        return
                    self.qualifier_found_has_field_access(call_name, inner_property_identifier[0], current_node,
                                                          identifier_found)
                else:
                    self.qualifier_not_found_has_field_access(call_name, inner_property_identifier[0], current_node,
                                                              identifier_list[0])
        else:
            return

    def local_module_call_process(self, current_node: PDGNode, import_entity: str, function: str,
                                  result: Result, in_edge: Edge):
        file_path = os.path.normpath(os.path.join('package', import_entity))
        if not file_path.endswith('.js'):
            file_path = file_path + '.js'
        local_call_result = None
        find_pdg = False
        for key, value in self.pdg_dict.items():
            if value.get_name() == function and value.get_file_name() == file_path:
                find_pdg = True
                if self.depth_trees[file_path].function_in_depth(function):
                    return None
                self.depth_trees[file_path].add_depth(function)
                self.pdg_analyzed[key] = True

                local_module_call_entrance_id = value.get_first_node_id()

                result.add_edge(current_node.get_id(), local_module_call_entrance_id, ['DDG'])
                local_call_result = self.behavior_gen(file_path, value, 'local module')
                self.depth_trees[file_path].delete_last_depth()
                break
        return local_call_result

    def right_call_is_require(self, identifier: Identifier, former_node: PDGNode, current_node: PDGNode,
                              right_node: CPGNode, result: Result, in_edge: Edge):
        ast_parser = ASTParser(right_node.get_value('CODE'), 'javascript')
        import_entity_query_expression = '(call_expression(arguments(string(string_fragment)@ar)))'
        import_entity = ast_parser.query_oneshot(import_entity_query_expression)
        if import_entity is not None:
            import_entity = import_entity.text.decode()
            is_local_js_file = self.is_local_js_file(current_node.get_file_name(), import_entity)
            if not is_local_js_file:
                query_result = db_query.find_in_database(import_entity, 'npm')
                if query_result == 'BUILTIN':
                    identifier.set_builtin(True)
                elif query_result == 'THIRD_PART':
                    identifier.set_third_part(True)
                elif query_result == 'NOT_IN':
                    identifier.set_third_part(True)

                    if import_entity not in self.download_failed_package:
                        res = db_query.add_to_database(import_entity, self.package_json.get_dependencies(), 'npm')
                        if not res:
                            self.download_failed_package.add(import_entity)

            identifier.set_type("REQUIRE")
            identifier.set_import_entity(import_entity)
            identifier.set_local(is_local_js_file)
        else:
            pass

        result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def right_call_is_addition(self, former_node: PDGNode, current_node: PDGNode, result: Result,
                               in_edge: Edge):
        if self.get_type_of_edge(in_edge) == 'DDG':
            if former_node.get_call_type() == 'FUNCTION_CALL' or former_node.get_call_type() == 'LOCAL_MODULE_CALL':
                self.add_the_return_value_to_current_node(former_node, current_node, in_edge, result)
            else:
                result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def right_call_is_field_index_access(self, identifier: Identifier, former_node: PDGNode,
                                         current_node: PDGNode, right_node: CPGNode, result: Result,
                                         depth_tree: DepthTree, in_edge: Edge, pdg: PDG):
        child_ast = self.cpg.get_child_ast(right_node.get_id())
        left_ast_of_child_ast = child_ast[0]
        right_ast_of_child_ast = child_ast[1]
        left_ast_code = left_ast_of_child_ast.get_value('CODE')
        right_ast_code = right_ast_of_child_ast.get_value('CODE')
        find_left_ast = depth_tree.find(left_ast_code, int(left_ast_of_child_ast.get_value('LINE_NUMBER')))
        if find_left_ast:
            if not self.has_ddg_line_of_two_nodes(current_node.get_id(), find_left_ast.get_node_id(), pdg):
                result.add_edge(find_left_ast.get_node_id(), current_node.get_id(),
                                [f"DDG: {find_left_ast.get_name()}"])
            else:
                attr = pdg.get_edges()[(find_left_ast.get_node_id(), current_node.get_id())].get_attr()
                result.add_edge(find_left_ast.get_node_id(), current_node.get_id(), attr)

            if find_left_ast.get_type() == 'REQUIRE':
                identifier.set_type('FUNCTION_FROM_REQUIRE')
                identifier.set_import_entity(find_left_ast.get_import_entity())
                identifier.set_imported_function(right_ast_code)
                identifier.set_builtin(find_left_ast.is_builtin())
                identifier.set_full_name(f"{find_left_ast.get_import_entity()}.{right_ast_code}")

        elif left_ast_of_child_ast.get_value('NAME') == 'require':
            right_ast_of_child_ast = child_ast[1]
            imported_func = right_ast_of_child_ast.get_value('CODE')
            query_str = '(call_expression(arguments(string(string_fragment)@ar)))'
            ast_parser = ASTParser(left_ast_code, 'javascript')
            query_res = ast_parser.query_oneshot(query_str)
            import_entity = None
            if query_res is not None:
                import_entity = query_res.text.decode()
            else:
                pass
            if import_entity is not None:
                if imported_func == 'default':
                    identifier.set_type('REQUIRE')
                    identifier.set_import_entity(import_entity)
                else:
                    identifier.set_type('FUNCTION_FROM_REQUIRE')
                    identifier.set_import_entity(import_entity)
                    identifier.set_imported_function(imported_func)
                is_local_js_file = self.is_local_js_file(current_node.get_file_name(),
                                                         import_entity)  # local module judge
                if not is_local_js_file:

                    query_res = db_query.find_in_database(import_entity, 'npm')
                    if query_res == 'BUILTIN':
                        identifier.set_builtin(True)
                        identifier.set_full_name(f"{import_entity}.{imported_func}")
                    elif query_res == 'THIRD_PART':
                        identifier.set_third_part(True)
                        identifier.set_full_name(f"{import_entity}.{imported_func}")
                    elif query_res == 'NOT_IN':
                        identifier.set_third_part(True)

                        if import_entity not in self.download_failed_package:
                            res = db_query.add_to_database(import_entity, self.package_json.get_dependencies(), 'npm')
                            if not res:
                                self.download_failed_package.add(import_entity)
                else:
                    identifier.set_local(True)

        result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def right_call_is_local_module_call(self, identifier: Identifier, former_node: PDGNode, current_node: PDGNode,
                                        right_node: CPGNode, result: Result):
        identifier.set_type('LOCAL_MODULE_FUNCTION_RETURN_VALUE')
        return_value_list = self.get_local_module_call_pdg(right_node.get_id()).get_diagram_of_call().get_return_value()
        if return_value_list:
            for value in return_value_list:
                result.add_edge(value.get_id(), current_node.get_id(), ['DDG'])
        else:
            result.add_edge(former_node.get_id(), current_node.get_id(), ['DDG'])

    def right_call_is_function_call(self, identifier: Identifier, former_node: PDGNode, current_node: PDGNode,
                                    right_node: CPGNode, result: Result):
        identifier.set_type('FUNCTION_RETURN_VALUE')
        diagram_of_call = self.get_function_call_pdg(right_node.get_id()).get_diagram_of_call()
        if diagram_of_call:
            return_value_list = diagram_of_call.get_return_value()
            if return_value_list:
                if return_value_list:
                    for value in return_value_list:
                        result.add_edge(value.get_id(), current_node.get_id(), ['DDG'])
            else:
                result.add_edge(former_node.get_id(), current_node.get_id(), ['DDG'])
        else:
            result.add_edge(former_node.get_id(), current_node.get_id(), ['CFG'])

    def right_is_identifier(self, identifier: Identifier, former_node: PDGNode, current_node: PDGNode,
                            right_node: CPGNode, depth_tree: DepthTree, result: Result, in_edge: Edge, pdg: PDG):
        right_identifier_name = right_node.get_value('CODE')
        right_identifier = depth_tree.find(right_identifier_name, current_node.get_line_number())
        if right_identifier:
            identifier.set_original_identifier(right_identifier_name)
            identifier.set_type(right_identifier.get_type())
            identifier.set_local(right_identifier.get_local())
            identifier.set_builtin(right_identifier.is_builtin())
            identifier.set_third_part(right_identifier.is_third_part())
            identifier.set_import_entity(right_identifier.get_import_entity())
            identifier.set_full_name(right_identifier.get_full_name())
            identifier.set_imported_function(right_identifier.get_imported_function())
            identifier.set_original_right_type(right_identifier.get_original_right_type())

            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

            if right_identifier.get_node_id() is not None:

                if not self.has_ddg_line_of_two_nodes(current_node.get_id(), right_identifier.get_node_id(), pdg):
                    result.add_edge(right_identifier.get_node_id(), current_node.get_id(),
                                    [f"DDG: {right_identifier_name}"])
                else:
                    attr = pdg.get_edges()[(right_identifier.get_node_id(), current_node.get_id())].get_attr()
                    result.add_edge(right_identifier.get_node_id(), current_node.get_id(), attr)
        else:
            result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())

    def right_is_block(self, identifier: Identifier, former_node: PDGNode, current_node: PDGNode,
                       right_node: CPGNode, depth_tree: DepthTree, result: Result, in_edge: Edge, pdg):
        result.add_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
        ast_parser = ASTParser(right_node.get_value('CODE'), 'javascript')
        new_query = '(new_expression(identifier)@id)'
        new_object = ast_parser.query_oneshot(new_query)
        if new_object is not None:
            new_object = new_object.text.decode()
            new_object_found = depth_tree.find(new_object, current_node.get_line_number())
            if new_object_found:
                if new_object_found.get_type() == 'REQUIRE' and new_object_found.is_builtin():
                    identifier.set_import_entity(new_object_found.get_import_entity())
                    identifier.set_type('REQUIRE')
                    identifier.set_builtin(True)
                elif new_object_found.get_type() == 'FUNCTION_FROM_REQUIRE' and new_object_found.is_builtin():
                    identifier.set_full_name(
                        f"{new_object_found.get_import_entity()}.{new_object_found.get_imported_function()}")
                    identifier.set_type('RETURN_OBJECT')
                    identifier.set_original_right_type('builtin')
                elif new_object_found.get_type() == 'REQUIRE' and new_object_found.is_third_part():
                    identifier.set_third_part(True)
                    identifier.set_type('REQUIRE')
                    identifier.set_import_entity(new_object_found.get_import_entity())
                else:
                    pass
                if new_object_found.get_type() != 'FUNCTION_DECLARE':
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), new_object_found.get_node_id(), pdg):
                        result.add_edge(new_object_found.get_node_id(), current_node.get_id(),
                                        [f"DDG: {new_object_found.get_name()}"])
                    else:
                        attr = pdg.get_edges()[(new_object_found.get_node_id(), current_node.get_id())].get_attr()
                        result.add_edge(new_object_found.get_node_id(), current_node.get_id(), attr)

            else:

                query_result = db_query.find_in_database(new_object, 'npm')
                if query_result == 'BUILTIN':
                    identifier.set_builtin(True)
                    identifier.set_type('REQUIRE')
                    identifier.set_import_entity(new_object)

        else:

            new_query_2 = '(new_expression(member_expression(identifier)@id . (property_identifier)@pro))'
            parser_res = ast_parser.query(new_query_2)
            if len(parser_res) == 2 and parser_res[0][1] == 'id' and parser_res[1][1] == 'pro':
                identifier_in_expression = parser_res[0][0].text.decode()
                property_identifier = parser_res[1][0].text.decode()
                qualifier_found = depth_tree.find(identifier_in_expression, current_node.get_line_number())
                if qualifier_found:

                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), qualifier_found.get_node_id(), pdg):
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(),
                                        [f"DDG: {qualifier_found.get_name()}"])
                    else:
                        attr = pdg.get_edges()[(qualifier_found.get_node_id(), current_node.get_id())].get_attr()
                        result.add_edge(qualifier_found.get_node_id(), current_node.get_id(), attr)

                    if qualifier_found.get_type() == 'REQUIRE':
                        import_entity = qualifier_found.get_import_entity()
                        query_result = db_query.find_in_database(import_entity, 'npm')
                        is_sensitive_call = None
                        if query_result == 'BUILTIN':
                            is_sensitive_call = db_query.is_sensitive_call(import_entity, property_identifier, 'npm',
                                                                           'builtin')
                            identifier.set_full_name(f"{import_entity}.{property_identifier}")
                            identifier.set_type('RETURN_OBJECT')
                            identifier.set_original_right_type('builtin')
                        elif query_result == 'THIRD':
                            is_sensitive_call = db_query.is_sensitive_call(import_entity, property_identifier, 'npm',
                                                                           'third')
                            identifier.set_original_right_type('third')
                            identifier.set_full_name(f"{import_entity}.{property_identifier}")
                            identifier.set_type('RETURN_OBJECT')
                        if is_sensitive_call and is_sensitive_call[0]:
                            current_node.set_sensitive_node(True)
                            current_node.set_class_list(is_sensitive_call[1])
                            identifier.set_create_by_sensitive_call(True)
                            identifier.set_category_list_from_call(is_sensitive_call[1])

                else:
                    query_res = db_query.find_in_database(identifier_in_expression, 'npm')
                    if query_res == 'BUILTIN':

                        # new Buffer.from()
                        identifier.set_full_name(f"{identifier_in_expression}.{property_identifier}")
                        identifier.set_original_right_type('builtin')
                        identifier.set_type('RETURN_OBJECT')
                        is_sensitive_call = db_query.is_sensitive_call(identifier_in_expression, property_identifier,
                                                                       'npm', 'builtin')
                        if is_sensitive_call and is_sensitive_call[0]:
                            current_node.set_sensitive_node(True)
                            current_node.set_class_list(is_sensitive_call[1])
                            identifier.set_category_list_from_call(is_sensitive_call[1])
                            identifier.set_create_by_sensitive_call(True)

    def single_call_name(self, current_node: PDGNode, call_name: str,
                         depth_tree: DepthTree, result: Result, in_edge: Edge):

        qualifier_found = depth_tree.find(call_name, current_node.get_line_number())
        if qualifier_found:
            if qualifier_found.get_type() == 'FUNCTION_DECLARE':

                call_node_id = None
                current_node.set_call_type('FUNCTION_CALL')
                call_node = self.cpg.get_call(current_node.get_id())
                if call_node:
                    call_node_id = call_node.get_id()

                self.function_call_dict[current_node.get_id()] = current_node
                function_pdg = qualifier_found.get_pdg()
                function_pdg_id = function_pdg.get_first_node_id()
                if call_node_id is not None and function_pdg_id != call_node_id:
                    return
                function_call_result = self.function_call_process(current_node, function_pdg, depth_tree, result,
                                                                  in_edge)
                if function_call_result:
                    joint(result, function_call_result)
                    current_node.set_diagram_of_call(function_call_result)
            elif qualifier_found.get_type() == 'FUNCTION_FROM_REQUIRE':

                if qualifier_found.get_local() is False:

                    self.function_from_require_non_local(current_node, qualifier_found, call_name)

                else:

                    import_entity = qualifier_found.get_import_entity()
                    function = qualifier_found.get_imported_function()
                    local_call_result = self.local_module_call_process(current_node, import_entity,
                                                                       function,
                                                                       result, in_edge)
                    if local_call_result is not None:
                        current_node.set_call_type('LOCAL_MODULE_CALL')
                        self.local_module_call_dict[current_node.get_id()] = current_node
                        joint(result, local_call_result)
                        current_node.set_diagram_of_call(local_call_result)
            elif qualifier_found.get_type() == 'REQUIRE':

                import_entity = qualifier_found.get_import_entity()
                query_result = db_query.find_in_database(import_entity, 'npm')
                if query_result == 'THIRD_PART':
                    current_node.set_call_original_derivation('third')
                    current_node.set_call_full_name(import_entity)

                    is_sensitive_call = db_query.is_sensitive_call(import_entity, import_entity, 'npm', 'third')

                    if is_sensitive_call[0]:
                        current_node.set_sensitive_node(True)
                        current_node.set_class_list(is_sensitive_call[1])
                elif query_result == 'BUILTIN':
                    current_node.set_call_original_derivation('builtin')

                    is_sensitive_call = db_query.is_sensitive_call(import_entity, call_name, 'npm', 'builtin')
                    current_node.set_call_full_name(import_entity)
                    if is_sensitive_call[0]:
                        current_node.set_sensitive_node(True)
                        current_node.set_class_list(is_sensitive_call[1])
                else:
                    pass
            else:
                pass
        else:

            query_result = db_query.find_in_database(call_name, 'npm')
            if query_result == 'BUILTIN':
                current_node.set_call_original_derivation('builtin')
                is_sensitive_call = db_query.is_sensitive_call(call_name, call_name, 'npm', 'builtin')
                if is_sensitive_call[0]:
                    current_node.set_sensitive_node(True)
                    current_node.set_class_list(is_sensitive_call[1])
            else:
                pass

    def function_call_process(self, current_node: PDGNode, function_pdg: PDG, depth_tree: DepthTree, result: Result,
                              in_edge: Edge):
        if depth_tree.function_in_depth(function_pdg.get_name()):
            return None
        depth_tree.add_depth(function_pdg.get_name())
        self.pdg_analyzed[function_pdg.get_first_node_id()] = True

        function_call_entrance_id = function_pdg.get_first_node_id()

        result.add_edge(current_node.get_id(), function_call_entrance_id, ['DDG'])
        function_call_result = self.behavior_gen(current_node.get_file_name(), function_pdg, 'function')
        depth_tree.delete_last_depth()
        return function_call_result

    def function_from_require_non_local(self, current_node: PDGNode, qualifier_found: Identifier,
                                        call_name: str):
        query_result = db_query.find_in_database(qualifier_found.get_import_entity(), 'npm')
        is_sensitive_call = None
        if query_result == 'BUILTIN':
            is_sensitive_call = db_query.is_sensitive_call(qualifier_found.get_import_entity(),
                                                           qualifier_found.get_imported_function(),
                                                           'npm', 'builtin')
            current_node.set_call_full_name(qualifier_found.get_full_name())
            current_node.set_call_original_derivation('builtin')
        elif query_result == 'THIRD_PART':
            is_sensitive_call = db_query.is_sensitive_call(qualifier_found.get_import_entity(),
                                                           qualifier_found.get_imported_function(),
                                                           'npm', 'third')
            current_node.set_call_original_derivation('third')
            current_node.set_call_full_name(qualifier_found.get_full_name())
        else:

            if qualifier_found.get_import_entity() not in self.download_failed_package:
                res = db_query.add_to_database(qualifier_found.get_import_entity(),
                                               self.package_json.get_dependencies(), 'npm')
                if not res:
                    self.download_failed_package.add(qualifier_found.get_import_entity())
                else:
                    current_node.set_call_original_derivation('third')
                    current_node.set_call_full_name(
                        f"{qualifier_found.get_import_entity()}.{qualifier_found.get_imported_function()}")
                    is_sensitive_call = db_query.is_sensitive_call(qualifier_found.get_import_entity(),
                                                                   qualifier_found.get_imported_function(),
                                                                   'npm', 'third')
        if is_sensitive_call and is_sensitive_call[0]:
            current_node.set_sensitive_node(True)
            current_node.set_class_list(is_sensitive_call[1])

    def qualifier_found_process_with_call_name(self, call_name: str, current_node: PDGNode,
                                               qualifier_found: Identifier,
                                               result: Result, in_edge, pdg: PDG):
        identifier_type = qualifier_found.get_type()
        if identifier_type == 'REQUIRE':

            # module from require
            is_local = qualifier_found.get_local()
            import_entity = qualifier_found.get_import_entity()
            if is_local:

                # local module call
                local_call_result = self.local_module_call_process(current_node, import_entity, call_name,
                                                                   result, in_edge)

                if local_call_result:
                    current_node.set_call_type('LOCAL_MODULE_CALL')
                    self.local_module_call_dict[current_node.get_id()] = current_node
                    # add the local module call result to the caller
                    joint(result, local_call_result)
                    current_node.set_diagram_of_call(local_call_result)
            else:

                # non local module
                is_sensitive_call = None
                if qualifier_found.is_builtin():
                    is_sensitive_call = db_query.is_sensitive_call(import_entity, call_name, 'npm', 'builtin')
                    current_node.set_call_original_derivation('builtin')
                    current_node.set_call_full_name(f"{import_entity}.{call_name}")
                elif qualifier_found.is_third_part():
                    is_sensitive_call = db_query.is_sensitive_call(import_entity, call_name, 'npm', 'third')
                    current_node.set_call_original_derivation('third')
                    current_node.set_call_full_name(f"{import_entity}.{call_name}")
                else:

                    # empty module
                    pass

                if is_sensitive_call[0]:
                    current_node.set_sensitive_node(True)
                    current_node.set_class_list(is_sensitive_call[1])
        else:
            is_sensitive_call = None

            # method call on identifier
            if qualifier_found.get_full_name() is not None and qualifier_found.get_type() == 'RETURN_OBJECT':

                # identifier is the return value,
                # identifier is either from a built-in or third-party call.
                if qualifier_found.get_original_right_type() == 'third':

                    interest_cate = self.get_interest_cate(qualifier_found.get_category_list_from_call())
                    if interest_cate:
                        # third-party API call return value
                        is_sensitive_call = db_query.is_sensitive_call(qualifier_found.get_full_name(), call_name,
                                                                       'npm', 'third', category_doc[interest_cate])
                elif qualifier_found.get_original_right_type() == 'builtin':

                    qualifier_class = get_class(qualifier_found.get_full_name())
                    if qualifier_class:
                        is_sensitive_call = db_query.is_sensitive_call(qualifier_class, call_name, 'npm', 'builtin')
                    else:
                        is_sensitive_call = db_query.is_sensitive_call(qualifier_found.get_full_name(), call_name,
                                                                       'npm', 'builtin')
                else:
                    pass

            elif qualifier_found.get_original_right_type() == 'builtin':
                pass

            if is_sensitive_call and is_sensitive_call[0]:
                current_node.set_sensitive_node(True)
                current_node.set_class_list(is_sensitive_call[1])

    def qualifier_not_found_process_with_call_name(self, current_node: PDGNode, qualifier: str, call_name: str,
                                                   pdg: PDG):

        # check the qualifier is builtin or not
        query_result = db_query.find_in_database(qualifier, 'npm')
        if query_result == 'BUILTIN':
            current_node.set_call_full_name(f"{qualifier}.{call_name}")
            current_node.set_call_original_derivation('builtin')
            is_sensitive_call = db_query.is_sensitive_call(qualifier, call_name, 'npm', 'builtin')
            if is_sensitive_call[0]:
                current_node.set_sensitive_node(True)
                current_node.set_class_list(is_sensitive_call[1])
        else:
            pass

    def qualifier_found_has_field_access(self, call_name: str, second_part: str, current_node: PDGNode,
                                         qualifier_found: Identifier):

        qualifier_type = qualifier_found.get_type()
        is_sensitive_call = None
        if qualifier_type == 'REQUIRE':
            if not qualifier_found.get_local():

                import_entity = qualifier_found.get_import_entity()
                if qualifier_found.is_builtin():
                    current_node.set_call_original_derivation('builtin')
                    is_sensitive_call = db_query.is_sensitive_call(f"{import_entity}.{second_part}", call_name, 'npm',
                                                                   'builtin')
                elif qualifier_found.is_third_part():
                    pass
                else:
                    # empty module
                    pass
                if is_sensitive_call and is_sensitive_call[0]:
                    current_node.set_sensitive_node(True)
                    current_node.set_class_list(is_sensitive_call[1])
            else:

                pass
        elif qualifier_type == 'RETURN_OBJECT':
            if qualifier_found.get_original_right_type() == 'builtin':
                qualifier_full_name = qualifier_found.get_full_name()
                if qualifier_full_name:
                    qualifier_class = get_class(qualifier_found.get_full_name())
                    if qualifier_class:
                        is_sensitive_call = db_query.is_sensitive_call(qualifier_class, f"{second_part}.{call_name}",
                                                                       'npm', 'builtin')
                    else:
                        is_sensitive_call = db_query.is_sensitive_call(qualifier_full_name,
                                                                       f"{second_part}.{call_name}",
                                                                       'npm', 'builtin')
                if is_sensitive_call[0]:
                    current_node.set_sensitive_node(True)
                    current_node.set_class_list(is_sensitive_call[1])
            elif qualifier_found.get_original_right_type() == 'third':

                qualifier_full_name = qualifier_found.get_full_name()
                if qualifier_full_name:

                    interest_cate = self.get_interest_cate(qualifier_found.get_category_list_from_call())
                    if interest_cate:
                        is_sensitive_call = db_query.is_sensitive_call(
                            f"{qualifier_found.get_full_name()}.{second_part}",
                            call_name, 'npm', 'third', category_doc[interest_cate])
                        if is_sensitive_call and is_sensitive_call[0]:
                            current_node.set_sensitive_node(True)
                            current_node.set_class_list(is_sensitive_call[1])
                            current_node.set_call_full_name(
                                f"{qualifier_found.get_full_name()}.{second_part}.{call_name}")
            else:
                pass

    def qualifier_not_found_has_field_access(self, call_name: str, second_part: str, current_node: PDGNode,
                                             qualifier: str):
        query_result = db_query.find_in_database(qualifier, 'npm')
        if query_result == 'BUILTIN':
            is_sensitive_call = db_query.is_sensitive_call(f"{qualifier}.{second_part}", call_name, 'npm', 'builtin')
            if is_sensitive_call[0]:
                current_node.set_sensitive_node(True)
                current_node.set_class_list(is_sensitive_call[1])
        else:
            pass

    @staticmethod
    def get_interest_cate(category_list):
        for category_num in category_list:
            if category_num in ['6', '7', '9', '10', '17', '18', '19', '20', '22', '31', '32']:
                return category_num
        return None

    @staticmethod
    def has_ddg_line_of_two_nodes(current_node_id: int, identifier_id: int, pdg: PDG):
        if (identifier_id, current_node_id) in pdg.get_edges():
            return True
        return False

    def get_lambda_pdg(self, current_node: PDGNode):
        parameters = self.cpg.get_argument(current_node.get_id())

        # get parameter of lambda function
        if len(parameters) > 0:
            last_parameter = parameters[-1]
            method_full_name = self.cpg.get_node(last_parameter.get_id()).get_value('METHOD_FULL_NAME')
            if method_full_name is not None:

                # parameter has method full name
                code = self.cpg.get_node(last_parameter.get_id()).get_value('CODE')
                if re.match(r'<lambda>\d+', code):

                    # find lambda
                    for key, value in self.pdg_dict.items():
                        if value.get_full_name() == method_full_name:
                            return value
            else:
                return None
        else:
            return None

    def lambda_function(self,
                        current_node: PDGNode,
                        depth_tree: DepthTree,
                        lambda_pdg: PDG,
                        result: Result):
        self.pdg_analyzed[lambda_pdg.get_first_node_id()] = True
        depth_tree.add_depth(lambda_pdg.get_name())

        # connect the lambda function use data dependency
        result.add_edge(current_node.get_id(), lambda_pdg.get_first_node_id(), ['DDG'])
        anonymous_call_result = self.behavior_gen(current_node.get_file_name(), lambda_pdg, 'lambda')
        depth_tree.delete_last_depth()
        joint(result, anonymous_call_result)

    def connect_by_param(self, current_node: PDGNode, depth_tree: DepthTree, result: Result, pdg: PDG):
        # get parameters
        parameters = self.cpg.get_argument(current_node.get_id())

        # based on the parameters, add new edge
        has_other_connection = self.get_parameters_and_connect(current_node, parameters, '', depth_tree,
                                                               result, pdg)

    def get_parameters_and_connect(self, current_node: PDGNode, parameters: list[CPGNode],
                                   qualifier: str, depth_tree: DepthTree,
                                   result: Result, pdg: PDG):

        connect = False
        if len(parameters) != 0:
            for parameter in parameters:
                label = parameter.get_value('label')
                if label == 'METHOD_REF':
                    continue
                if label == 'CALL':

                    # the type of parameter is call
                    if parameter.get_value('NAME') == '<operator>.fieldAccess' or \
                            parameter.get_value('NAME') == '<operator>.indexAccess':
                        connect = True
                        _ast = self.cpg.get_child_ast(parameter.get_id())
                        left_ast = _ast[0]
                        left_ast_code = left_ast.get_value('CODE')
                        find_left_ast = depth_tree.find(left_ast_code, int(left_ast.get_value('LINE_NUMBER')))
                        if find_left_ast:
                            if find_left_ast.get_type() != 'FUNCTION_DECLARE' and \
                                    find_left_ast.get_type() != 'FUNCTION_FROM_REQUIRE':
                                if not self.has_ddg_line_of_two_nodes(current_node.get_id(),
                                                                      find_left_ast.get_node_id(),
                                                                      pdg):
                                    result.add_edge(find_left_ast.get_node_id(), current_node.get_id(),
                                                    [f"DDG: {find_left_ast.get_name()}"])
                                    connect = True
                                else:
                                    attr = pdg.get_edges()[
                                        (find_left_ast.get_node_id(), current_node.get_id())].get_attr()
                                    result.add_edge(find_left_ast.get_node_id(), current_node.get_id(), attr)

                elif label == 'IDENTIFIER':
                    parameter_code = parameter.get_value('CODE')
                    ast_parser = ASTParser(parameter_code, 'javascript')
                    identifier_query_str = '((identifier)@id)'
                    identifiers = ast_parser.query(identifier_query_str)
                    if identifiers:
                        for identifier in identifiers:
                            parameter_code = identifier[0].text.decode()
                            if parameter_code == qualifier:
                                continue
                            parameter_line_number = int(parameter.get_value('LINE_NUMBER'))
                            if parameter_code == 'this':
                                continue
                            else:
                                parameter_found = depth_tree.find(parameter_code, parameter_line_number)
                                if parameter_found and parameter_found.get_type() != 'FUNCTION_DECLARE' and parameter_found.get_type() != 'FUNCTION_FROM_REQUIRE':

                                    # previous identifier
                                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(),
                                                                          parameter_found.get_node_id(), pdg):
                                        result.add_edge(parameter_found.get_node_id(), current_node.get_id(),
                                                        [f"DDG: {parameter_found.get_name()}"])
                                        connect = True
                                    else:
                                        attr = pdg.get_edges()[
                                            (parameter_found.get_node_id(), current_node.get_id())].get_attr()
                                        result.add_edge(parameter_found.get_node_id(), current_node.get_id(), attr)
                else:
                    pass
        return connect

    @staticmethod
    def is_top_expression_statement(node):
        parent = node.parent
        while parent is not None:
            if parent.type == 'expression_statement':
                return False
            parent = parent.parent
        return True

    @staticmethod
    def is_top_subscript(node):
        parent = node.parent
        while parent is not None:
            if parent.type == 'expression_statement' or parent.type == 'program':
                return False
            parent = parent.parent
        return True

    def is_local_module_call(self, node_id: int):
        return node_id in self.local_module_call_dict

    def get_local_module_call_pdg(self, node_id: int):
        return self.local_module_call_dict[node_id]

    def is_function_call(self, node_id: int):
        return node_id in self.function_call_dict

    def get_function_call_pdg(self, node_id: int):
        return self.function_call_dict[node_id]

    @staticmethod
    def is_sensitive_file_extension(filename: str):
        extensions = ['md', 'sh', 'exe']
        for extension in extensions:
            if filename.endswith(extension):
                return True
        return False
