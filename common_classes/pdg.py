from common_classes.pdg_node import PDGNode
from common_classes.cpg_pdg_edge import Edge
import os
import re
import sys
import networkx as nx


class PDG:
    def __init__(self, pdg_path, cpg):
        self.pdg_path = pdg_path
        self.nodes: dict[int, PDGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, list[int]] = {}
        self.in_edges: dict[int, list[int]] = {}

        if not os.path.exists(self.pdg_path):
            raise FileNotFoundError(f"dot file is not found in {self.pdg_path}")

        pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)

        if len(pdg.nodes) == 0:
            return

        # fist node in PDG
        first_node_id = list(pdg.nodes)[0]
        self.first_node_id = int(first_node_id)

        # name of the pdg
        self.name = pdg.nodes[first_node_id]['NAME']

        # starting line number of the code corresponding to PDG
        self.line_number = int(pdg.nodes[first_node_id]['LINE_NUMBER']) if 'LINE_NUMBER' in pdg.nodes[
            first_node_id] else 0

        # ending line number of the code corresponding to PDG
        self.line_number = int(pdg.nodes[first_node_id]['LINE_NUMBER_END']) if 'LINE_NUMBER_END' in pdg.nodes[
            first_node_id] else 0

        # starting column number of the code corresponding to PDG
        self.line_number = int(pdg.nodes[first_node_id]['COLUMN_NUMBER']) if 'COLUMN_NUMBER' in pdg.nodes[
            first_node_id] else 0

        # ending column number of the code corresponding to PDG
        self.line_number = int(pdg.nodes[first_node_id]['COLUMN_NUMBER_END']) if 'COLUMN_NUMBER_END' in pdg.nodes[
            first_node_id] else 0

        # locate information about this method within the code file
        if 'FULL_NAME' in pdg.nodes[first_node_id]:
            self.full_name = pdg.nodes[first_node_id]['FULL_NAME']
        else:
            self.full_name = ''
        if 'FILENAME' in pdg.nodes[first_node_id]:
            self.file_name = pdg.nodes[first_node_id]['FILENAME']
        else:
            self.file_name = ''
        self.code = cpg.get_node(self.first_node_id).get_value('CODE')

        # implicit main entry point for each file
        if self.name == ':program':
            self.type = 'program'

        # lambda function
        elif re.match(r'<lambda>\d*', self.name):
            self.type = 'lambda'
        else:

            # function type
            self.type = 'function'

        # read all nodes in pdg
        for node in pdg.nodes:
            node_id = int(node)
            pdg_node = PDGNode(node_id)
            pdg_node.set_belong_to_pdg(self.first_node_id)
            pdg_node.set_file_path(self.file_name)
            pdg_node.set_node_type(pdg.nodes[node]['NODE_TYPE'])
            if 'LINE_NUMBER' in pdg.nodes[node]:
                line_number = int(pdg.nodes[node]['LINE_NUMBER'])
                pdg_node.set_line_number(line_number)
            else:
                pdg_node.set_line_number(sys.maxsize)

            if 'COLUMN_NUMBER' in pdg.nodes[node]:
                column_number = int(pdg.nodes[node]['COLUMN_NUMBER'])
                pdg_node.set_column_number(column_number)
            else:
                pdg_node.set_column_number_end(sys.maxsize)

            if 'NAME' in pdg.nodes[node]:
                name = pdg.nodes[node]['NAME']
                pdg_node.set_name(name)

            if 'CODE' in pdg.nodes[node]:
                code = cpg.get_node(int(node)).get_value('CODE')
                pdg_node.set_code(code)

            self.nodes[node_id] = pdg_node

        # entrance of pdg
        self.nodes[self.first_node_id].set_entrance(True)

        # read all edges in pdg
        for head, tail, key, edge_dict in pdg.edges(data=True, keys=True):
            src = int(head)
            dst = int(tail)
            if src not in self.nodes:
                continue
            if (src, dst) not in self.edges:
                pdg_edge = Edge((src, dst))
            else:
                pdg_edge = self.edges[(src, dst)]

            # add to the out edge
            if src not in self.out_edges:
                self.out_edges[src] = []
                self.out_edges[src].append(dst)
            else:
                if dst not in self.out_edges[src]:
                    self.out_edges[src].append(dst)

            # add to in edge
            if dst not in self.in_edges:
                self.in_edges[dst] = []
                self.in_edges[dst].append(src)
            else:
                if src not in self.in_edges[dst]:
                    self.in_edges[dst].append(src)
            for _key, _value in edge_dict.items():
                pdg_edge.set_attr(_value)
            self.edges[(src, dst)] = pdg_edge

    def get_node(self, node_id) -> PDGNode:
        return self.nodes[node_id]

    def get_file_name(self) -> str:
        return self.file_name

    def get_line_number(self) -> int:
        return self.line_number

    def get_name(self) -> str:
        return self.name

    def is_empty(self):
        return len(self.nodes) == 0

    def get_nodes(self) -> dict[int, PDGNode]:
        return self.nodes

    def get_edges(self) -> dict[tuple[int, int], Edge]:
        return self.edges

    def get_in_edges(self) -> dict[int, list[int]]:
        return self.in_edges

    def get_out_edges(self) -> dict[int, list[int]]:
        return self.out_edges

    def get_first_node_id(self) -> int:
        return self.first_node_id

    def get_full_name(self) -> str:
        return self.full_name
