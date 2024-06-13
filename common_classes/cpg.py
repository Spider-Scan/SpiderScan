from __future__ import annotations

from common_classes.cpg_node import CPGNode
from common_classes.cpg_pdg_edge import Edge
import os
import networkx as nx


class CPG:
    def __init__(self, cpg_dir: str):
        self.cpg_dir = cpg_dir
        self.nodes: dict[int, CPGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, set[int]] = {}
        self.in_edges: dict[int, set[int]] = {}
        self.max_node_id = 0

        cpg_path = os.path.join(cpg_dir, 'export.dot')
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")

        cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)
        for node in cpg.nodes:

            # read the node info in CPG
            node_id = int(node)
            cpg_node = CPGNode(node_id)
            for key, value in cpg.nodes[node].items():
                cpg_node.set_attr(key, value)
            self.nodes[node_id] = cpg_node
            self.max_node_id = node_id

        # read all edges in cpg
        for head, tail, key, edge_dict in cpg.edges(data=True, keys=True):
            src = int(head)
            dst = int(tail)
            if (src, dst) not in self.edges:
                cpg_edge = Edge((src, dst))
            else:
                cpg_edge = self.edges[(src, dst)]

            # add to the out edges
            if src not in self.out_edges:
                self.out_edges[src] = set()
                self.out_edges[src].add(dst)
            else:
                self.out_edges[src].add(dst)

            # add to the in edge
            if dst not in self.in_edges:
                self.in_edges[dst] = set()
                self.in_edges[dst].add(src)
            else:
                self.in_edges[dst].add(src)

            for _key, _value in edge_dict.items():
                cpg_edge.set_attr(_value)
            self.edges[(src, dst)] = cpg_edge

    def get_node(self, node_id: int) -> CPGNode:
        return self.nodes[node_id]

    def get_child_ast(self, node_id: int) -> list[CPGNode]:
        """
        get ast nodes
        """
        nodes_id = self.out_edges[node_id]
        ast = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'AST':
                    ast.append(self.nodes[tail_id])

        # ascend
        return sorted(ast, key=lambda x: int(x.get_value('ORDER')))

    def get_argument(self, node_id: int) -> list[CPGNode]:
        """
        get argument type edge
        """
        nodes_id = self.out_edges[node_id]
        ast = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'ARGUMENT':
                    ast.append(self.nodes[tail_id])
        ast = sorted(ast, key=lambda x: int(x.get_value('ARGUMENT_INDEX')))
        return ast

    def get_call(self, node_id: int) -> CPGNode | None:
        """
        get call type edge
        """
        nodes_id = self.out_edges[node_id]
        call_node = None
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'CALL':
                    call_node = self.nodes[tail_id]
        return call_node

    def get_max_node_id(self):
        self.max_node_id += 1
        return self.max_node_id
