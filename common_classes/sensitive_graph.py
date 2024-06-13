from common_classes.pdg_node import PDGNode


class SensitiveGraph:

    def __init__(self):
        self.nodes: dict[int, PDGNode] = {}
        self.edges: dict[tuple[int, int], str] = {}  # record the edge attributes between two nodes, i.e., CPG or DDG.
        self.out_edges: dict[int, set[int]] = {}  # out edges
        self.node_on_path: dict[tuple[int, int], set[int]] = {}

    def add_node(self, node_id, node: PDGNode):
        if node_id in self.nodes:
            return
        else:
            self.nodes[node_id] = node

    def get_node(self, node_id):
        return self.nodes[node_id]

    def get_nodes(self) -> dict[int, PDGNode]:
        return self.nodes

    def update_node_on_path(self, head, tail, node_on_path):
        if (head, tail) not in self.node_on_path:
            self.node_on_path[(head, tail)] = set()
        self.node_on_path[(head, tail)].update(node_on_path)

    def add_edge(self, head, tail, edge_type):
        """
        add new edge or update current edge
        """
        if (head, tail) in self.edges:
            if self.edges[(head, tail)] == 'DDG' or edge_type == 'DDG':
                combine_edge_type = 'DDG'
            else:
                combine_edge_type = 'CFG'
        else:
            combine_edge_type = edge_type
        self.edges[(head, tail)] = combine_edge_type

        self.__add_out_edge(head, tail)

    def __add_out_edge(self, head, tail):
        if head not in self.out_edges:
            self.out_edges[head] = set()
            self.out_edges[head].add(tail)
        else:
            self.out_edges[head].add(tail)

    def get_out_edges(self) -> dict[int, set[int]]:
        return self.out_edges

    def get_edges(self) -> dict[tuple[int, int], str]:
        return self.edges

    def get_node_on_path(self, head, tail):
        return self.node_on_path[(head, tail)]
