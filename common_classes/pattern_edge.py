from common_classes.pattern_node import PatternNode


class PatternEdge:
    def __init__(self, head_node_class: str, edge_type: str = None, tail_node_class: str = None):

        # when tail node are None, it means that the edge only has one point.
        self.head_node = PatternNode(head_node_class)
        self.edge = edge_type
        self.tail_node = PatternNode(tail_node_class)
        if self.edge is None:
            self.edge_type = 'Single'
        else:
            self.edge_type = 'Normal'

    def get_head_node(self) -> PatternNode:
        return self.head_node

    def get_tail_node(self) -> PatternNode:
        return self.tail_node

    def get_edge(self) -> str:
        return self.edge

    def is_single(self) -> bool:
        return self.edge_type == 'Single'
