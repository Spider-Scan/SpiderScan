from common_classes.pattern_edge import PatternEdge
import networkx as nx
from category import category_doc
import os


class Pattern:
    def __init__(self, maliciousness: str, pattern_desc, kpr: PatternEdge, pr: list[PatternEdge] = None):
        self.maliciousness = maliciousness  # General Classification of Malicious Behavior
        self.pattern_desc = pattern_desc  # Detailed Classification of Malicious Behavior
        self.key_potential_risk = kpr
        if pr is not None:
            self.potential_risk = pr
        else:
            self.potential_risk = None
        self.adjacent: dict[str, list[tuple[str, str]]] = {}  # adjacent matrix
        self.node_class_list = set()  # category in pattern
        self.__set_kpr()
        self.__set_pr()

    def get_pattern_desc(self):
        return self.pattern_desc

    def get_head_of_kpr(self):
        """
        get the first node
        """
        # whether it is a single node or a double node, the head node is not null
        return self.key_potential_risk.get_head_node()

    def __set_kpr(self):
        """
        modify the adjacency matrix and type queue based on kpr information
        """
        if self.key_potential_risk.is_single():

            # kpr consists of single node
            single_node_class = self.key_potential_risk.get_head_node()
            self.node_class_list.add(single_node_class.get_class())
            if single_node_class.get_class() not in self.adjacent:
                self.adjacent[single_node_class.get_class()] = []

        else:

            head_node = self.key_potential_risk.get_head_node()
            tail_node = self.key_potential_risk.get_tail_node()
            edge = self.key_potential_risk.get_edge()
            self.node_class_list.add(head_node.get_class())
            self.node_class_list.add(tail_node.get_class())

            if head_node.get_class() not in self.adjacent:
                self.adjacent[head_node.get_class()] = []

            if tail_node.get_class() not in self.adjacent:
                self.adjacent[tail_node.get_class()] = []

                # (edge, tail node)
                self.adjacent[head_node.get_class()].append((edge, tail_node.get_class()))

    def __set_pr(self):
        if self.potential_risk is not None:
            for pattern_edge in self.potential_risk:

                head_node = pattern_edge.get_head_node()
                tail_node = pattern_edge.get_tail_node()
                edge = pattern_edge.get_edge()
                self.node_class_list.add(head_node.get_class())
                self.node_class_list.add(tail_node.get_class())

                if head_node.get_class() not in self.adjacent:
                    self.adjacent[head_node.get_class()] = []

                if tail_node.get_class() not in self.adjacent:
                    self.adjacent[tail_node.get_class()] = []

                # (edge, tail node)
                self.adjacent[head_node.get_class()].append((edge, tail_node.get_class()))

    @staticmethod
    def get_key_of_value(value):
        for key, _value in category_doc.items():
            if _value == value:
                return key

        return None

    def __lt__(self, other):
        """
        overload the < operator.
        """
        if not isinstance(other, Pattern):
            return False

        other_class_list = other.get_class_list()
        if not all(value in other_class_list for value in self.node_class_list):

            # check if the 'other class' is in the current class's node list
            return False

        other_pattern_adjacent = other.get_adjacent()
        for head_class, edge_tail_list in self.adjacent.items():
            for edge_tail in edge_tail_list:
                edge = edge_tail[0]
                tail_class = edge_tail[1]

                # check if the connected points in 'other' are connected in the current adjacency matrix
                if not self.is_sub_path(head_class, tail_class, edge, other_pattern_adjacent):
                    return False

        return True

    def is_sub_path(self, head_class, tail_class, edge_type, other_adjacent):

        # check if there exists a path from 'head' to 'tail' in the current adjacency matrix
        if head_class not in other_adjacent:
            return False
        else:
            if not self.is_reachable(head_class, tail_class, edge_type, other_adjacent):
                return False
            else:
                return True

    def is_reachable(self, head_class, tail_class, edge_type, other_adjacent):

        # determine if 'head' and 'tail' are connected through the edge of type 'edge_type'
        adjacent_edge_node_list = other_adjacent[head_class]
        if edge_type == 'CFG':

            # the type is CFG
            for edge_node in adjacent_edge_node_list:
                if (edge_node[0] == 'CFG' or edge_node[0] == 'DDG') and tail_class == edge_node[1]:

                    # find nodes of the same type that are connected by CFG or DDG
                    return True
                else:
                    return self.is_reachable(edge_node[1], tail_class, edge_type, other_adjacent)
        else:

            # the type is DDG
            for edge_node in adjacent_edge_node_list:
                if edge_node[0] == 'DDG' and tail_class == edge_node[1]:

                    # find nodes of the same type that are connected by DDG.
                    return True
                else:
                    if edge_node[0] == 'DDG':
                        return self.is_reachable(edge_node[1], tail_class, edge_type, other_adjacent)

        return False

    def get_class_list(self):
        return list(self.node_class_list)

    def get_adjacent(self) -> dict[str, list[tuple[str, str]]]:
        return self.adjacent

    def get_maliciousness(self):
        return self.maliciousness
