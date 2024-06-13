from __future__ import annotations

from npm_pipeline.classes.depth_node import DepthNode
from npm_pipeline.classes.identifier import Identifier


class DepthTree:
    def __init__(self, name):
        self.name = name
        self.program_node = []
        self.root = DepthNode(None, 'program')
        self.last_node = self.root

    def add_identifier(self, identifier):

        # add identifier to the last node of the tree
        self.last_node.add_identifier(identifier)

    def add_depth(self, name):
        # add a new node to the depth tree
        sub_node = DepthNode(self.last_node, name)
        self.last_node = sub_node

    def find(self, name: str, line_number: int) -> None | Identifier:
        """
        find identifier with the name given before specific line number
        """
        current_node = self.last_node
        while current_node is not None:
            for identifier in reversed(current_node.get_identifiers()):
                if name == identifier.get_name() and identifier.get_line_number() <= line_number:
                    return identifier
            current_node = current_node.get_former()
        return None

    def clean(self):
        while self.last_node != self.root:
            former_node = self.last_node.get_former()
            del self.last_node
            self.last_node = former_node
        self.root = DepthNode(None, 'program')
        self.last_node = self.root

    def delete_last_depth(self):
        if self.last_node != self.root:
            self.last_node = self.last_node.get_former()

    def function_in_depth(self, name):

        current_node = self.last_node
        while current_node is not None:
            if name == current_node.get_scope():
                return True
            current_node = current_node.get_former()
        return False
