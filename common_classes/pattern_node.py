class PatternNode:
    def __init__(self, node_class: str):
        self.node_class = node_class

    def get_class(self) -> str:
        return self.node_class
