from npm_pipeline.classes.identifier import Identifier


class DepthNode:
    def __init__(self, former, scope):
        self.former = former
        self.scope = scope
        self.identifiers: list[Identifier] = []

    def get_former(self):
        return self.former

    def get_identifiers(self):
        return self.identifiers

    def add_identifier(self, identifier):
        self.identifiers.append(identifier)

    def get_scope(self):
        return self.scope
