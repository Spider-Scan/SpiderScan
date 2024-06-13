from __future__ import annotations


class PDGNode:
    def __init__(self, node_id):
        self.node_id = node_id  # node ID
        self.belong_to_pdg = None  # PDG graph the node belong to
        self.node_type = None  # The type of node corresponds to the NODE_TYPE in the PDG
        self.line_number: int = 0  # starting line number
        self.line_number_end: int = 0  # ending line number
        self.column_number: int = 0  # starting column number
        self.column_number_end: int = 0  # ending column number
        self.name = None  # name of the pdg
        self.filename = None  # file
        self.code = None  # code of the node
        self.sensitive_node = False  # sensitive
        self.entrance = False
        self.is_return_value = False
        self.class_list: list = []  # category list
        self.class_description = None
        self.call_type = ''
        self.diagram_corresponding_to_call = None
        self.call_full_name = None
        self.call_original_derivation = None

    def __lt__(self, other):
        return self.line_number < other.line_number

    def set_belong_to_pdg(self, pdg_id):
        self.belong_to_pdg = pdg_id

    def get_belong_to_pdg(self):
        return self.belong_to_pdg

    def get_call_type(self):
        return self.call_type

    def set_call_type(self, call_type):
        self.call_type = call_type

    def get_diagram_of_call(self):
        return self.diagram_corresponding_to_call

    def set_diagram_of_call(self, diagram):
        self.diagram_corresponding_to_call = diagram

    def set_class_list(self, cat):
        self.class_list = cat

    def get_class_list(self):
        return self.class_list

    def get_id(self):
        return self.node_id

    def get_node_type(self):
        return self.node_type

    def set_node_type(self, label):
        self.node_type = label

    def get_line_number(self) -> int:
        return self.line_number

    def set_line_number(self, line_number: int):
        self.line_number = line_number

    def get_line_number_end(self) -> int:
        return self.line_number_end

    def set_line_number_end(self, line_number_end: int):
        self.line_number_end = line_number_end

    def get_column_number(self) -> int:
        return self.column_number

    def set_column_number(self, column_number):
        self.column_number = column_number

    def get_column_number_end(self):
        return self.column_number_end

    def set_column_number_end(self, column_number_end):
        self.column_number_end = column_number_end

    def set_sensitive_node(self, bool_value):
        self.sensitive_node = bool_value

    def is_sensitive_node(self):
        return self.sensitive_node

    def set_entrance(self, bool_value):
        self.entrance = bool_value

    def is_entrance(self):
        return self.entrance

    def set_is_return_value(self, bool_value):
        self.is_return_value = bool_value

    def is_return_value_(self):
        return self.is_return_value

    def set_category_description(self, text):
        self.class_description = text

    def get_category_description(self):
        return self.class_description

    def set_file_path(self, filename):
        self.filename = filename

    def get_file_name(self) -> str:
        return self.filename

    def set_call_full_name(self, call_full_name):
        self.call_full_name = call_full_name

    def get_call_full_name(self):
        return self.call_full_name

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_code(self, code):
        self.code = code

    def get_code(self):
        return self.code

    def set_call_original_derivation(self, original_derivation: str):
        self.call_original_derivation = original_derivation

    def get_call_original_derivation(self):
        return self.call_original_derivation
