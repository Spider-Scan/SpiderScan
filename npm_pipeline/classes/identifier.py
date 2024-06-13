from common_classes.pdg_node import PDGNode
from common_classes.pdg import PDG


class Identifier:
    def __init__(self, name, line_number, type_, node_id, file, pdg, import_entity=None, local=False, sensitive=False,
                 builtin=False, third_part=False, imported_function=None, parameter_count=None):
        self.name = name  # identifier's name
        self.line_number = line_number  # line number
        self.type = type_  # REQUIRE, FUNCTION_FROM_REQUIRE, LOCAL_MODULE_FUNCTION_RETURN_VALUE, FUNCTION_RETURN_VALUE, RETURN_OBJECT
        self.node_id = node_id  # node id
        self.file = file  # file
        self.import_entity = import_entity  # alias
        self.local = local  # local sign
        self.builtin = builtin  # builtin sign
        self.third_part = third_part  # third sign
        self.pdg = pdg  # pdg
        self.imported_function = imported_function  # imported function
        self.full_name = None
        self.original_right_type = None  # get from which type of call
        self.original_identifier = name
        self.create_by_sensitive_call = False  # create by sensitive call sign
        self.behavior_category_list = None  # the category of right call

    def get_name(self):
        return self.name

    def get_line_number(self) -> int:
        return self.line_number

    def get_type(self):
        return self.type

    def set_type(self, type):
        self.type = type

    def get_node_id(self):
        return self.node_id

    def get_file(self):
        return self.file

    def get_import_entity(self):
        return self.import_entity

    def set_import_entity(self, import_entity):
        self.import_entity = import_entity

    def get_pdg(self) -> PDG:
        return self.pdg

    def get_local(self):
        return self.local

    def set_local(self, local):
        self.local = local

    def set_builtin(self, bool_value):
        self.builtin = bool_value

    def is_builtin(self):
        return self.builtin

    def set_third_part(self, bool_value):
        self.third_part = bool_value

    def is_third_part(self):
        return self.third_part

    def set_imported_function(self, imported_function):
        self.imported_function = imported_function

    def get_imported_function(self):
        return self.imported_function

    def set_full_name(self, method_full_name):
        self.full_name = method_full_name

    def get_full_name(self):
        return self.full_name

    def set_original_identifier(self, original_identifier):
        self.original_identifier = original_identifier

    def get_original_identifier(self):
        return self.original_identifier

    def set_original_right_type(self, right_type):
        self.original_right_type = right_type

    def get_original_right_type(self):
        return self.original_right_type

    def set_create_by_sensitive_call(self, bool_value: bool):
        self.create_by_sensitive_call = bool_value

    def is_crate_by_sensitive_call(self):
        return self.create_by_sensitive_call

    def set_category_list_from_call(self, category_list):
        self.behavior_category_list = category_list

    def get_category_list_from_call(self):
        return self.behavior_category_list
