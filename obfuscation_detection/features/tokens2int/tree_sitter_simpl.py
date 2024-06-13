"""
    Configuration file storing the dictionary ast_units_dico.
        Key: tree-sitter syntactic unit;
        Value: Unique integer.
"""
ast_units_dico = {
    'class_declaration': 0,
    'function_declaration': 0,
    'generator_function_declaration': 0,
    'lexical_declaration': 1,
    'variable_declaration': 1,
    'variable_declarator': 1,
    'augmented_assignment_expression': 2,
    'binary_expression': 3,
    'new_expression': 4,
    'ternary_expression': 5,
    'unary_expression': 5,
    'update_expression': 5,
    'yield_expression': 5,
    'identifier': 6,
    'property_identifier': 6,
    'shorthand_property_identifier_pattern': 6,
    'private_property_identifier': 6,
    'statement_identifier': 6,
    'computed_property_name': 6,
    'shorthand_property_identifier': 6,
    'array_pattern': 7,
    'array': 7,
    'member_expression': 8,
    'subscript_expression': 9,
    'arrow_function': 10,
    'call_expression': 11,
    'false': 12,
    'true': 12,
    'function_expression': 13,
    'generator_function': 13,
    'parenthesized_expression': 14,
    'string': 15,
    'string_fragment': 15,
    'template_string': 15,
    'break_statement': 16,
    'continue_statement': 16,
    'debugger_statement': 16,
    'do_statement': 16,
    'for_in_statement': 16,
    'for_statement': 16,
    'if_statement': 16,
    'while_statement': 16,
    'switch_statement': 16,
    'with_statement': 16,
    'switch_body': 16,
    'switch_case': 16,
    'else_clause': 16,
    'switch_default': 16,
    'expression_statement': 17,
    'assignment_expression': 17,
    'object_assignment_pattern': 17,
    'assignment_pattern': 17,
    'await_expression': 17,
    'labeled_statement': 17,
    'statement_block': 17,
    'formal_parameters': 18,
    'arguments': 18,
    'field_definition': 19,
    'method_definition': 19,
    'pair': 20,
    'pair_pattern': 20,
    'escape_sequence': 21,
    'template_substitution': 22,
    'number': 23,
    'sequence_expression': 24,
    'optional_chain': 25,
    'glimmer_template': 30,
    'jsx_element': 30,
    'jsx_self_closing_element': 30,
    'object_pattern': 30,
    'rest_pattern': 30,
    'spread_element': 30,
    'undefined': 30,
    'class': 30,
    'class_body': 30,
    'meta_property': 30,
    'null': 30,
    'object': 30,
    'regex': 30,
    'super': 30,
    'this': 30,
    'export_statement': 30,
    'empty_statement': 30,
    'import_statement': 30,
    'import': 30,
    'return_statement': 30,
    'throw_statement': 30,
    'try_statement': 30,
    'catch_clause': 30,
    'decorator': 30,
    'class_heritage': 30,
    'class_static_block': 30,
    'comment': 30,
    'export_clause': 30,
    'export_specifier': 30,
    'namespace_export': 30,
    'finally_clause': 30,
    'glimmer_closing_tag': 30,
    'glimmer_opening_tag': 30,
    'import_attribute': 30,
    'import_clause': 30,
    'named_imports': 30,
    'namespace_import': 30,
    'import_specifier': 30,
    'jsx_attribute': 30,
    'jsx_expression': 30,
    'jsx_namespace_name': 30,
    'jsx_closing_element': 30,
    'jsx_opening_element': 30,
    'html_character_reference': 30,
    'jsx_text': 30,
    'program': 30,
    'ERROR': 30,
    'hash_bang_line': 30,
    'regex_flags': 30,
    'regex_pattern': 30,
}

whole_types = {
    'class_declaration': 0,
    'function_declaration': 1,
    'generator_function_declaration': 2,
    'lexical_declaration': 3,
    'variable_declaration': 4,
    'assignment_expression': 5,
    'augmented_assignment_expression': 6,
    'await_expression': 7,
    'binary_expression': 8,
    'glimmer_template': 9,
    'jsx_element': 10,
    'jsx_self_closing_element': 11,
    'new_expression': 12,
    'primary_expression': 13,
    'ternary_expression': 14,
    'unary_expression': 15,
    'update_expression': 16,
    'yield_expression': 17,
    'array_pattern': 18,
    'identifier': 19,
    'member_expression': 20,
    'object_pattern': 21,
    'rest_pattern': 22,
    'subscript_expression': 23,
    'undefined': 24,
    'array': 25,
    'arrow_function': 26,
    'call_expression': 27,
    'class': 28,
    'false': 29,
    'function_expression': 30,
    'generator_function': 31,
    'meta_property': 32,
    'null': 33,
    'number': 34,
    'object': 35,
    'parenthesized_expression': 36,
    'regex': 37,
    'string': 38,
    'super': 39,
    'template_string': 40,
    'this': 41,
    'true': 42,
    'break_statement': 43,
    'continue_statement': 44,
    'debugger_statement': 45,
    'do_statement': 46,
    'empty_statement': 47,
    'export_statement': 48,
    'expression_statement': 49,
    'for_in_statement': 50,
    'for_statement': 51,
    'if_statement': 52,
    'import_statement': 53,
    'labeled_statement': 54,
    'return_statement': 55,
    'statement_block': 56,
    'switch_statement': 57,
    'throw_statement': 58,
    'try_statement': 59,
    'while_statement': 60,
    'with_statement': 61,
    'spread_element': 62,
    'assignment_pattern': 64,
    'formal_parameters': 65,
    'private_property_identifier': 66,
    'statement_identifier': 67,
    'import': 68,
    'catch_clause': 69,
    'class_body': 70,
    'decorator': 71,
    'class_heritage': 72,
    'class_static_block': 73,
    'field_definition': 74,
    'method_definition': 75,
    'comment': 76,
    'computed_property_name': 77,
    'else_clause': 78,
    'export_clause': 79,
    'export_specifier': 80,
    'namespace_export': 81,
    'property_identifier': 82,
    'finally_clause': 83,
    'glimmer_closing_tag': 84,
    'glimmer_opening_tag': 85,
    'import_attribute': 86,
    'import_clause': 87,
    'named_imports': 88,
    'namespace_import': 89,
    'import_specifier': 90,
    'jsx_attribute': 91,
    'jsx_expression': 92,
    'jsx_namespace_name': 93,
    'jsx_closing_element': 94,
    'jsx_opening_element': 95,
    'html_character_reference': 96,
    'jsx_text': 97,
    'arguments': 98,
    'pair': 99,
    'shorthand_property_identifier': 100,
    'object_assignment_pattern': 101,
    'shorthand_property_identifier_pattern': 102,
    'pair_pattern': 103,
    'program': 104,
    'hash_bang_line': 105,
    'regex_flags': 106,
    'regex_pattern': 107,
    'escape_sequence': 108,
    'string_fragment': 109,
    'switch_body': 110,
    'switch_case': 111,
    'switch_default': 112,
    'template_substitution': 113,
    'variable_declarator': 114,
}