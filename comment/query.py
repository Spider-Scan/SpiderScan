JS_EXPORT = """
[
	(assignment_expression
      left: 
      [
      	(member_expression
          object: (identifier)@exports
          (#eq? @exports "exports")
          property: (property_identifier)@name
        )
        (member_expression
          object: (identifier)
          property: (property_identifier)@exports
          (#eq? @exports "exports")
        )
      ]
      right: 
      [
        (identifier)@name
        (member_expression
          object: (identifier)
          property: (property_identifier)@name
        )
      ]
	)
    (assignment_expression
      left: (member_expression
        object: (identifier)@exports
        (#eq? @exports "exports")
        property: (property_identifier)@name
      )
      right: (function_expression)
    )
    (assignment_expression
      left: (member_expression
        object: (identifier)@module
        (#eq? @module "module")
        property: (property_identifier)@exports
        (#eq? @exports "exports")
      )
      right: (object
      	(shorthand_property_identifier)@name
      )
    )
]
"""

JS_EXPORT_FUNC_DOC = """
(
  (comment)+ @doc
  .
  (expression_statement
    (assignment_expression
      left: (member_expression
        object: (identifier)@id
        (#eq? @id "exports")
        property: (property_identifier)@name
      )
      right: (function_expression)@definition.function
    )
  )
)
"""

JS_EXPORT_FUNC = """
(expression_statement
  (assignment_expression
    left: (member_expression
      object: (identifier)@id
      (#eq? @id "exports")
      property: (property_identifier)@name
    )
    right: (function_expression)@definition.function
  )
)
"""

JS_FUNC_QUERY = """
(
  [
    (function_expression
      name: (identifier) @name)
    (function_declaration
      name: (identifier) @name)
    (generator_function
      name: (identifier) @name)
    (generator_function_declaration
      name: (identifier) @name)
    (variable_declarator
      name: (identifier) @name
      value: (arrow_function)
    )
    (expression_statement
      (assignment_expression
        left: (member_expression
          property: (property_identifier)@name
        )
        right: (function_expression)
      )
    )
  ] @definition.function
  (#eq? @name "{0}")
)
"""

JS_FUNC_DOC = """
(
  (comment)+ @doc
  .
  [
    (function_expression
      name: (identifier) @name)
    (function_declaration
      name: (identifier) @name)
    (generator_function
      name: (identifier) @name)
    (generator_function_declaration
      name: (identifier) @name)
    (variable_declarator
      name: (identifier) @name
      value: (arrow_function)
    )
    (expression_statement
      (assignment_expression
        left: (member_expression
          property: (property_identifier)@name
        )
        right: (function_expression)
      )
    )
  ] @definition.function
  (#strip! @doc "^[\\s\\*/]+|^[\\s\\*/]$")
  (#select-adjacent! @doc @definition.function)
)
"""

JS_FUNC = """
(
  [
    (function_expression
      name: (identifier) @name)
    (function_declaration
      name: (identifier) @name)
    (generator_function
      name: (identifier) @name)
    (generator_function_declaration
      name: (identifier) @name)
    (variable_declarator
      name: (identifier) @name
      value: (arrow_function)
    )
    (expression_statement
      (assignment_expression
        left: (member_expression
          property: (property_identifier)@name
        )
        right: (function_expression)
      )
    )
  ] @definition.function
)
"""