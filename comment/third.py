import os
import json
import comment.query as querys
from comment.function import Function
from tree_sitter import Language, Parser
import tree_sitter_python as ts_python
import tree_sitter_javascript as ts_javascript

JS_LANGUAGE = Language(ts_javascript.language())
PY_LANGUAGE = Language(ts_python.language())


def get_src_files(folder_path: str, type: str, recursive: bool) -> list[str]:
    src_files = []
    if recursive:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith((f"{type}")):
                    src_files.append(os.path.join(root, file))
    else:
        for file in os.listdir(folder_path):
            if file.endswith((f"{type}")):
                src_files.append(os.path.join(folder_path, file))
    return src_files


def get_function_list_js(package_path: str) -> list[Function]:
    package_name = package_path.split("/")[-1]
    js_files = get_src_files(package_path, type=".js", recursive=True)
    parser = Parser(JS_LANGUAGE)
    function_list: list[Function] = []
    for file in js_files:
        with open(file, "rb") as f:
            data = f.read()
        tree = parser.parse(data)
        query = JS_LANGUAGE.query(querys.JS_EXPORT)
        captures = query.captures(tree.root_node)
        exports = [capture[0].text.decode() for capture in captures if capture[1] == "name"]
        query = JS_LANGUAGE.query(querys.JS_FUNC_DOC)
        captures = query.captures(tree.root_node)
        docs = [capture[0].text.decode() for capture in captures if capture[1] == "doc"]
        names = [capture[0].text.decode() for capture in captures if capture[1] == "name"]
        name_doc = dict(zip(names, docs))
        query = JS_LANGUAGE.query(querys.JS_FUNC)
        captures = query.captures(tree.root_node)
        names = [capture[0].text.decode() for capture in captures if capture[1] == "name"]
        codes = [capture[0].text.decode() for capture in captures if capture[1] == "definition.function"]
        for name, code in zip(names, codes):
            # if name not in exports:
            #     continue
            file_path = file.split(package_path)[1].strip("/")
            function = Function(package_name, file_path, name, name, name_doc.get(name, ""), 0, code)
            is_exits = False
            for func in function_list:
                if func.name == name:
                    is_exits = True
                    break
            if is_exits:
                continue
            function_list.append(function)
    return function_list


def get_function_list(package_path: str, language: str) -> list[Function]:
    if language == "javascript":
        return get_function_list_js(package_path)
    else:
        return []
