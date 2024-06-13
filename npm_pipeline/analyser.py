import json
import os
import re
import shutil
from npm_pipeline.classes.package import Package
import traceback
import joern_helper
from ast_parser import ASTParser
from status import *
import signal
import jsbeautifier
from custom_exception import PackageJsonNotFoundException
from obfuscation_detect import detect_obfuscation
import subprocess

timeout_limit = 600


def timeout_handler(signum, frame):
    raise TimeoutError("Time out")


def timeout(seconds):
    def decorator(func):
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapper

    return decorator


@timeout(timeout_limit)
def run(package_name: str, report_dir: str, code_dir: str, joern_dir: str, format_dir: str,
        overwrite=True, generate_report: bool = False):
    report_path = os.path.join(report_dir, package_name)
    os.makedirs(report_path, exist_ok=True)
    package_dir = os.path.join(code_dir, package_name)
    if not os.path.exists(package_dir):
        return STATUS_CODE_NOT_EXIST

    try:
        format_package_dir = os.path.join(format_dir, package_name)
        # move to format folder
        move_folder(package_dir, format_package_dir)

        res, obfuscated_file_list = detect_obfuscation(pkg_dir=format_package_dir)
        if res is False:
            pass
        else:
            if obfuscated_file_list:
                report_path = os.path.join(report_dir, package_name, 'report.json')
                data = {'Malicious': True, 'Obfuscation': obfuscated_file_list}
                with open(report_path, 'w') as file:
                    json.dump(data, file, indent=4)

                return STATUS_OBFUSCATION

        package_joern_path = os.path.abspath(os.path.join(joern_dir, package_name))
        pdg_dir = os.path.join(joern_dir, package_name, 'pdg')
        cfg_dir = os.path.join(joern_dir, package_name, 'cfg')
        cpg_dir = os.path.join(joern_dir, package_name, 'cpg')
        if os.path.exists(package_joern_path) and not overwrite:
            pass
        else:
            package_preprocess(format_package_dir)
            joern_helper.joern_export(package_name, format_package_dir, joern_dir, 'javascript', overwrite=overwrite)
            cpg_preprocess(cpg_dir)
            joern_helper.joern_preprocess(format_package_dir, pdg_dir, cfg_dir, cpg_dir)

        if not os.path.exists(pdg_dir):
            print(f"{package_name}'s pdg dir is not exist")
            return STATUS_JOERN_ERROR
        if not os.path.exists(cfg_dir):
            print(f"{package_name}'s cfg path is not exist")
            return STATUS_JOERN_ERROR
        if not os.path.exists(cpg_dir):
            print(f"{package_name}'s cpg path is not exist")
            return STATUS_JOERN_ERROR
        contents = os.listdir(pdg_dir)
        package = Package(package_name=package_name, package_dir=format_package_dir, pdg_dir=pdg_dir, cpg_dir=cpg_dir)
        if package.get_file_number() == 0:

            # no js files
            print(f"There is no js file in {package_name}")

            # analyze package.json
            status = package.analyse_script(report_dir=report_dir, generate_report=generate_report)
            return status
        else:
            if not contents:
                print(f"{package_name}'s pdg dir is empty, which means the code may have syntax error")
                status = package.analyse_script(report_dir=report_dir, generate_report=generate_report)
                if status == STATUS_MALICIOUS:
                    return STATUS_MALICIOUS
                else:
                    return STATUS_CODE_SYNTACTIC_ERROR
        status = package.analyse(report_dir=report_dir, generate_report=generate_report)
        return status

    except PackageJsonNotFoundException:
        print(f"Package.json is not exist")
        return STATUS_PACKAGE_JSON_NOT_EXIST
    except ConnectionError:
        print(f"GPT Connection error")
        return STATUS_GPT_ERROR
    except FileNotFoundError as e:
        print(f"Joern parsing Error: {e}")
        return STATUS_JOERN_ERROR
    except subprocess.TimeoutExpired as e:
        print(f"Joern Time out: {e}")
        return STATUS_JOERN_ERROR
    except TimeoutError:
        print(f"Time out")
        return STATUS_TIMEOUT
    except Exception as e:
        traceback.print_exc()
        print(e)
        return STATUS_PROGRAM_ERROR


def move_folder(source, destination):
    if os.path.exists(destination):
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def package_preprocess(pkg_dir):
    js_files = []
    for root, dirs, files in os.walk(pkg_dir):
        for file in files:
            if file.endswith('.js'):
                js_files.append(os.path.join(root, file))
    for file in js_files:
        require_process(file)
        property_access_process(file)
        await_process(file)
        format_code(file)
        joern_fix(file)


def require_process(path):
    with open(path, 'r') as code_file:
        code = code_file.read()

    pattern = r"""require\(['"]node:[^'"]+['"]\)"""
    match_list = re.findall(pattern, code)
    for match in match_list:
        require_code_without_node = match.replace("node:", "", 1)
        code = code.replace(match, require_code_without_node, 1)

    parser = ASTParser(code, "javascript")

    query_variable = """        
        (variable_declarator 
            (object_pattern 
                (shorthand_property_identifier_pattern)@property
            ) @ob
            .
          (call_expression 
              (identifier)@id (#eq? @id "require")
          )
        )@va
    """
    code = replace_require(parser, code, query_variable, path)
    query_key_value = """
    (variable_declarator 
          (object_pattern 
                (pair_pattern
                	key: (property_identifier)@key
                    value: (identifier)@value
                )
          ) @ob
            .
          (call_expression 
              (identifier)@id (#eq? @id "require")
          )
    )@va
    """
    code = replace_require_key_value(parser, code, query_key_value, path)

    with open(path, 'w') as code_file:
        code_file.write(code)


def await_process(path):
    with open(path, 'r') as code_file:
        code = code_file.read()

    parser = ASTParser(code, "javascript")
    query = """
        (await_expression)@await
    """
    result = parser.query(query)
    for res in result:
        await_expression = res[0].text.decode()

        replaced_await_expression = await_expression.replace('await ', '')
        code = code.replace(await_expression, replaced_await_expression)

    with open(path, 'w') as code_file:
        code_file.write(code)


def replace_require(parser: ASTParser, code: str, query: str, path: str):
    result = parser.query(query)
    insert_index = 0
    import_statement = [r[0].text.decode() for r in result if r[1] == "va"]
    property_of_import = [r[0].text.decode() for r in result if r[1] == "property"]
    object_pattern = [r[0].text.decode() for r in result if r[1] == "ob"]
    for item1, item2, item3 in zip(import_statement, property_of_import, object_pattern):
        tmp = item1
        item1 = item1.replace(item3, item2, 1)
        item1 = item1.replace(';', '') + "." + item2
        if insert_index == 0:
            insert_index = code.find(tmp)
            code = code.replace(tmp, item1)
            insert_index = insert_index + len(item1)
        else:

            code = code[:insert_index] + ', ' + item1 + code[insert_index:]
            insert_index = insert_index + 2 + len(item1)

    return code


def replace_require_key_value(parser: ASTParser, code: str, query: str, path: str):
    result = parser.query(query)
    insert_index = 0
    import_statement = [r[0].text.decode() for r in result if r[1] == "va"]
    key = [r[0].text.decode() for r in result if r[1] == "key"]
    value = [r[0].text.decode() for r in result if r[1] == "value"]
    object_pattern = [r[0].text.decode() for r in result if r[1] == "ob"]
    for item1, item2, item3, item4 in zip(import_statement, key, value, object_pattern):
        temp = item1
        item1 = item1.replace(item4, item2, 1)
        item1 = item1 + '.' + item3
        if insert_index == 0:
            insert_index = code.find(temp)
            code = code.replace(temp, item1)
            insert_index = insert_index + len(item1)
        else:
            code = code[:insert_index] + '; ' + item1 + code[insert_index:]
            insert_index = insert_index + 2 + len(item1)

    return code


def property_access_process(path):
    process_property = ['arch', 'platform', 'version', 'env', 'platform', 'config', 'pid', 'release', 'versions',
                        'argv']
    document_property = ['cookie', 'forms']
    with open(path, 'r') as code_file:
        code = code_file.read()
        for item in process_property:
            pattern = rf'(?<![a-zA-Z0-9])(process\.{item})(?![a-zA-Z0-9\(\[])'
            match_list = re.findall(pattern, code)
            for match in match_list:
                code = re.sub(pattern, match + '()', code, count=1)
        for item in document_property:
            pattern = rf'(?<![a-zA-Z0-9])(document\.{item})(?![a-zA-Z0-9\(])(?![ ]*=[ ]*)'
            match_list = re.findall(pattern, code)
            for match in match_list:
                code = re.sub(pattern, match + '()', code, count=1)
    with open(path, 'w') as code_file:
        code_file.write(code)


def format_code(path):
    with open(path, 'r') as code_file:
        try:
            code = code_file.read()
            formatted_code = jsbeautifier.beautify(code)

            with open(path, 'w') as code_write_ile:
                code_write_ile.write(formatted_code)
        except Exception as e:
            print(f"Format Code failed: {e}")


def cpg_preprocess(cpg_path):
    cpg_file_path = os.path.join(cpg_path, 'export.dot')
    if not os.path.exists(cpg_file_path):
        return

    with open(cpg_file_path, 'r') as file:
        dot_file_contents = file.readlines()

    for index, line in enumerate(dot_file_contents):
        new_line = process_one_line_of_cpg(line)
        dot_file_contents[index] = new_line

    with open(cpg_file_path, 'w') as file:
        file.writelines(dot_file_contents)


def process_one_line_of_cpg(line):
    index_of_DYNAMIC_TYPE_HINT_FULL_NAME = line.find('DYNAMIC_TYPE_HINT_FULL_NAME=\"')
    if index_of_DYNAMIC_TYPE_HINT_FULL_NAME == -1:

        return line
    else:

        index_of_NAME = line.find('\" NAME=\"')
        if index_of_NAME != -1:

            inner_content = line[index_of_DYNAMIC_TYPE_HINT_FULL_NAME + 29: index_of_NAME]
            inner_content = inner_content.replace('\"', '\\\"')
            line = line[0: index_of_DYNAMIC_TYPE_HINT_FULL_NAME + 29] + inner_content + line[index_of_NAME:]
            return line
        else:

            index_of_right_square = line.find('\"]')

            if index_of_right_square != -1 and index_of_right_square == len(line) - 3:
                inner_content = line[index_of_DYNAMIC_TYPE_HINT_FULL_NAME + 29: index_of_right_square]
                inner_content = inner_content.replace('\"', '\\\"')
                line = line[0: index_of_DYNAMIC_TYPE_HINT_FULL_NAME + 29] + inner_content + line[index_of_right_square:]
                return line
            else:
                return line


def joern_fix(path):
    with open(path, 'r') as code_file:
        code = code_file.read()
    with open(path, 'r') as code_file:
        lines = code_file.readlines()

    parser = ASTParser(code, 'javascript')
    query = """(expression_statement
	            (call_expression
    	            function: (member_expression
       		            object: (identifier) @identifier
                        property: (property_identifier)@property_identifier
                        (#eq? @property_identifier "forEach")
        	        )
                    arguments: (arguments
         	        (identifier)@argument_identifier
                )
            )
        )@expression_statement
    """
    query_result = parser.query(query)
    if len(query_result) != 0:
        identifier_list = [r[0] for r in query_result if r[1] == 'identifier']
        argument_identifier_list = [r[0] for r in query_result if r[1] == 'argument_identifier']
        expression_statement_list = [r[0] for r in query_result if r[1] == 'expression_statement']
        identifier = identifier_list[0]
        argument_identifier = argument_identifier_list[0]
        expression_statement = expression_statement_list[0]

        start_point = expression_statement.start_point
        end_point = expression_statement.end_point
        identifier_text = identifier.text.decode()
        argument_identifier_text = argument_identifier.text.decode()
        fixed_code = f"{identifier_text}.forEach(({identifier_text}_) => {argument_identifier_text}({identifier_text}_));"
        start_row = start_point.row
        start_column = start_point.column
        end_row = end_point.row
        end_column = end_point.column
        if start_row == end_row:
            line = lines[start_row]
            lines[start_row] = line[:start_column] + fixed_code + line[end_column:]
        else:
            start_line = lines[start_row][:start_column] + fixed_code
            # Handle the end line
            end_line = lines[end_row][end_column:]

            # Replace the lines in between with an empty string
            for i in range(start_row + 1, end_row):
                lines[i] = ""

            # Combine start and end
            lines[start_row] = start_line
            lines[end_row] = end_line
        with open(path, 'w') as file:
            file.writelines(lines)
    else:
        return
