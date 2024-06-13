from db_instance import DatabaseConnection
import llm as llm
import requests
import json
import os
import urllib.request
import zipfile
import shutil
import comment.third as comment_fetch
from legal_module_name import is_legal_module_name


def find_in_database(module_name, eco):
    """
    search the module in database
    """
    db = DatabaseConnection('remote')
    if is_legal_module_name(module_name):
        builtin_query_result = db.package_in_builtin(module_name, eco)
        if len(builtin_query_result) != 0:
            db.close()
            return 'BUILTIN'
        else:
            third_part_result = db.package_in_third_part(module_name, eco)
            if len(third_part_result) != 0:
                db.close()
                return 'THIRD_PART'
            else:
                db.close()
                return 'NOT_IN'
    else:
        db.close()
        return 'NOT_IN'


def is_function_of_module(module_name, function_name, eco, log):
    db = DatabaseConnection('remote')
    query_result = db.function_of_the_module(eco, module_name, function_name, 'third')
    db.close()
    if len(query_result) != 0:
        log.info(f"`{function_name}` is the function from module `{module_name}`")
        return True
    else:
        return False


def get_download_name(module_name: str, dependency_list: list):
    for dependency in dependency_list:
        if '/' in dependency:
            if module_name == dependency.split('/')[-1]:
                return dependency
        elif module_name == dependency:
            return dependency
    return module_name


def add_to_database(module_name: str, dependency_list: list, eco: str):
    download_name = get_download_name(module_name, dependency_list)
    current_file_path = os.path.abspath(__file__)
    current_dir_path = os.path.dirname(current_file_path)

    npm_package_download_folder = os.path.join(current_dir_path, f'../npm_download/')
    npm_package_unzip_folder = os.path.join(current_dir_path, f'../npm_unzip/')
    url = 'https://registry.npmmirror.com/'
    res = requests.get(f"{url}{download_name}")

    if res.status_code == 200:
        js = json.loads(res.text)
        if 'versions' not in js:
            return False

        link = js['versions'][list(js['versions'])[-1]]['dist']['tarball']
        if link is None:
            print(f"No URL found in module: {download_name}")
        else:
            fileName = link.split("/")[-1]
            db = DatabaseConnection('remote')
            try:
                urllib.request.urlretrieve(link, os.path.join(npm_package_download_folder, fileName))

                src_path = os.path.join(npm_package_download_folder, fileName)
                dst_path = os.path.join(npm_package_unzip_folder, download_name)
                if fileName.endswith(".whl") or fileName.endswith(".egg"):
                    with zipfile.ZipFile(src_path, "r") as zip_ref:
                        zip_files = zip_ref.namelist()
                        for zip_file in zip_files:
                            zip_ref.extract(zip_file, dst_path)
                elif fileName.endswith(".tgz") or fileName.endswith(".zip") or fileName.endswith(".tar.gz"):
                    shutil.unpack_archive(src_path, dst_path)
                else:
                    raise Exception(f'file: {fileName} with unsupported type')

                function_list = comment_fetch.get_function_list(dst_path, "javascript")
                for func in function_list:
                    db.to_db(download_name, func.file, func.name, func.qualifiedname, func.comment,
                             func.parameters_num, func.code, f'{eco}_third')
                db.close()
                return True
            except Exception as e:
                db.close()
                return False
    else:
        return False


def is_sensitive_call(qualifier, call_name, eco, db_name, category=None):
    db = DatabaseConnection('remote')
    res = db.query(eco, db_name, 'package', qualifier, 'name', call_name)
    if len(res) != 0:
        category_str = res[0][7]
        if category_str is not None and category_str != '':
            if category_str == 'Others':
                db.close()
                return False, 'Others'
            else:
                category_list = category_str.split('-')
                db.close()
                return True, category_list
        else:
            # GPT
            if db_name == 'third':
                comment = res[0][5]
                code = res[0][9]
                code_summary = llm.llm_code_summary(code)
                category_list = llm.llm_classification_comment_with_code_summary(comment, code_summary)
                category_string = '-'.join(category_list)
                if 'Others' in category_string:
                    category_string = 'Others'
                db.update(eco, db_name, res[0][0], 'category', category_string)
                db.update(eco, db_name, res[0][0], 'summary', code_summary)
            else:
                comment = res[0][5]
                category_list = llm.llm_classification(comment)
                category_string = '-'.join(category_list)
                if 'Others' in category_string:
                    category_string = 'Others'
                db.update(eco, db_name, res[0][0], 'category', category_string)
            if 'Others' in category_string:
                db.close()
                return False, 'Others'
            else:
                db.close()
                return True, category_list
    else:
        if db_name == 'third':
            if category is not None:
                code_assumption = llm.llm_make_assumption_from_cate_call_name(qualifier, category, call_name)
            else:
                code_assumption = llm.llm_make_assumption_from_code(f"{qualifier}.{call_name}()", call_name,
                                                                    'JavaScript')
        else:
            code_assumption = llm.llm_make_assumption_from_code(f"{qualifier}.{call_name}()", call_name, 'JavaScript')
        category_list = llm.llm_classification(code_assumption)
        category_string = '-'.join(category_list)
        if 'Others' in category_string:
            category_string = 'Others'

        db.insert(eco, db_name, qualifier, call_name, qualifier + '.' + call_name, category_string, code_assumption)
        if 'Others' in category_string:
            db.close()
            return False, 'Others'
        else:
            db.close()
            return True, category_list
