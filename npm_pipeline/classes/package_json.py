"""
PackageJson Class Description: Contains the behavior of the
"""
import json
import os
import re
import llm as llm
from npm_pipeline.classes.script import Script
from custom_exception import PackageJsonNotFoundException


def fetch_json_info(phase, json_object):
    script = Script(phase)
    script_type = json_object['Type']
    if script_type == 'Node':

        # run files
        script.set_script_type('Node')
        running_files = json_object['Run']
        running_file_list = []
        for file in running_files:
            running_file_list.append(file)
        script.set_running_files(running_file_list)
        script.set_need_static(True)
    elif script_type == 'Shell_Command':

        # shell command
        script.set_script_type('Shell Command')
    else:
        pass
    return script


def script_analysis(script_segment, field):
    pattern_node = r'node\s+([^\s]+\.js\b)'
    script_json = {}

    # regex first, if not then GPT
    match = re.findall(pattern_node, script_segment)
    if len(match) > 0:
        script_json['Type'] = 'Node'
        script_json['Run'] = []
        for run_item in match:
            script_json['Run'].append(run_item)

    else:
        script_json = llm.llm_analyse_script(script_segment)
    script_object = fetch_json_info(field, script_json)
    if script_object.get_script_type() == 'Shell Command':
        shell_command_json_object = llm.llm_shell_command_interpret(script_segment)
        description = shell_command_json_object['Description']
        judgement = shell_command_json_object['Judgement']
        file = shell_command_json_object['File'] if 'File' in shell_command_json_object else []
        file_list = []
        for value in file:
            file_list.append(value)
        script_object.set_shell_command(script_segment)
        script_object.set_shell_command_description(description)
        script_object.set_malicious(True if judgement == 'malicious' else False)
        script_object.set_running_files(file_list)
    return script_object


class PackageJson:
    def __init__(self, package_dir):
        self.pkg_dir = package_dir
        self.package_json_path = None
        self.main = None  # main script
        self.preinstall = None  # preinstall script
        self.install = None  # install script
        self.postinstall = None  # postinstall script
        self.description = None  # the description in for package.json
        self.dependencies = []  # the dependencies in package.json
        self.__get_root_package_json()
        self.__get_install_time_info()

    def __get_dependencies(self):
        """
        get the dependencies of package.json
        """
        with open(self.package_json_path, 'r') as package_json_file:
            package_json_data = json.load(package_json_file)
            if 'dependencies' in package_json_data.keys():
                for dependency in package_json_data['dependencies'].keys():
                    self.dependencies.append(dependency)

    def __get_root_package_json(self):
        """
        get the path of package.json
        default: pkg_dir/package/package.json
        """
        root_package_json_path = os.path.join(self.pkg_dir, 'package', 'package.json')
        if not os.path.exists(root_package_json_path):
            raise PackageJsonNotFoundException(
                f"package.json file not found at {os.path.join(self.pkg_dir, 'package')}")
        else:
            self.package_json_path = root_package_json_path

    def __get_install_time_info(self):
        """
        based on the script segment, fetch the info of install time
        """
        with open(self.package_json_path, 'r') as package_json_file:
            package_json_data = json.load(package_json_file)

        if 'main' in package_json_data.keys():
            self.main = package_json_data['main']
        else:
            # default
            self.main = 'index.js'

        if 'scripts' in package_json_data.keys():

            # search for entries in scripts
            for key, value in package_json_data['scripts'].items():

                # check the installation script
                # get the "preinstall" script
                if key == 'preinstall':
                    self.preinstall = value
                elif key == 'install':
                    self.install = value
                elif key == 'postinstall':
                    self.postinstall = value
                else:
                    pass

    def install_time_analyze(self, report_path) -> dict[str, Script]:
        """
        analyze postinstall preinstall install
        """

        def serialize_script(script):
            if isinstance(script, Script):
                return script.to_dict()
            else:
                raise TypeError(f"Object of type {type(script)} is not JSON serializable")

        def deserialize_script(data):
            if 'phase' in data:
                return Script.from_dict(data)
            else:
                return data

        package_json_profile_path = os.path.join(report_path, 'package_json_profile.json')
        if os.path.isfile(package_json_profile_path):
            with open(package_json_profile_path, 'r') as json_file:
                restored_description = json.load(json_file, object_hook=deserialize_script)
                return restored_description
        else:
            self.description = {}
            if self.preinstall is not None:
                self.description['preinstall'] = script_analysis(self.preinstall, 'preinstall')
            if self.install is not None:
                self.description['install'] = script_analysis(self.install, 'install')
            if self.postinstall is not None:
                self.description['postinstall'] = script_analysis(self.postinstall, 'postinstall')

        with open(package_json_profile_path, 'w') as json_file:
            json.dump(self.description, json_file, indent=4, default=serialize_script)
        return self.description

    def get_main(self):
        return self.main

    def get_dependencies(self):
        return self.dependencies

    def __str__(self):
        return f'main: {self.main}, ' \
               f'preinstall: {self.preinstall}, ' \
               f'install: {self.install}, ' \
               f'postinstall: {self.postinstall}'
