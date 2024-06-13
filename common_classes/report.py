import json
import os


class Report:
    def __init__(self):
        self.is_malicious = False
        self.install_time_script: dict = {}  # install-time scripts
        self.install_time_mal_behavior: dict[str, list[dict]] = {}  # maliciousness in install-time
        self.import_time_mal_behavior: dict[str, list[dict]] = {}  # maliciousness in import-time
        self.run_time_mal_behavior: dict[str, list[dict]] = {}  # maliciousness in run-time

    def add_phase_to_install_script(self, phase, script_desc):
        self.install_time_script[phase] = script_desc

    def add_malicious_locality(self, phase: str, description: str, sub_description: str, locality):
        """
        add a malicious behavior and the corresponding line numbers of malicious code
        :param phase: install import runtime
        :param description: general description
        :param sub_description: sub description
        :param locality: file ane line number
        """
        if phase == 'INSTALL':
            behavior_dict = self.install_time_mal_behavior
        elif phase == 'IMPORT':
            behavior_dict = self.import_time_mal_behavior
        else:
            behavior_dict = self.run_time_mal_behavior

        if description not in behavior_dict:
            behavior_dict[description] = []

        one_match = {'pattern desc': sub_description, 'file': {}}
        for item in locality:
            filename = item[0]
            line_number = item[1]
            if filename not in one_match['file']:
                one_match['file'][filename] = set()
            one_match['file'][filename].add(line_number)
        for filename in one_match['file']:
            one_match['file'][filename] = list(one_match['file'][filename])

        find_same = False
        for mal_match in behavior_dict[description]:
            if mal_match == one_match:
                find_same = True
                break
            else:
                file_dict_of_mal_match = mal_match['file']
                file_dict_of_one_match = one_match['file']
                if set(file_dict_of_mal_match.keys()) == set(file_dict_of_one_match.keys()):

                    is_subset = True
                    for file, node_list_of_mal_match in file_dict_of_mal_match.items():
                        node_list_of_one_match = file_dict_of_one_match[file]
                        if not set(node_list_of_one_match).issubset(set(node_list_of_mal_match)):
                            is_subset = False
                            break
                    if is_subset:
                        find_same = True
                        break

        if not find_same:
            behavior_dict[description].append(one_match)
            return True
        else:
            return False

    def write_to_file(self, path: str):
        path = os.path.join(path, 'report.json')
        data = {'Malicious': self.is_malicious}
        if self.install_time_script:
            for phase, script in self.install_time_script.items():
                data['INSTALL TIME SCRIPT'] = {phase: script}
        if self.install_time_mal_behavior:
            data['INSTALL'] = self.install_time_mal_behavior
        if self.import_time_mal_behavior:
            data['IMPORT'] = self.import_time_mal_behavior
        if self.run_time_mal_behavior:
            data['RUN'] = self.run_time_mal_behavior

        with open(path, 'w') as file:
            json.dump(data, file, indent=4)

    def set_malicious(self, bool_value):
        self.is_malicious = bool_value

    def get_malicious(self):
        return self.is_malicious

    def contain_information_stealing(self):
        if 'Information Stealing' in self.install_time_mal_behavior \
                or 'Information Stealing' in self.import_time_mal_behavior \
                or 'Information Stealing' in self.run_time_mal_behavior:
            return True
        else:
            return False
