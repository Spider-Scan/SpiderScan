from obfuscation_detection.classify_api import classify_api
import os

model = 'obfuscation_detection/models/3-grams/model'


def detect_obfuscation(pkg_dir: str):
    obfuscated_files = []
    for root, dirs, files in os.walk(pkg_dir):
        for file in files:
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                obfuscated_file_path = get_obfuscated_file(file_path)
                if obfuscated_file_path is not None:
                    obfuscated_files.append(obfuscated_file_path)

    if len(obfuscated_files) == 0:
        return False, []

    else:
        return True, obfuscated_files


def get_obfuscated_file(file_path):
    if classify_api(js_file=file_path, model=model, ngrams=3) == 'malicious':
        return file_path
    else:
        return None
