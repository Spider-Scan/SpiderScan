import npm_pipeline.analyser as npm_analyser
from loggerManager import LoggerManager
import os
import argparse
from status import *


def analyse(package_name, report_dir, code_dir, joern_dir, format_dir, log_pipeline: LoggerManager,
            overwrite=True, generate_report=True):
    status = npm_analyser.run(package_name=package_name, report_dir=report_dir, code_dir=code_dir,
                              joern_dir=joern_dir, format_dir=format_dir,
                              overwrite=overwrite, generate_report=generate_report)
    if status == STATUS_JOERN_ERROR:
        log_pipeline.info(f"package: {package_name} Joern error")
    elif status == STATUS_MALICIOUS:
        log_pipeline.critical(f"package: {package_name} is malicious")
    elif status == STATUS_BENIGN:
        log_pipeline.info(f"package: {package_name} is benign")
    elif status == STATUS_CODE_NOT_EXIST:
        log_pipeline.warning(f"package: {package_name} code dir not exist")
    elif status == STATUS_CODE_SYNTACTIC_ERROR:
        log_pipeline.info(f"package: {package_name} code syntactic error")
    elif status == STATUS_EMPTY_PACKAGE:
        log_pipeline.info(f"package: {package_name} is empty")
    elif status == STATUS_OBFUSCATION:
        log_pipeline.critical(f"package: {package_name} is obfuscated")
    elif status == STATUS_PACKAGE_JSON_NOT_EXIST:
        log_pipeline.info(f"package: {package_name} does not contain package.json")
    elif status == STATUS_TIMEOUT:
        log_pipeline.info(f"package: {package_name} is time out")
    elif status == STATUS_GPT_ERROR:
        log_pipeline.info(f"package: {package_name} GPT error")
    else:
        return None

    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-base_dir', type=str)
    parser.add_argument('-package_dir', type=str)
    parser.add_argument('-package_name', type=str)
    parser.add_argument('-report_dir', type=str)
    parser.add_argument('-joern_workspace', type=str)
    args = parser.parse_args()
    base_dir = args.base_dir
    package_dir = args.package_dir
    package_name = args.package_name
    report_dir = args.report_dir
    joern_workspace = args.joern_workspace

    _pipeline_log_dir = os.path.join(base_dir, 'run_info')
    _log_pipeline = LoggerManager('pipeline_info', _pipeline_log_dir, asctime=True, overwrite=False)
    _log_pipeline.info(f"Start Analyzing: {package_name}")
    _format_dir = os.path.join(base_dir, 'format')
    analyse(package_name, report_dir, package_dir, joern_workspace, _format_dir, _log_pipeline)
