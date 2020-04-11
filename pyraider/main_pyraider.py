import colored
from colored import stylize
import json
import pkg_resources
from pyraider.utils import export_to_csv, export_to_json, show_vulnerablities, \
    render_package_update_report, scan_vulnerabilities, scanned_vulnerable_data, \
    validate_version, fix, auto_fix_all, show_secure_packages, get_info_from_pypi, check_latestdb


def read_from_env():
    """
        Collect requirments from env and scan and show reports
    """
    print(stylize('Started Scanning .....', colored.fg("green")))
    print('\n')
    data = scan_vulnerabilities()
    dists = [d for d in pkg_resources.working_set]
    for pkg in dists:
        convert_str = str(pkg)
        package = convert_str.split()
        req_name = package[0].lower()
        req_version = package[1]
        scanned_data = scanned_vulnerable_data(data, req_name, req_version)
        if scanned_data:
            show_vulnerablities(scanned_data)


def check_new_version(to_scan_file=None, is_pipenv=False):
    """
        Check latest version from requirements.txt file
    """
    if to_scan_file:
        if is_pipenv:
            with open(to_scan_file) as fp:
                line = json.loads(fp.read())
                for k, v in line['default'].items():
                    validated_data = validate_version(
                        k.lower(), v['version'].split("==")[1])
                    render_package_update_report(validated_data)
        else:
            with open(to_scan_file) as fp:
                line = fp.readline()
                cnt = 1
                while line:
                    req = line.strip().split('==')
                    if len(req) == 2:
                        req_name = req[0].lower()
                        req_version = req[1]
                        validated_data = validate_version(
                            req_name, req_version)
                        render_package_update_report(validated_data)
                    line = fp.readline()
                    cnt += 1
    else:
        dists = [d for d in pkg_resources.working_set]
        for pkg in dists:
            convert_str = str(pkg)
            package = convert_str.split()
            req_name = package[0].lower()
            req_version = package[1]
            validated_data = validate_version(req_name, req_version)
            render_package_update_report(validated_data)


def read_from_file(to_scan_file, export_format=None, export_file_path=None, is_pipenv=False):
    """
        Read requirents from requirements.txt file and also we can generate a JSON and CSV report.
    """
    print(stylize('Started Scanning .....', colored.fg("green")))
    print('\n')
    data_dict = []
    secure_data_dict = []
    data = scan_vulnerabilities()
    if is_pipenv:
        with open(to_scan_file) as fp:
            line = json.loads(fp.read())
            for k, v in line['default'].items():
                req_name = k.lower()
                package_version = v['version'].split("==")
                req_version = package_version[1]
                pyenv_scanned_data = scanned_vulnerable_data(
                    data, req_name, req_version)
                if bool(pyenv_scanned_data):
                    show_vulnerablities(pyenv_scanned_data)
                    if export_format == 'json':
                        data_dict.append(pyenv_scanned_data)
                    elif export_format == 'csv':
                        data_dict.append(pyenv_scanned_data)
            show_secure_packages(secure_data_dict)
    else:
        with open(to_scan_file) as fp:
            line = fp.readline()
            cnt = 1
            while line:
                package = line.strip()
                txt_req = package.split('==')
                if len(txt_req) == 2:
                    txt_req_name = txt_req[0].lower()
                    txt_req_version = txt_req[1]
                    txt_scanned_data = scanned_vulnerable_data(
                        data, txt_req_name, txt_req_version)
                    if bool(txt_scanned_data):
                        show_vulnerablities(txt_scanned_data)
                        if export_format == 'json':
                            data_dict.append(txt_scanned_data)
                        elif export_format == 'csv':
                            data_dict.append(txt_scanned_data)
                line = fp.readline()
                cnt += 1
        show_secure_packages(secure_data_dict)
    if export_format == 'json':
        report_header = {'pyraider': '0.4.7'}
        data_dict.append(report_header)
        export_to_json(data_dict, export_file_path)
    elif export_format == 'csv':
        report_header = {'pyraider': '0.4.7'}
        data_dict.append(report_header)
        export_to_csv(data_dict, export_file_path)


def fix_packages(to_scan_file=None, is_pipenv=False):
    """
        Update one by one packages
    """
    if to_scan_file:
        if is_pipenv:
            with open(to_scan_file) as fp:
                line = json.loads(fp.read())
                for k, v in line['default'].items():
                    validated_data = validate_version(
                        k.lower(), v['version'].split("==")[1])
                    fix(validated_data, to_scan_file, is_pipenv=True)
        else:
            with open(to_scan_file) as fp:
                line = fp.readline()
                cnt = 1
                while line:
                    req = line.strip().split('==')
                    if len(req) == 2:
                        req_name = req[0].lower()
                        req_version = req[1]
                        validated_data = validate_version(
                            req_name, req_version)
                        fix(validated_data, to_scan_file)
                    line = fp.readline()
                    cnt += 1
    else:
        dists = [d for d in pkg_resources.working_set]
        for pkg in dists:
            convert_str = str(pkg)
            package = convert_str.split()
            req_name = package[0].lower()
            req_version = package[1]
            validated_data = validate_version(req_name, req_version)
            fix(validated_data, to_scan_file)


def auto_fix_all_packages(to_scan_file=None, is_pipenv=False):
    """
        Update all packages
    """
    if to_scan_file:
        all_packages = []
        if is_pipenv:
            with open(to_scan_file) as fp:
                line = json.loads(fp.read())
                for k, v in line['default'].items():
                    validated_data = validate_version(
                        k.lower(), v['version'].split("==")[1])
                    all_packages.append(validated_data)
            auto_fix_all(all_packages, to_scan_file, is_pipenv=True)
        else:
            with open(to_scan_file) as fp:
                line = fp.readline()
                cnt = 1
                while line:
                    req = line.strip().split('==')
                    if len(req) == 2:
                        req_name = req[0].lower()
                        req_version = req[1]
                        validated_data = validate_version(
                            req_name, req_version)
                        all_packages.append(validated_data)
                    line = fp.readline()
                    cnt += 1
            auto_fix_all(all_packages, to_scan_file)
    else:
        all_packages = []
        dists = [d for d in pkg_resources.working_set]
        for pkg in dists:
            convert_str = str(pkg)
            package = convert_str.split()
            req_name = package[0].lower()
            req_version = package[1]
            validated_data = validate_version(req_name, req_version)
            all_packages.append(validated_data)
        auto_fix_all(all_packages, to_scan_file)


def update_db():
    check_latestdb()
# End-of-file
