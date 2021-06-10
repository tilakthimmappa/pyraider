import colored
from colored import stylize
import json
import os
import pkg_resources
from pyraider.utils import export_to_csv, export_to_json, show_vulnerablities, \
    render_package_update_report, scan_vulnerabilities, scanned_vulnerable_data, \
    validate_version, fix, auto_fix_all, show_secure_packages, get_info_from_pypi, check_latestdb, scan_light_vulnerabilities, export_to_html


def read_from_env(export_format=None, export_file_path=None,deep_scan=False,sev=None):
    """
        Collect requirments from env and scan and show reports
    """
    print(stylize('Started Scanning .....', colored.fg("green")))
    print('\n')
    data_dict = {}
    secure_data_dict = []
    data_dict['pyraider'] = []
    data_dict['version'] = '1.0.13'
    vul_package_count = 0
    if deep_scan:
        data = scan_vulnerabilities()
    else:
        data = scan_light_vulnerabilities()
    dists = [d for d in pkg_resources.working_set]
    for pkg in dists:
        convert_str = str(pkg)
        package = convert_str.split()
        req_name = package[0].lower()
        req_version = package[1]
        scanned_data = scanned_vulnerable_data(data, req_name, req_version, sev)
        if bool(scanned_data):
            vul_package_count += 1
            if not export_format:
                show_vulnerablities(scanned_data, sev)
            if export_format == 'json':
                data_dict['pyraider'].append(scanned_data)
            elif export_format == 'csv':
                data_dict['pyraider'].append(scanned_data)
            elif export_format == 'html':
                data_dict['pyraider'].append(scanned_data)
            if not export_format:
                show_secure_packages(secure_data_dict)
        if not export_format:
            show_secure_packages(secure_data_dict)
    if export_format == 'json':
        export_to_json(data_dict, export_file_path)
    elif export_format == 'csv':
        export_to_csv(data_dict, export_file_path)
    elif export_format == 'html':
        export_to_html(data_dict, export_file_path)
    if vul_package_count == 0:
        print(stylize('No known vulnerabilities found', colored.fg("green")))


def check_new_version(to_scan_file=None, vpackage=False):
    """
        Check latest version from requirements.txt file
    """
    if to_scan_file:
        filename, file_extension = os.path.splitext(to_scan_file)
        if file_extension == '.lock':
            with open(to_scan_file) as fp:
                line = json.loads(fp.read())
                for k, v in line['default'].items():
                    validated_data = validate_version(
                        k.lower(), v['version'].split("==")[1])
                    render_package_update_report(validated_data)
        if file_extension == '.txt':
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
    if to_scan_file and vpackage:
        req = to_scan_file.strip().split('==')
        if len(req) == 2:
            req_name = req[0].lower()
            req_version = req[1]
            validated_data = validate_version(
                req_name, req_version)
            render_package_update_report(validated_data)
        else:
            validated_data = validate_version(req[0].lower(), None)
            render_package_update_report(validated_data)

    if to_scan_file==None and vpackage==False:
        dists = [d for d in pkg_resources.working_set]
        for pkg in dists:
            convert_str = str(pkg)
            package = convert_str.split()
            req_name = package[0].lower()
            req_version = package[1]
            validated_data = validate_version(req_name, req_version)
            render_package_update_report(validated_data)


def read_from_file(to_scan_file, export_format=None, export_file_path=None, deep_scan=False,sev=None):
    """
        Read requirents from requirements.txt file and also we can generate a JSON and CSV report.
    """
    print(stylize('Started Scanning .....', colored.fg("green")))
    print('\n')
    data_dict = {}
    secure_data_dict = []
    data_dict['pyraider'] = []
    data_dict['version'] = '1.0.13'
    vul_package_count = 0
    filename, file_extension = os.path.splitext(to_scan_file)
    if deep_scan:
        data = scan_vulnerabilities()
    else:
        data = scan_light_vulnerabilities()
    if file_extension == '.lock':
        with open(to_scan_file) as fp:
            line = json.loads(fp.read())
            for k, v in line['default'].items():
                req_name = k.lower()
                package_version = v['version'].split("==")
                req_version = package_version[1]
                pyenv_scanned_data = scanned_vulnerable_data(
                    data, req_name, req_version,sev)
                if bool(pyenv_scanned_data):
                    vul_package_count +=1
                    if not export_format:
                        show_vulnerablities(pyenv_scanned_data, sev)
                    if export_format == 'json':
                        data_dict['pyraider'].append(pyenv_scanned_data)
                    elif export_format == 'csv':
                        data_dict['pyraider'].append(pyenv_scanned_data)
                    elif export_format == 'html':
                        data_dict['pyraider'].append(pyenv_scanned_data)
            if not export_format:
                show_secure_packages(secure_data_dict)
    if file_extension == '.txt':
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
                        data, txt_req_name, txt_req_version,sev)
                    if bool(txt_scanned_data):
                        vul_package_count +=1
                        if not export_format:
                            show_vulnerablities(txt_scanned_data, sev)
                        if export_format == 'json':
                            data_dict['pyraider'].append(txt_scanned_data)
                        elif export_format == 'csv':
                            data_dict['pyraider'].append(txt_scanned_data)
                        elif export_format == 'html':
                            data_dict['pyraider'].append(txt_scanned_data)
                line = fp.readline()
                cnt += 1
        if not export_format:
            show_secure_packages(secure_data_dict)
    if export_format == 'json':
        export_to_json(data_dict, export_file_path)
    elif export_format == 'csv':
        export_to_csv(data_dict, export_file_path)
    elif export_format == 'html':
        export_to_html(data_dict, export_file_path)
    if vul_package_count == 0:
        print(stylize('No known vulnerabilities found', colored.fg("green")))


def fix_packages(to_scan_file=None, is_pipenv=False, sev=None, deep_scan=False):
    """
        Update one by one packages
    """ 
    print(stylize('Started Scanning .....', colored.fg("green")))
    print('\n')
    if deep_scan:
        data = scan_vulnerabilities()
    else:
        data = scan_light_vulnerabilities()
    dists = [d for d in pkg_resources.working_set]
    data_list = []
    vul_package_count = 0
    for pkg in dists:
        convert_str = str(pkg)
        package = convert_str.split()
        req_name = package[0].lower()
        req_version = package[1]
        scanned_data = scanned_vulnerable_data(data, req_name, req_version, sev)
        if bool(scanned_data):
            vul_package_count += 1
            data_list.append(scanned_data)
    if len(data_list)  > 0:
        fix(data_list)
    if vul_package_count == 0:
        print(stylize('No known vulnerabilities found', colored.fg("green")))


def auto_fix_all_packages(to_scan_file=None, is_pipenv=False, sev=None, deep_scan=False):
    """
        Update all packages
    """
    print(stylize('Started Scanning .....', colored.fg("green")))
    print('\n')
    if deep_scan:
        data = scan_vulnerabilities()
    else:
        data = scan_light_vulnerabilities()
    all_packages = []
    vul_package_count = 0
    dists = [d for d in pkg_resources.working_set]
    for pkg in dists:
        convert_str = str(pkg)
        package = convert_str.split()
        req_name = package[0].lower()
        req_version = package[1]
        scanned_data = scanned_vulnerable_data(data, req_name, req_version, sev)
        if bool(scanned_data):
            vul_package_count += 1
            all_packages.append(scanned_data)
    if len(all_packages) > 0:
        auto_fix_all(all_packages)
    if vul_package_count == 0:
        print(stylize('No known vulnerabilities found', colored.fg("green")))
    


def update_db():
    check_latestdb()
# End-of-file