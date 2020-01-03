import pkg_resources
from pyraider.utils import export_to_csv, export_to_json, show_vulnerablities, \
    render_package_update_report, scan_vulnerabilities, scanned_vulnerable_data, \
    validate_version, fix, auto_fix_all

def read_from_env():
    """
        Collect requirments from env and scan and show reports
    """
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


def check_new_version(to_scan_file):
    """
        Check latest version from requirements.txt file
    """
    with open(to_scan_file) as fp:
        line = fp.readline()
        cnt = 1
        while line:
            req = line.strip().split('==')
            if len(req) == 2:
                req_name = req[0].lower()
                req_version = req[1]
                validated_data = validate_version(req_name, req_version)
                render_package_update_report(validated_data)
            line = fp.readline()
            cnt += 1

def read_from_file(to_scan_file, export_format=None, export_file_path=None):
    """
        Read requirents from requirements.txt file and also we can generate a JSON and CSV report.
    """
    data_dict = []
    data = scan_vulnerabilities()
    with open(to_scan_file) as fp:
        line = fp.readline()
        cnt = 1
        while line:
            req = line.strip().split('==')
            if len(req) == 2:
                req_name = req[0].lower()
                req_version = req[1]
                scanned_data = scanned_vulnerable_data(data, req_name, req_version)
                if scanned_data:
                    show_vulnerablities(scanned_data)
                    if export_format == 'json':
                        data_dict.append(scanned_data)
                    elif export_format == 'csv':
                        data_dict.append(scanned_data)
            line = fp.readline()
            cnt += 1
    if export_format == 'json':
        report_header = {'pyraider': '0.2'}
        data_dict.append(report_header)
        export_to_json(data_dict, export_file_path)
    elif export_format == 'csv':
        report_header = {'pyraider': '0.2'}
        data_dict.append(report_header)
        export_to_csv(data_dict, export_file_path)


def fix_packages(to_scan_file=None):
    """
        Update one by one packages
    """
    if to_scan_file:
        with open(to_scan_file) as fp:
            line = fp.readline()
            cnt = 1
            while line:
                req = line.strip().split('==')
                if len(req) == 2:
                    req_name = req[0].lower()
                    req_version = req[1]
                    validated_data = validate_version(req_name, req_version)
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

def auto_fix_all_packages(to_scan_file=None):
    """
        Update all packages
    """
    if to_scan_file:
        all_packages = []
        with open(to_scan_file) as fp:
            line = fp.readline()
            cnt = 1
            while line:
                req = line.strip().split('==')
                if len(req) == 2:
                    req_name = req[0].lower()
                    req_version = req[1]
                    validated_data = validate_version(req_name, req_version)
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
        auto_fix_all(all_packages,to_scan_file)


# End-of-file
