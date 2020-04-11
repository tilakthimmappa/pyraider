from beautifultable import BeautifulTable
import colored
from colored import stylize
import csv
import hashlib
import json
import os
import pickle
from pkg_resources import parse_version
import subprocess
import sys
import ssl
try:
    from urllib2 import Request, urlopen
except ImportError:
    from urllib.request import Request, urlopen, urlretrieve

resource_file_hash = '6c01752524f79084c642e3ecc4b4fdd7'


def export_to_json(data_dict, export_file_path):
    """
        Export vulnerable data into a JSON file
    """
    result_path = ''
    if export_file_path == '.':
        result_path = 'result.json'
    elif export_file_path:
        result_path = export_file_path
    else:
        result_path = 'result.json'
    with open(result_path, 'w') as fp:
        json.dump(data_dict, fp, indent=4)


def export_to_csv(data_dict, export_file_path):
    """
        Export vulnerable data into a CSV file
    """
    result_path = ''
    if export_file_path == '.':
        result_path = 'result.csv'
    elif export_file_path:
        result_path = export_file_path
    else:
        result_path = 'result.csv'
    with open(result_path, 'w') as f:
        writer = csv.DictWriter(f,
                                fieldnames=['Package', 'Current Version', 'Vulnerability', 'Severity', 'CWE', 'CVE',
                                            'Update Version'])
        writer.writeheader()
        for k, v in data_dict.items():
            writer.writerow(
                {"Package": k, "Current Version": v.get('current_version'), "Vulnerability": v.get('vul_name'),
                 'Severity': v.get('severity'), 'CWE': v.get('cwe'),
                 'CVE': v.get('cve'), 'Update Version': v.get('update_to')})


def show_vulnerablities(data_dict):
    """
        Render Vulnerable data into a terminal table
    """
    for k, v in data_dict.items():
        parent_table = BeautifulTable()
        parent_table.append_row(['Package', k])
        if v.get('severity') == 'HIGH':
            parent_table.append_row(
                ["Severity", stylize(v.get('severity'), colored.fg("red"))])
        elif v.get('severity') == 'MEDIUM':
            parent_table.append_row(["Severity", stylize(
                v.get('severity'), colored.fg("yellow"))])
        elif v.get('severity') == 'LOW':
            parent_table.append_row(
                ["Severity", stylize(v.get('severity'), colored.fg("blue"))])
        else:
            parent_table.append_row(
                ["Severity", stylize(v.get('severity'), colored.fg("blue"))])
        parent_table.append_row(['CWE', v.get('cwe')])
        parent_table.append_row(['CVE', v.get('cve')])
        if v.get('current_version') < v.get('update_to'):
            parent_table.append_row(['Current version', stylize(
                v.get('current_version'), colored.fg("red"))])
        else:
            parent_table.append_row(['Current version', stylize(
                v.get('current_version'), colored.fg("green"))])
        if v.get('current_version') == v.get('update_to'):
            parent_table.append_row(['Update To', stylize(
                'Package is up to date', colored.fg("green"))])
        else:
            parent_table.append_row(['Update To', stylize(
                v.get('update_to'), colored.fg("green"))])
        print('\n')
        print(parent_table)


def show_secure_packages(data_dict):
    """
        Render Vulnerable data into a terminal table
    """
    for secure in data_dict:
        for k, v in secure.items():
            parent_table = BeautifulTable()
            parent_table.append_row(['Package', k])
            parent_table.append_row(['Current version', stylize(
                v.get('current_version'), colored.fg("green"))])
            parent_table.append_row(['Status', stylize(
                'No known security vulnerabilities found', colored.fg("green"))])
            print('\n')
            print(parent_table)


def render_package_update_report(data_dict):
    """
        Render package and latest version
    """
    print("\n")
    for k, v in data_dict.items():
        parent_table = BeautifulTable()
        parent_table.append_row(['Package', k])
        if v.get('current_version') < v.get('update_to'):
            parent_table.append_row(['Current version', stylize(
                v.get('current_version'), colored.fg("red"))])
        else:
            parent_table.append_row(['Current version', stylize(
                v.get('current_version'), colored.fg("green"))])
        if v.get('current_version') == v.get('update_to'):
            parent_table.append_row(['Update To', stylize(
                'Package is up to date', colored.fg("green"))])
        else:
            parent_table.append_row(['Update To', stylize(
                v.get('update_to'), colored.fg("green"))])
        print('\n')
        print(parent_table)


def get_info_from_pypi(packages):
    """
        Get latest package version
    """
    ssl._create_default_https_context = ssl._create_unverified_context
    url = 'https://pypi.python.org/pypi/{0}/json'.format(packages)
    headers = {'Accept': 'application/json'}
    req = Request(url=url, headers=headers)
    resp = urlopen(req)
    if resp.code == 200:
        info = resp.read()
        decode_data = info.decode()
        info_data = json.loads(decode_data)
        latest_version = sorted(info_data["releases"], key=parse_version)
        return latest_version[-1]
    else:
        return 'Unexpected error'


def validate_version(packages, current_version):
    """
        Create a dict with current, and update version data
    """
    data_dict = {}
    validated_data = get_info_from_pypi(packages)
    data_dict[packages] = {}
    data_dict[packages]['current_version'] = current_version
    data_dict[packages]['update_to'] = validated_data
    return data_dict


def scan_vulnerabilities():
    """
        Read from database
    """
    this_dir, this_filename = os.path.split(__file__)
    data_path = os.path.join(this_dir, 'resource.pickle')
    if os.path.exists(data_path):
        if resource_file_hash == hashlib.md5(open(data_path, 'rb').read()).hexdigest():
            data = pickle.load(open(data_path, 'rb'))
            return data
        else:
            print(stylize(
                'Downloading resources to scan the packages, It may take some time to download  .....', colored.fg("green")))
            ssl._create_default_https_context = ssl._create_unverified_context
            url = 'https://pyraider-source-data.s3-us-west-2.amazonaws.com/resource.pickle'
            try:
                urlretrieve(url, data_path)
            except Exception as e:
                print(stylize('There is some error. You need to enable `https://pyraider-source-data.s3-us-west-2.amazonaws.com/` URL to download database',
                              colored.fg("red")))
            data = pickle.load(open(data_path, 'rb'))
            print(stylize('Resource has been successfully downloaded',
                          colored.fg("green")))
            return data
    else:
        print(stylize('Downloading resources to scan the packages, It may take some time to download  .....', colored.fg("green")))
        ssl._create_default_https_context = ssl._create_unverified_context
        url = 'https://pyraider-source-data.s3-us-west-2.amazonaws.com/resource.pickle'
        try:
            urlretrieve(url, data_path)
        except Exception as e:
            print(stylize('There is some error. You need to enable `https://pyraider-source-data.s3-us-west-2.amazonaws.com/` URL to download database',
                          colored.fg("red")))
        data = pickle.load(open(data_path, 'rb'))
        print(stylize('Resource has been successfully downloaded', colored.fg("green")))
        return data


def check_latestdb():
    """
        check and download the latest database
    """
    this_dir, this_filename = os.path.split(__file__)
    data_path = os.path.join(this_dir, 'resource.pickle')
    if resource_file_hash == hashlib.md5(open(data_path, 'rb').read()).hexdigest():
        print(stylize('Resource database is already upto date', colored.fg("green")))
    else:
        print(stylize('Downloading resources to scan the packages, It may take some time to download  .....', colored.fg("green")))
        ssl._create_default_https_context = ssl._create_unverified_context
        url = 'https://pyraider-source-data.s3-us-west-2.amazonaws.com/resource.pickle'
        try:
            urlretrieve(url, data_path)
        except Exception as e:
            print(stylize('There is some error. You need to enable `https://pyraider-source-data.s3-us-west-2.amazonaws.com/` URL to download database',
                          colored.fg("red")))
        print(stylize('Resource database has been successfully updated',
                      colored.fg("green")))


def scanned_vulnerable_data(data, req_name, req_version):
    """
        Scan vulnerable library
    """
    data_dict = {}
    for k, v in data.items():
        if k.lower() == req_name:
            validated_version = get_info_from_pypi(k.lower())
            for vuls in v.get('info'):
                if vuls.get('version'):
                    if req_version <= vuls.get('version') or vuls.get('version') <= req_version:
                        data_dict[k] = {}
                        data_dict[k]['current_version'] = req_version
                        data_dict[k]['update_to'] = validated_version
                        data_dict[k]['cwe'] = vuls.get('cwe')
                        data_dict[k]['cve'] = vuls.get('cve')
                        data_dict[k]['severity'] = vuls.get('sev')
                        data_dict[k]['vul_name'] = vuls.get('vul_name')
    return data_dict


def query_yes_no(question, default="yes"):
    """
        Question prompt tag
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: {0}".format(default))
    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            if valid[choice]:
                print("")
            else:
                print("")
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def fix(data_dict, to_scan_file, is_pipenv=False):
    """
        Update latest version one by one
    """
    for k, v in data_dict.items():
        if v.get('current_version') < v.get('update_to'):
            ans = "Do you want to update {0} pacakge to {1}, It might affect other packages?".format(
                k, v.get('update_to'))
            answers = query_yes_no(ans)
            if answers == True:
                if is_pipenv:
                    installing = subprocess.call(
                        ['pipenv', 'install', "{0}=={1}".format(k, v.get('update_to'))])
                    print(installing)
                    print(stylize("{0} == {1} version has been installed successfully!!!".format(
                        k, v.get('update_to')), colored.fg("green")))
                    print(
                        stylize("Pipfile has been updated successfully!!!"), colored.fg("green"))
                else:
                    installing = subprocess.call(
                        ['pip', 'install', "{0}=={1}".format(k, v.get('update_to'))])
                    print(installing)
                    print(stylize("{0} == {1} version has been installed successfully!!!".format(
                        k, v.get('update_to')), colored.fg("green")))
                    old_pkg_name = k + '==' + v.get('current_version')
                    new_pkg_name = k + '==' + v.get('update_to')
                    f = open(to_scan_file, 'r')
                    filedata = f.read()
                    f.close()
                    newdata = filedata.replace(old_pkg_name, new_pkg_name)
                    with open(to_scan_file, 'w') as p:
                        p.write(newdata)
                    print(stylize(
                        "requirements.txt file has been updated successfully!!!"), colored.fg("green"))
        else:
            print(stylize("{0} is already up-to date to {1} version".format(k,
                                                                            v.get('update_to')), colored.fg("green")))


def auto_fix_all(data_dict, to_scan_file, is_pipenv=False):
    """
        Update all packages 
    """
    ans = 'Are you sure want to update all the packages, It might affect other packages?'
    answers = query_yes_no(ans)
    if answers == True:
        for vul in data_dict:
            for k, v in vul.items():
                if v.get('current_version') < v.get('update_to'):
                    if is_pipenv:
                        installing = subprocess.call(
                            ['pipenv', 'install', "{0}=={1}".format(k, v.get('update_to'))])
                        print(installing)
                        print(stylize("{0} == {1} version has been installed successfully!!!".format(
                            k, v.get('update_to')), colored.fg("green")))
                        print(
                            stylize("Pipfile has been updated successfully!!!"), colored.fg("green"))
                    else:
                        installing = subprocess.call(
                            ['pip', 'install', "{0}=={1}".format(k, v.get('update_to'))])
                        print(installing)
                        print(stylize("{0} == {1} version has been installed successfully!!!".format(
                            k), colored.fg("green")))
                        old_pkg_name = k + '==' + v.get('current_version')
                        new_pkg_name = k + '==' + v.get('update_to')
                        f = open(to_scan_file, 'r')
                        filedata = f.read()
                        f.close()
                        newdata = filedata.replace(old_pkg_name, new_pkg_name)
                        with open(to_scan_file, 'w') as p:
                            p.write(newdata)
                        print(stylize(
                            "requirements.txt file has been updated successfully!!!"), colored.fg("green"))
                else:
                    print(stylize("{0} is already up to date to {1} version".format(
                        k, v.get('update_to')), colored.fg("green")))

# End-Of-File
