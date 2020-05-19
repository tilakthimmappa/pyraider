from beautifultable import BeautifulTable
import colored
from colored import stylize
import csv
import hashlib
import json
from json2html import *
import os
import pickle
from pkg_resources import parse_version
import subprocess
import sys
import ssl

lib_path = os.path.abspath(os.path.join('..'))
sys.path.append(lib_path)
try:
    from urllib2 import Request, urlopen
except ImportError:
    from urllib.request import Request, urlopen, urlretrieve

resource_file_hash = '6c01752524f79084c642e3ecc4b4fdd7'
resource_light_file_hash = 'dcc71e14f99c901023920083958d4a3c'


def export_to_json(data_dict, export_file_path):
    """
        Export vulnerable data into a JSON file
    """
    if len(data_dict.get('pyraider'))>0:
        result_path = ''
        if export_file_path == '.':
            result_path = 'result.json'
            print(stylize('result.json has been exported in the current directory', colored.fg("green")))
        elif export_file_path:
            result_path = export_file_path
            filename = os.path.basename(result_path)
            print(stylize('{0} has been exported in {1} directory'.format(filename, result_path), colored.fg("green")))
        else:
            result_path = 'result.json'
            print(stylize('result.json has been exported in the current directory', colored.fg("green")))
        
        with open(result_path, 'w') as fp:
            json.dump(data_dict, fp, indent=4)

def export_to_html(data_dict, export_file_path):
    """
        Export vulnerable data into a JSON file
    """
    if len(data_dict.get('pyraider'))>0:
        result_path = ''
        if export_file_path == '.':
            result_path = 'result.html'
            print(stylize('result.html has been exported in the current directory', colored.fg("green")))
        elif export_file_path:
            result_path = export_file_path
            filename = os.path.basename(result_path)
            print(stylize('{0} has been exported in {1} directory'.format(filename, result_path), colored.fg("green")))
        else:
            result_path = 'result.html'
            print(stylize('result.html has been exported in the current directory', colored.fg("green")))
        data = json2html.convert(json = data_dict, table_attributes="id=\"info-table\" class=\"table table-striped table-bordered table-hover\"")
        header = """<html>
    <head>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    </head>
    <div class="jumbotron jumbotron-fluid">
    <div class="container">
        <h1 class="display-4">PyRaider Result</h1>    
    </div>
    </div>
    <hr>
    <br>
    </html>"""
        with open(result_path, 'w') as fp:
            fp.write(header) 
            fp.write(data) 


def export_to_csv(data_dict, export_file_path):
    """
        Export vulnerable data into a CSV file
    """
    if len(data_dict.get('pyraider'))>0:
        result_path = ''
        if export_file_path == '.':
            result_path = 'result.csv'
            print(stylize('result.csv has been exported in the current directory', colored.fg("green")))
        elif export_file_path:
            result_path = export_file_path
            filename = os.path.basename(result_path)
            print(stylize('{0} has been exported in {1} directory'.format(filename, result_path), colored.fg("green")))
        else:
            result_path = 'result.csv'
            print(stylize('result.csv has been exported in the current directory', colored.fg("green")))
        with open(result_path, 'w') as f:
            writer = csv.DictWriter(f,
                                    fieldnames=['Package', 'Current Version', 'Description', 'Severity', 'CWE', 'CVE',
                                                'Update Version'])
            writer.writeheader()
            for k,v in data_dict.items():
                for data in v:
                    for k, v in data.items():
                        writer.writerow(
                            {"Package": k, "Current Version": v.get('current_version'), "Description": v.get('decription'),
                            'Severity': v.get('severity'), 'CWE': v.get('cwe'),
                            'CVE': v.get('cve'), 'Update Version': v.get('update_to')})

def show_high_severity_vulnerabilities(data_dict):
    """
        Only High severity
    """    
    for k, v in data_dict.items():
        parent_table = BeautifulTable()
        parent_table.append_row(['Package', k])
        if v.get('severity') == 'HIGH':
            parent_table.append_row(
                ["Severity", stylize(v.get('severity'), colored.fg("red"))])
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
            parent_table.append_row(['Description', v.get('description')])
            parent_table.append_row(['Resolve', "pip install {0}=={1}".format(k,v.get('update_to'))])
            parent_table.append_row(['More Info', "https://nvd.nist.gov/vuln/detail/{0}".format(v.get('cve'))])
            print('\n')
            print(parent_table)

def show_medium_severity_vulnerabilities(data_dict):
    """
        Only Medium severity
    """
    for k, v in data_dict.items():
        parent_table = BeautifulTable()
        parent_table.append_row(['Package', k])
        if v.get('severity') == 'MEDIUM':
            parent_table.append_row(["Severity", stylize(
                v.get('severity'), colored.fg("yellow"))])
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
            parent_table.append_row(['Description', v.get('description')])
            parent_table.append_row(['Resolve', "pip install {0}=={1}".format(k,v.get('update_to'))])
            parent_table.append_row(['More Info', "https://nvd.nist.gov/vuln/detail/{0}".format(v.get('cve'))])
            print('\n')
            print(parent_table)

def show_low_severity_vulnerabilities(data_dict):
    """
        Only Low severity
    """
    for k, v in data_dict.items():
        parent_table = BeautifulTable()
        parent_table.append_row(['Package', k])
        if v.get('severity') == 'Low':
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
            parent_table.append_row(['Description', v.get('description')])
            parent_table.append_row(['Resolve', "pip install {0}=={1}".format(k,v.get('update_to'))])
            parent_table.append_row(['More Info', "https://nvd.nist.gov/vuln/detail/{0}".format(v.get('cve'))])
            print('\n')
            print(parent_table)


def show_vulnerablities(data_dict,sev=None):
    """
        Render Vulnerable data into a terminal table
    """
    if sev == 'HIGH':
        show_high_severity_vulnerabilities(data_dict)
    elif sev == 'MEDIUM':
        show_medium_severity_vulnerabilities(data_dict)
    elif sev == 'LOW':
        show_low_severity_vulnerabilities(data_dict)
    else:       
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
            parent_table.append_row(['Description', v.get('description')])
            parent_table.append_row(['Resolve', "pip install {0}=={1}".format(k,v.get('update_to'))])
            parent_table.append_row(['More Info', "https://nvd.nist.gov/vuln/detail/{0}".format(v.get('cve'))])
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
        if v.get('current_version') !=None:
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
        else:
             parent_table.append_row(['Latest Version', stylize(
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
    if current_version != None:
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

def scan_light_vulnerabilities():
    """
        Read from database
    """
    this_dir, this_filename = os.path.split(__file__)
    data_path = os.path.join(this_dir, 'resource_light.pickle')
    if os.path.exists(data_path):
        if resource_light_file_hash == hashlib.md5(open(data_path, 'rb').read()).hexdigest():
            data = pickle.load(open(data_path, 'rb'))
            return data
        else:
            print(stylize(
                'Downloading resources to scan the packages, It may take some time to download  .....', colored.fg("green")))
            ssl._create_default_https_context = ssl._create_unverified_context
            url = 'https://pyraider-source-data.s3-us-west-2.amazonaws.com/resource_light.pickle'
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
        url = 'https://pyraider-source-data.s3-us-west-2.amazonaws.com/resource_light.pickle'
        try:
            urlretrieve(url, data_path)
        except Exception as e:
            print(stylize('There is some error. You need to enable `https://pyraider-source-data.s3-us-west-2.amazonaws.com/` URL to download database',
                          colored.fg("red")))
        data = pickle.load(open(data_path, 'rb'))
        print(stylize('Resource has been successfully downloaded', colored.fg("green")))
        return data


def check_latestdb(deep_scan=False):
    """
        check and download the latest database
    """
    this_dir, this_filename = os.path.split(__file__)
    if deep_scan:
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
    else:
        data_path = os.path.join(this_dir, 'resource_light.pickle')
        if resource_light_file_hash == hashlib.md5(open(data_path, 'rb').read()).hexdigest():
            print(stylize('Resource database is already upto date', colored.fg("green")))
        else:
            print(stylize('Downloading resources to scan the packages, It may take some time to download  .....', colored.fg("green")))
            ssl._create_default_https_context = ssl._create_unverified_context
            url = 'https://pyraider-source-data.s3-us-west-2.amazonaws.com/resource_light.pickle'
            try:
                urlretrieve(url, data_path)
            except Exception as e:
                print(stylize('There is some error. You need to enable `https://pyraider-source-data.s3-us-west-2.amazonaws.com/` URL to download database',
                            colored.fg("red")))
            print(stylize('Resource database has been successfully updated',
                        colored.fg("green")))

def scanned_high_severity(data, req_name, req_version):
    """
        Scan High vulnerable library
    """
    data_dict = {}
    for k, v in data.items():
        if k.lower() == req_name:
            validated_version = get_info_from_pypi(k.lower())
            for vuls in v.get('info'):
                if vuls.get('sev') == 'HIGH':                    
                    if vuls.get('version'):
                        if req_version <= vuls.get('version') or vuls.get('version') <= req_version:
                            data_dict[k] = {}
                            data_dict[k]['current_version'] = req_version
                            data_dict[k]['update_to'] = validated_version
                            data_dict[k]['cwe'] = vuls.get('cwe')
                            data_dict[k]['cve'] = vuls.get('cve')
                            data_dict[k]['severity'] = vuls.get('sev')
                            if vuls.get('description'):
                                data_dict[k]['description'] = vuls.get('description')
    return data_dict

def scanned_medium_severity(data, req_name, req_version):
    """
        Scan Medium vulnerable library
    """
    data_dict = {}
    for k, v in data.items():
        if k.lower() == req_name:
            validated_version = get_info_from_pypi(k.lower())
            for vuls in v.get('info'):
                if vuls.get('sev') == 'MEDIUM':
                    if vuls.get('version'):
                        if req_version <= vuls.get('version') or vuls.get('version') <= req_version:
                            data_dict[k] = {}
                            data_dict[k]['current_version'] = req_version
                            data_dict[k]['update_to'] = validated_version
                            data_dict[k]['cwe'] = vuls.get('cwe')
                            data_dict[k]['cve'] = vuls.get('cve')
                            data_dict[k]['severity'] = vuls.get('sev')
                            if vuls.get('description'):
                                data_dict[k]['description'] = vuls.get('description')
    return data_dict

def scanned_low_severity(data, req_name, req_version):
    """
        Scan Low vulnerable library
    """
    data_dict = {}
    for k, v in data.items():
        if k.lower() == req_name:
            validated_version = get_info_from_pypi(k.lower())
            for vuls in v.get('info'):
                if vuls.get('sev') == 'LOW':
                    if vuls.get('version'):
                        if req_version <= vuls.get('version') or vuls.get('version') <= req_version:
                            data_dict[k] = {}
                            data_dict[k]['current_version'] = req_version
                            data_dict[k]['update_to'] = validated_version
                            data_dict[k]['cwe'] = vuls.get('cwe')
                            data_dict[k]['cve'] = vuls.get('cve')
                            data_dict[k]['severity'] = vuls.get('sev')
                            if vuls.get('description'):
                                data_dict[k]['description'] = vuls.get('description')
    return data_dict


def scanned_vulnerable_data(data, req_name, req_version,sev):
    """
        Scan vulnerable library
    """
    if sev == 'HIGH':
        data_dict = scanned_high_severity(data, req_name, req_version)
        return data_dict
    elif sev == 'MEDIUM':
        data_dict = scanned_medium_severity(data, req_name, req_version)
        return data_dict
    elif sev == 'LOW':
        data_dict = scanned_low_severity(data, req_name, req_version)
        return data_dict
    else:
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
                            if vuls.get('description'):
                                data_dict[k]['description'] = vuls.get('description')
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
