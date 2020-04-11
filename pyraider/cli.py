"""
Usage:
  pyraider go
  pyraider check -f <filename>
  pyraider check -f <filename> -e <format> <exportFileName>
  pyraider validate
  pyraider validate -f <filename>
  pyraider fix
  pyraider autofix
  pyraider updatedb

Examples:
  pyraider go
  pyraider check -f requirments.txt
  pyraider check -f requirments.txt -e json result.json
  pyraider check -f requirments.txt -e csv result.csv
  pyraider validate
  pyraider validate -f requirments.txt
  pyraider fix
  pyraider autofix
  pyraider updatedb

Options:
  -h, --help
  -v, --version
"""

from docopt import docopt
import os
from pyraider.main_pyraider import read_from_file, read_from_env, check_new_version, \
    fix_packages, auto_fix_all_packages,update_db

logo = """
  _____       _____       _     _           
 |  __ \     |  __ \     (_)   | |          
 | |__) |   _| |__) |__ _ _  __| | ___ _ __ 
 |  ___/ | | |  _  // _` | |/ _` |/ _ \ '__|
 | |   | |_| | | \ \ (_| | | (_| |  __/ |   
 |_|    \__, |_|  \_\__,_|_|\__,_|\___|_|   
         __/ |                              
        |___/    
 
by RaiderSource version 0.4.7
"""


def find_file(name, path):
    """
        Find requirments.txt file
    """
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def main():
    print(logo)
    arguments = docopt(__doc__, version='0.4.7')
    if arguments.get('check') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
        try:
            filename, file_extension = os.path.splitext(
                arguments.get('<filename>'))
            if file_extension == '.txt':
                read_from_file(arguments.get('<filename>'))
            elif file_extension == '.lock':
                read_from_file(arguments.get('<filename>'), is_pipenv=True)
            else:
                read_from_file(arguments.get('<filename>'))
        except Exception as e:
            exit(1)
    if arguments.get('check') and arguments.get('<exportFileName>') and arguments.get('<format>'):
        try:
            filename, file_extension = os.path.splitext(
                arguments.get('<filename>'))
            if file_extension == '.txt':
                read_from_file(arguments.get('<filename>'), arguments.get(
                    '<format>'), arguments.get('<exportFileName>'))
            elif file_extension == '.lock':
                read_from_file(arguments.get('<filename>'), arguments.get(
                    '<format>'), arguments.get('<exportFileName>'), is_pipenv=True)
            else:
                read_from_file(arguments.get('<filename>'), arguments.get(
                    '<format>'), arguments.get('<exportFileName>'))
        except Exception as e:
            exit(1)
    if arguments.get('go'):
        try:
            find_req_file = find_file('requirements.txt', '.')
            find_pipenv_file = find_file('Pipfile.lock', '.')
            if find_req_file:
                read_from_file(find_req_file)
            elif find_pipenv_file:
                read_from_file(find_req_file, is_pipenv=True)
            else:
                read_from_env()
        except Exception as e:
            exit(1)
    if arguments.get('validate'):
        try:
            find_req_file = find_file('requirements.txt', '.')
            find_pipenv_file = find_file('Pipfile.lock', '.')
            if arguments.get('<filename>'):
                filename, file_extension = os.path.splitext(
                    arguments.get('<filename>'))
                if file_extension == '.txt':
                    check_new_version(arguments.get('<filename>'))
                elif file_extension == '.lock':
                    check_new_version(arguments.get(
                        '<filename>'), is_pipenv=True)
                else:
                    check_new_version()
            elif find_req_file:
                check_new_version(find_req_file)
            elif find_pipenv_file:
                check_new_version(find_pipenv_file, is_pipenv=True)
            else:
                check_new_version()
        except Exception as e:
            exit(1)
    if arguments.get('fix'):
        try:
            find_req_file = find_file('requirements.txt', '.')
            find_pipenv_file = find_file('Pipfile.lock', '.')
            if find_req_file:
                fix_packages(find_req_file)
            elif find_pipenv_file:
                fix_packages(find_pipenv_file, is_pipenv=True)
            else:
                fix_packages()
        except Exception as e:
            exit(1)
    if arguments.get('autofix'):
        try:
            find_req_file = find_file('requirements.txt', '.')
            find_pipenv_file = find_file('Pipfile.lock', '.')
            if find_req_file:
                auto_fix_all_packages(find_req_file)
            elif find_pipenv_file:
                auto_fix_all_packages(find_pipenv_file, is_pipenv=True)
            else:
                auto_fix_all_packages()
        except Exception as e:
            exit(1)
    if arguments.get('updatedb'):
        try:
            update_db()
        except Exception as e:
            exit(1)


if __name__ == "__main__":
    main()

# End-Of-File
