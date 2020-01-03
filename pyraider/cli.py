"""
Usage:
  pyraider go
  pyraider check -f <filename>
  pyraider check -f <filename> -e <format> <exportFileName>
  pyraider validate
  pyraider validate -f <filename>
  pyraider fix
  pyraider autofix

Examples:
  pyraider go
  pyraider check -f requirments.txt
  pyraider check -f requirments.txt -e json result.json
  pyraider check -f requirments.txt -e csv result.csv
  pyraider validate
  pyraider validate -f requirments.txt
  pyraider fix
  pyraider autofix

Options:
  -h, --help
  -v, --version
"""

from docopt import docopt
import os
from pyraider.main_pyraider import read_from_file, read_from_env, check_new_version, \
    fix_packages, auto_fix_all_packages

logo =  """
  _____       _____       _     _           
 |  __ \     |  __ \     (_)   | |          
 | |__) |   _| |__) |__ _ _  __| | ___ _ __ 
 |  ___/ | | |  _  // _` | |/ _` |/ _ \ '__|
 | |   | |_| | | \ \ (_| | | (_| |  __/ |   
 |_|    \__, |_|  \_\__,_|_|\__,_|\___|_|   
         __/ |                              
        |___/    
 
by RaiderSource version 0.2
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
    arguments = docopt(__doc__, version='0.1')
    if arguments.get('check') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
        try:
            read_from_file(arguments.get('<filename>'))
        except Exception as e:
            exit(1)
    if arguments.get('check') and arguments.get('<exportFileName>') and arguments.get('<format>'):
        try:
            read_from_file(arguments.get('<filename>'), arguments.get('<format>'), arguments.get('<exportFileName>'))
        except Exception as e:
            exit(1)
    if arguments.get('go'):
        try:
            fileName = find_file('requirements.txt', '.')
            if fileName:
                read_from_file(fileName)
            else:
                read_from_env()
        except Exception as e:
            exit(1)
    if arguments.get('validate'):
        try:
            fileName = find_file('requirements.txt', '.')
            if arguments.get('<filename>'):
                check_new_version(arguments.get('<filename>'))            
            elif fileName:
                check_new_version(fileName)            
            else:
                check_new_version()
        except Exception as e:
            exit(1)
    if arguments.get('fix'):
        try:
            fileName = find_file('requirements.txt', '.')
            if fileName:
                fix_packages(fileName)
            else:
                fix_packages()
        except Exception as e:
            exit(1)
    if arguments.get('autofix'):
        try:
            fileName = find_file('requirements.txt', '.')
            if fileName:
                auto_fix_all_packages(fileName)
            else:
                auto_fix_all_packages()
        except Exception as e:
            exit(1)

if __name__ == "__main__":
    main()

# End-Of-File
