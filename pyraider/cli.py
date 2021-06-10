"""
Usage:
  pyraider go [-d | -s [high|medium|low] | -e <format> | -e <format>  <exportFileName> | -e <format> -s [high|medium|low] | -e <format>  <exportFileName> -s [high|medium|low] | -d -s [high|medium|low] | -d -e <format> | -d -e <format>  <exportFileName> | -d -e <format> -s [high|medium|low] | -d -e <format> <exportFileName> -s [high|medium|low]]
  pyraider check -f <filename> [-d | -e <format> | <exportFileName> | -e <format>  <exportFileName> | -s [high|medium|low] | -e <format> -s [high|medium|low] |  -e <format>  <exportFileName> -s [high|medium|low]]
  pyraider validate [-p <package> | -f <filename>]
  pyraider fix [-d | -s [high|medium|low] | -d -s [high|medium|low]]
  pyraider autofix [-d | -s [high|medium|low] | -d -s [high|medium|low]]
  pyraider updatedb [-d]

Examples:
  pyraider go
  pyraider go -s high
  pyraider go -e json
  pyraider go -e json -s high
  pyraider check -f requirements.txt
  pyraider check -f requirements.txt -e json result.json
  pyraider check -f requirements.txt -e json result.json -s high
  pyraider validate
  pyraider validate -p django==1.11.13
  pyraider validate -f requirements.txt
  pyraider fix
  pyraider fix -s high
  pyraider autofix
  pyraider autofix -s high
  pyraider updatedb

Options:
  -h, --help
  -v, --version
"""

from docopt import docopt
import os
from pyraider.main_pyraider import read_from_file, read_from_env, check_new_version, \
    fix_packages, auto_fix_all_packages, update_db

logo = """
  _____       _____       _     _
 |  __ \     |  __ \     (_)   | |
 | |__) |   _| |__) |__ _ _  __| | ___ _ __
 |  ___/ | | |  _  // _` | |/ _` |/ _ \ '__|
 | |   | |_| | | \ \ (_| | | (_| |  __/ |
 |_|    \__, |_|  \_\__,_|_|\__,_|\___|_|
         __/ |
        |___/

by RaiderSource version 1.0.13
"""


def find_file(name, path):
    """
        Find requirements.txt file
    """
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def main():
    print(logo)
    arguments = docopt(__doc__, version='1.0.13')
    if arguments.get('check'):
        if arguments.get('high'):
            if arguments.get('<filename>') and not arguments.get('<exportFileName>') and not arguments.get('<format>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'),sev='HIGH')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('-d') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
                try:
                    read_from_file(arguments.get('<filename>'), deep_scan=True, sev='HIGH')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('<format>') and not arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), ".", sev='HIGH')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('<format>') and arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), arguments.get('<exportFileName>'),sev='HIGH')
                except Exception as e:
                    exit(1)
        elif arguments.get('medium'):
            if arguments.get('<filename>') and not arguments.get('<exportFileName>') and not arguments.get('<format>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'),sev='MEDIUM')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('-d') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
                try:
                    read_from_file(arguments.get('<filename>'), deep_scan=True, sev='MEDIUM')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('<format>') and not arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), ".", sev='MEDIUM')
                except Exception as e:
                    exit(1)
            elif arguments.get('<format>') and arguments.get('<filename>') and arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), arguments.get('<exportFileName>'),sev='MEDIUM')
                except Exception as e:
                    exit(1)
        elif arguments.get('low'):
            if arguments.get('<filename>') and not arguments.get('<exportFileName>') and not arguments.get('<format>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'),sev='LOW')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('-d') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
                try:
                    read_from_file(arguments.get('<filename>'), deep_scan=True, sev='LOW')
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('<format>') and not arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), ".", sev='LOW')
                except Exception as e:
                    exit(1)
            elif arguments.get('<format>') and arguments.get('<filename>') and arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), arguments.get('<exportFileName>'),sev='LOW')
                except Exception as e:
                    exit(1)
        else:
            if arguments.get('<filename>') and not arguments.get('<exportFileName>') and not arguments.get('<format>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'))
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('-d') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
                try:
                    read_from_file(arguments.get('<filename>'), deep_scan=True)
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>') and arguments.get('<format>') and not arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), ".")
                except Exception as e:
                    exit(1)
            elif arguments.get('<filename>')  and arguments.get('<format>') and arguments.get('<filename>') and arguments.get('<exportFileName>') and not arguments.get('-d'):
                try:
                    read_from_file(arguments.get('<filename>'), arguments.get('<format>'), arguments.get('<exportFileName>'))
                except Exception as e:
                    exit(1)
    if arguments.get('go'):  
        if arguments.get('-d') and arguments.get('<format>') and arguments.get('<exportFileName>') and arguments.get('high'):
            try:
                read_from_env(arguments.get('<format>'),arguments.get('<exportFileName>'), deep_scan=True, sev='HIGH')
            except Exception as e:
                exit(1)
        if arguments.get('-d') and arguments.get('<format>') and not arguments.get('<exportFileName>') and arguments.get('high'):
            try:
                read_from_env(arguments.get('<format>'), deep_scan=True, sev='HIGH')
            except Exception as e:
                exit(1)
        elif arguments.get('-d') and arguments.get('<format>') and arguments.get('<exportFileName>') and arguments.get('medium'):
            try:
                read_from_env(arguments.get('<format>'),arguments.get('<exportFileName>'), deep_scan=True, sev='MEDIUM')
            except Exception as e:
                exit(1)
        elif arguments.get('-d') and arguments.get('<format>') and not arguments.get('<exportFileName>') and arguments.get('medium'):
            try:
                read_from_env(arguments.get('<format>'), deep_scan=True, sev='MEDIUM')
            except Exception as e:
                exit(1)
        elif arguments.get('-d') and arguments.get('<format>') and arguments.get('<exportFileName>') and arguments.get('low'):
            try:
                read_from_env(arguments.get('<format>'),arguments.get('<exportFileName>'), deep_scan=True, sev='LOW')
            except Exception as e:
                exit(1)  
        elif arguments.get('-d') and arguments.get('<format>') and not arguments.get('<exportFileName>') and arguments.get('low'):
            try:
                read_from_env(arguments.get('<format>'), deep_scan=True, sev='LOW')
            except Exception as e:
                exit(1)    
        elif arguments.get('-d') and arguments.get('<format>') and arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'),arguments.get('<exportFileName>'), deep_scan=True)
            except Exception as e:
                exit(1)    
        elif arguments.get('-d') and arguments.get('<format>') and not arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), deep_scan=True)
            except Exception as e:
                exit(1)
        elif arguments.get('-d') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
            try:
                read_from_env(deep_scan=True)
            except Exception as e:
                exit(1)                      
        elif arguments.get('high') and arguments.get('<format>') and arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'),arguments.get('<exportFileName>'), sev='HIGH')
            except Exception as e:
                exit(1)
        elif arguments.get('high') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
            try:
                read_from_env(sev='HIGH')
            except Exception as e:
                exit(1)
        elif arguments.get('high') and arguments.get('<format>') and not arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), sev='HIGH')
            except Exception as e:
                exit(1)    
        elif arguments.get('medium') and arguments.get('<format>') and arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), arguments.get('<exportFileName>'), sev='MEDIUM')
            except Exception as e:
                exit(1)    
        elif arguments.get('medium') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
            try:
                read_from_env(sev='MEDIUM')
            except Exception as e:
                exit(1)
        elif arguments.get('medium') and arguments.get('<format>') and not arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), sev='MEDIUM')
            except Exception as e:
                exit(1)  
        elif arguments.get('low') and arguments.get('<format>') and arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), arguments.get('<exportFileName>'), sev='LOW')
            except Exception as e:
                exit(1)              
        elif arguments.get('low') and not arguments.get('<exportFileName>') and not arguments.get('<format>'):
            try:
                read_from_env(sev='LOW')
            except Exception as e:
                exit(1)
        elif arguments.get('low') and arguments.get('<format>') and not arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), sev='LOW')
            except Exception as e:
                exit(1)          
        elif arguments.get('<format>') and not arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'))
            except Exception as e:
                exit(1)  
        elif arguments.get('<format>') and arguments.get('<exportFileName>'):
            try:
                read_from_env(arguments.get('<format>'), arguments.get('<exportFileName>'))
            except Exception as e:
                exit(1)        
        else:
            try:
                read_from_env()
            except Exception as e:
                exit(1)
    if arguments.get('validate'):
        try:
            if arguments.get('<package>'):
                check_new_version(arguments.get('<package>'), vpackage=True)
            elif arguments.get('<filename>'):
                check_new_version(arguments.get('<filename>'))
            else:
                check_new_version()
        except Exception as e:
            exit(1)
    if arguments.get('fix'):
        if arguments.get('-d') and arguments.get('high'):
            fix_packages(sev='HIGH', deep_scan=True)
        elif arguments.get('-d') and arguments.get('medium'):
            fix_packages(sev='MEDIUM', deep_scan=True)
        elif arguments.get('-d') and arguments.get('low'):
            fix_packages(sev='LOW', deep_scan=True)
        elif arguments.get('high'):
            fix_packages(sev='HIGH')
        elif arguments.get('medium'):
            fix_packages(sev='MEDIUM')
        elif arguments.get('low'):
            fix_packages(sev='LOW')
        elif arguments.get('-d'):
            fix_packages(deep_scan=True)
        else:
            try:
                fix_packages()
            except Exception as e:
                exit(1)
    if arguments.get('autofix'):
        if arguments.get('-d') and arguments.get('high'):
            auto_fix_all_packages(sev='HIGH', deep_scan=True)
        elif arguments.get('-d') and arguments.get('medium'):
            auto_fix_all_packages(sev='MEDIUM', deep_scan=True)
        elif arguments.get('-d') and arguments.get('low'):
            auto_fix_all_packages(sev='LOW', deep_scan=True)
        elif arguments.get('high'):
            auto_fix_all_packages(sev='HIGH')
        elif arguments.get('medium'):
            auto_fix_all_packages(sev='MEDIUM')
        elif arguments.get('low'):
            auto_fix_all_packages(sev='LOW')
        elif arguments.get('-d'):
            auto_fix_all_packages(deep_scan=True)
        else:
            try:
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