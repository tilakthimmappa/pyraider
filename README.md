# PyRaider

> Using PyRaider You can scan installed dependencies known security vulnerabilities. It uses publicly known exploits, vulnerabilities database. [Documentation](https://pyraider.raidersource.com)

![version](https://img.shields.io/badge/release-1.0.7-success)
![python version](https://img.shields.io/badge/python-2.7%20%3C%203.7.5-blue)
![license](https://img.shields.io/badge/license-MIT-brightgreen)
[![Downloads](https://static.pepy.tech/personalized-badge/pyraider?period=total&units=international_system&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/pyraider)
[![Discord](https://img.shields.io/badge/chat-discord-46BC99.svg)](https://discord.gg/nxQgrT)
[![Twitter](https://img.shields.io/badge/follow--informational?style=social&logo=twitter)](https://twitter.com/ti1akt)


![pyraider](img/pyraider_scan.png)

                                    
## Usage

# Table of Contents
1. [Installation](https://pyraider.raidersource.com/docs/installation)
2. [Usage](https://pyraider.raidersource.com/docs/usage)
3. [Scan Dependencies](https://pyraider.raidersource.com/docs/go)
4. [Scan Dependencies by Severity](https://pyraider.raidersource.com/docs/go-sev)
5. [Report](https://pyraider.raidersource.com/docs/json-reports)
6. [Outdated package check](https://pyraider.raidersource.com/docs/outdated-packages)
7. [CI/CD](https://pyraider.raidersource.com/docs/jenkins-ci-cd)
8. [Fix](https://pyraider.raidersource.com/docs/fix)
9. [Autofix](https://pyraider.raidersource.com/docs/autofix)
10. [Release Note](https://pyraider.raidersource.com/docs/release-note)
11. [Help](https://pyraider.raidersource.com/docs/help)

[Documentation](https://pyraider.raidersource.com/)

### Install `pyraider` using `pip` or `pyenv`

```commandline
pip install pyraider
```

```commandline
pyenv install pyraider
```

### To check the list of options available.

```commandline
pyraider -h
```

##  Scan Vulnerabilities against the dependencies
> Using PyRaider you can scan the vulnerable packages.

### To run basic scan you can use `pyraider go` command. 
>It will automatically detects the installed packages and scans against it and shows the report.

```commandline
pyraider go
```

### If you want to scan you packages against `requirements.txt` or `Pipfile.lock` file.

```commandline
pyraider check -f /Users/raider/project/requirements.txt
```

```commandline
pyraider check -f /Users/raider/project/Pipfile.lock
```

## Reports
> PyRaider currently supports `JSON`, `HTML` and `CSV` formats.

### To Export as a `JSON` file.

```commandline
pyraider go -e json result.json
```

```commandline
pyraider check -f /Users/raider/project/requirements.txt -e json result.json
```


### To Export as a `CSV` file.

```commandline
pyraider go -e csv result.csv
```

```commandline
pyraider check -f /Users/raider/project/requirements.txt -e csv result.csv
```


### To Export as a `HTML` file.

```commandline
pyraider check -f go -e html result.html
```

```commandline
pyraider check -f /Users/raider/project/requirements.txt -e html result.html
```


## Out of Date Pacakges
> Using PyRaider you can check the latest packages. Against installed packages.

```commandline
pyraider validate -p django==1.11.13
```

```commandline
pyraider validate -f /Users/raider/project/requirements.txt
```

```commandline
pyraider validate -f /Users/raider/project/Pipfile.lock
```


## Auto Fix
> PyRaider also supports `fix` feature. Using this you can fix the vulnerable packages.

**Note:** To updating the packages might affect your application.

### Fix
> You can fix vulnerable package.

```
pyraider fix
```
### Fix by Severity

```
pyraider fix -s high
```

### Autofix
> You can also autofix vulnerable packages.

```
pyraider autofix
```

### Autofix by severity
```
pyraider autofix -s high
```

### Update latest database
> Now you can update the resource database with latest updated vulnerabilities

```
pyraider updatedb
```

## Docker container
> You can also run `pyraider` has a docker container.

### Build docker container image

```
docker build -t pyraider .
```

### Contact us:
* Discord : [Click here](https://discord.gg/tBbmCJq) to join Discord, to be a part of **PyRaider** family.
* Follow us on Twitter : https://twitter.com/raidersrc
* Email : raidersource@gmail.com

### Contribute
* We welcome contributions to this project in the form of:
    * Feature Requests, Suggestions
    * Bugs
    * Help with writing tests
    * Add-on features, plugins, etc
    * Documentation

### Author
    
* [Tilak Thimmapppa](https://tilakt.com/)
* Twitter : https://twitter.com/ti1akt