# PyRaider

> Using PyRaider You can scan installed dependencies known security vulnerabilities. It uses publicly known exploits, vulnerabilities database. [Documentation](https://pyraider.raidersource.com)

![version](https://img.shields.io/badge/release-1.0.19-success)
![python version](https://img.shields.io/badge/python-3-blue)
![license](https://img.shields.io/badge/license-MIT-brightgreen)
[![Downloads](https://static.pepy.tech/personalized-badge/pyraider?period=total&units=international_system&left_color=black&right_color=orange&left_text=downloads)](https://pepy.tech/project/pyraider)
[![Discord](https://img.shields.io/badge/chat-discord-46BC99.svg)](https://discord.gg/SdX62BnS8Y)
[![Twitter](https://img.shields.io/badge/follow--informational?style=social&logo=twitter)](https://twitter.com/tilakthimmappa)


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

```bash
pip install pyraider
```

```bash
pyenv install pyraider
```

### To check the list of options available.

```bash
pyraider -h
```

##  Scan Vulnerabilities against the dependencies
> Using PyRaider you can scan the vulnerable packages.

### To run basic scan you can use `pyraider go` command. 
>It will automatically detects the installed packages and scans against it and shows the report.

```bash
pyraider go
```

### If you want to scan you packages against `requirements.txt` or `Pipfile.lock` file.

```bash
pyraider check -f /Users/raider/project/requirements.txt
```

```bash
pyraider check -f /Users/raider/project/Pipfile.lock
```

## Reports
> PyRaider currently supports `JSON`, `HTML` and `CSV` formats.

### To Export as a `JSON` file.

```bash
pyraider go -e json result.json
```

```bash
pyraider check -f /Users/raider/project/requirements.txt -e json result.json
```


### To Export as a `CSV` file.

```bash
pyraider go -e csv result.csv
```

```bash
pyraider check -f /Users/raider/project/requirements.txt -e csv result.csv
```


### To Export as a `HTML` file.

```bash
pyraider check -f go -e html result.html
```

```bash
pyraider check -f /Users/raider/project/requirements.txt -e html result.html
```


## Out of Date Pacakges
> Using PyRaider you can check the latest packages. Against installed packages.

```bash
pyraider validate -p django==1.11.13
```

```bash
pyraider validate -f /Users/raider/project/requirements.txt
```

```bash
pyraider validate -f /Users/raider/project/Pipfile.lock
```


## Auto Fix
> PyRaider also supports `fix` feature. Using this you can fix the vulnerable packages.

**Note:** To updating the packages might affect your application.

### Fix
> You can fix vulnerable package.

```bash
pyraider fix
```
### Fix by Severity

```bash
pyraider fix -s high
```

### Autofix
> You can also autofix vulnerable packages.

```bash
pyraider autofix
```

### Autofix by severity
```bash
pyraider autofix -s high
```

### Update latest database
> Now you can update the resource database with latest updated vulnerabilities

```bash
pyraider updatedb
```

## Docker container
> You can also run `pyraider` has a docker container.

### Build docker container image

```bash
docker build -t pyraider .
```

### Contact us:
* Discord : [Click here](https://discord.gg/tBbmCJq) to join Discord, to be a part of **PyRaider** family.
* Follow us on Twitter : https://twitter.com/tilakthimmappa
* Email : raidersource@gmail.com

### Contribute
* We welcome contributions to this project in the form of:
    * Feature Requests, Suggestions
    * Bugs
    * Help with writing tests
    * Add-on features, plugins, etc
    * Documentation

### Author
    
* [Tilak Thimmapppa](https://tilakthimmappa.com/)
* [Twitter](https://twitter.com/tilakthimmappa)