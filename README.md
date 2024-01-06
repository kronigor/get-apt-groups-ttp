# Advanced Persistent Threat (APT) Groups TTPs Downloader (MITRE ATT&CK JSON file)

## Description
This script is designed to analyze and retrieve information about Advanced Persistent Threat (APT) groups and their Tactics, Techniques, and Procedures (TTPs). It provides various functionalities to interact with APT related data sources.


### Key Features
- Retrieve information about APT groups from different sources like MITRE ATT&CK framework and APT group tracker spreadsheets.
- Search for APT groups using specific keywords or group names.
- Download JSON files containing TTP data of specified APT groups.
- Update local data sources for APT group information and TTPs.

## Installation
Ensure you have Python version 3.x installed. To install necessary dependencies, use the provided `requirements.txt`:
```
pip install -r requirements.txt
```

## Usage

### Command-Line Arguments
- `-g`, `--groups`: Specifies the names of APT groups for which to download JSON files containing their TTPs. This can be a single group, e.g., -g/--groups "APT16", or multiple groups separated by commas, e.g., -g/--groups "APT16, FIN7".
- `-k`, `--keywords`: Specifies keywords for searching APT groups in 'enterprise-attack.json' and 'APT Groups and Operations.xlsx'. This can be a single keyword, e.g., -k/--keywords "financial", or multiple keywords separated by commas, e.g., -k/--keywords "financial, China".
- `-m`,`--mitre`,`--no-mitre`: A boolean argument. Defaults to True. When --no-mitre is specified (with -k/--keywords), the script will not search for groups in 'enterprise-attack.json'.
- `-t`,`--tracker`,`--no-tracker`: A boolean argument. Defaults to True. When --no-tracker is specified (with -k/--keywords), the script will not search for groups in 'APT Groups and Operations.xlsx'.
- `-u`,`--update`: A boolean argument. Defaults to False. When this argument is specified, the script performs an update (downloads) of 'enterprise-attack.json' and 'APT Groups and Operations.xlsx'.

### Calling the Help Menu
To see all available command-line options and get general information about the script, use the `-h` or `--help` argument:
```
python get_apt_groups_ttp.py -h

python get_apt_groups_ttp.py --help
```

### Using 
To run the script with Python, use the following command:
```
python get_apt_groups_ttp.py [-g GROUPS] [-k KEYWORDS] [-m | --mitre | --no-mitre] [-t | --tracker | --no-tracker] [-u]
```

Example usage:
- To search TTPs for specific APT groups:
```
python get_apt_groups_ttp.py -g "APT16"

python get_apt_groups_ttp.py -g "APT16,FIN7"
```
- To search for APT groups based on keywords:
```
python get_apt_groups_ttp.py -k "financial"

python get_apt_groups_ttp.py -k "financial,China"
```
- To search for groups in 'enterprise-attack.json' only:
```
python get_apt_groups_ttp.py -k "financial" --no-tracker
```
- To search for groups in 'APT Groups and Operations.xlsx' only:
```
python get_apt_groups_ttp.py -k "financial" --no-mitre
```
- To update files without searching:
```
python get_apt_groups_ttp.py -u
```

## License
This project is licensed under the GNU General Public License (GPL).
