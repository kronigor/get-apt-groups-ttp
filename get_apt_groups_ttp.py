import argparse
import os
import pandas as pd
import requests
import sys
import wget
import json


def parse_arguments():
    """
    The `parse_arguments` function is used to parse command line arguments for a script that analyzes
    and retrieves information about APT groups and their TTPs.
    :return: The function `parse_arguments` returns the parsed command-line arguments as an
    `argparse.Namespace` object.

    Arguments:
    -g/--groups: Specifies the names of APT groups for which to download JSON files containing their TTPs.
                 This can be a single group, e.g., --groups "APT16",
                 or multiple groups separated by commas, e.g., --groups "APT16, FIN7".

    -k/--keywords: Specifies keywords for searching APT groups in 'enterprise-attack.json' and
                   'APT Groups and Operations.xlsx'. This can be a single keyword, e.g., --keywords "financial",
                   or multiple keywords separated by commas, e.g., --keywords "financial, China".

    -m/--mitre/--no-mitre: A boolean argument. Defaults to True. When --no-mitre is specified (with -k/--keywords),
                           the script will not search for groups in 'enterprise-attack.json'.

    -t/--tracker/--no-tracker: A boolean argument. Defaults to True. When --no-tracker is specified
                               (with -k/--keywords), the script will not search for groups in
                               'APT Groups and Operations.xlsx'.

    -u/--update: A boolean argument. Defaults to False. When this argument is specified, the script performs an
                 update (downloads) of 'enterprise-attack.json' and 'APT Groups and Operations.xlsx'.

    Usage Examples:
    - To search for specific APT groups:
        python get_apt_groups_ttp.py -g APT16
        python get_apt_groups_ttp.py -g "APT16, FIN7"
    - To search for APT groups based on keywords:
        python get_apt_groups_ttp.py -k financial
        python get_apt_groups_ttp.py -k "financial, China"
    - To search for groups in 'enterprise-attack.json' only:
        python get_apt_groups_ttp.py -k "financial" --no-tracker
    - To search for groups in 'APT Groups and Operations.xlsx' only:
        python get_apt_groups_ttp.py -k "financial" --no-mitre
    - To update files without searching:
        python get_apt_groups_ttp.py -u
    """
    parser = argparse.ArgumentParser(description='Script for analyzing and retrieving information about APT groups '
                                                 'and their TTPs (json from MITRE).')
    parser.add_argument('-g', '--groups', type=lambda x: [str.strip(i) for i in x.split(',')],
                        help='Specify APT group names to download JSON files (from MITRE) containing their TTPs. Can '
                             'be a single or multiple groups separated by commas (example: -g "APT16, FIN7").')
    parser.add_argument('-k', '--keywords', type=lambda x: [str.strip(i) for i in x.split(',')],
                        help="Specify keywords to search for APT groups in 'enterprise-attack.json' and 'APT Groups "
                             "and Operations.xlsx'. Can be a single or multiple keywords separated by commas "
                             "(example: -k 'financial, China').")
    parser.add_argument('-m', '--mitre', action=argparse.BooleanOptionalAction, default=True,
                        help='If set to False (--no-mitre) with -k/--keywords, do not search in '
                             'enterprise-attack.json (example: -k "financial" --no-mitre)')
    parser.add_argument('-t', '--tracker', action=argparse.BooleanOptionalAction, default=True,
                        help="If set to False (--no-tracker) with -k/--keywords, do not search in "
                             "'APT Groups and Operations.xlsx' (example: -k 'financial' --no-tracker)")
    parser.add_argument('-u', '--update', action='store_true', default=False,
                        help="If set, update (download) 'enterprise-attack.json' and 'APT Groups and Operations.xlsx'.")
    arguments = parser.parse_args()
    if len(sys.argv) > 1:
        if not arguments.groups and not arguments.keywords and not arguments.update:
            parser.error('one of the arguments -g/--groups -k/--keywords -u/--update is required ')
        elif arguments.groups and arguments.keywords:
            parser.error('argument -k/--keywords: not allowed with argument -g/--groups')
    return arguments


def print_menu():
    """
    The `print_menu()` function prints a menu with numbered options.
    """
    light_blue = '\033[94m'
    end_color = '\033[0m'
    menu_options = {
        1: 'Get APT Groups from MITRE ATT&CK',
        2: 'Get APT Groups from APT Tracker',
        3: 'Download TTPs of APT Groups from MITRE ATT&CK (JSON)',
        4: 'Update APT Tracker Spreadsheet',
        5: 'Update MITRE ATT&CK Enterprise Matrix',
        0: 'Exit'
    }
    for key, value in menu_options.items():
        print(f"{light_blue}[{key}]{end_color} {value}")


def bar_progress(current, total, width=80):
    """
    The function `bar_progress` displays the progress of a task as a percentage.
    
    :param current: The current progress value. It represents the current progress of a task or
    operation
    :param total: The total parameter represents the total number of steps or iterations in the process
    you are tracking the progress of
    :param width: The `width` parameter is an optional parameter that specifies the width of the
    progress bar. By default, it is set to 80 characters, defaults to 80 (optional)
    """
    progress_message = "Progress: %d%%" % (current / total * 100)
    sys.stdout.write("\r" + progress_message)
    sys.stdout.flush()


def update_apt_groups(apt_filename: str):
    """
    The function `update_apt_groups` downloads a file from a Google Drive URL and saves it with the
    specified filename, removing any existing file with the same name.
    
    :param apt_filename: The `apt_filename` parameter is a string that represents the name of the file
    that will be downloaded from Google Drive
    :type apt_filename: str
    :return: nothing.
    """
    try:
        url = 'https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pub?output=xlsx'
        if os.path.exists(apt_filename):
            os.remove(apt_filename)
        print(f"Downloading '{apt_filename}' file from Google Drive:")
        wget.download(url, apt_filename, bar=bar_progress)
        print()
        return
    except Exception as e:
        print(e)


def update_matrix(matrix_filename: str):
    """
    The function `update_matrix` downloads a file from a specified URL and saves it with a given
    filename, removing any existing file with the same name.
    
    :param matrix_filename: The `matrix_filename` parameter is a string that represents the name of the
    file where the matrix will be saved
    :type matrix_filename: str
    :return: nothing.
    """
    try:
        url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        if os.path.exists(matrix_filename):
            os.remove(matrix_filename)
        print(f"Downloading '{matrix_filename}' file from MITRE GitHub:")
        wget.download(url, matrix_filename, bar=bar_progress)
        print()
        return
    except Exception as e:
        print(e)


def search_groups_from_mitre(groups: list, keywords: list):
    """
    The function `search_groups_from_mitre` searches for APT groups in an JSON file (enterprise-attack.json)
    based on keywords in the description field and exports the results to an Excel file.
    
    :param groups: The `groups` parameter is a list of dictionaries, where each dictionary represents an
    APT group. Each dictionary should have the following keys: 'name', 'aliases', and 'description'
    :type groups: list
    :param keywords: A list of keywords to search for in the Description field of the APT groups
    :type keywords: list
    :return: The function does not return any value.
    """
    try:
        print('[MITRE]: Searching by keyword(s) in the Description field...')
        result = []
        for word in keywords:
            filtered_groups = list(filter(lambda x: word.lower() in x['description'].lower(), groups))
            if filtered_groups:
                result.extend(filtered_groups)
        if result:
            df = pd.DataFrame(result)[['name', 'aliases', 'description']]
            df['aliases'] = df['aliases'].str.join(', ')
            df.sort_values(by='name')
            with pd.ExcelWriter('APT Groups list from MITRE.xlsx', engine='xlsxwriter') as file:
                df.to_excel(file, sheet_name='APT Groups', index=False)
                workbook = file.book
                format_border = workbook.add_format({'border': 1})
                format_wrap = workbook.add_format({'valign': 'top', 'text_wrap': True})
                worksheet = file.sheets['APT Groups']
                worksheet.autofilter(f"A1:C{str(df.shape[0])}")
                worksheet.conditional_format(f"A1:C{str(df.shape[0] + 1)}",
                                             {'type': 'no_blanks', 'format': format_border})
                worksheet.set_column('A:A', 15, format_wrap)
                worksheet.set_column('B:B', 80, format_wrap)
                worksheet.set_column('C:C', 150, format_wrap)
            print('[MITRE]: Found!')
        else:
            print('[MITRE]: APT Groups not found.')
        return
    except Exception as e:
        print(e)


def search_groups_from_tracker(filename: str, keywords: list):
    """
    The function `search_groups_from_tracker` searches for APT groups in an Excel file (APT Groups and Operations.xlsx)
    based on keywords in "Targets" and "Comment" fields and saves the results in a new Excel file.
    
    :param filename: The filename parameter is a string that represents the name or path of the Excel
    file that contains the data to be searched
    :type filename: str
    :param keywords: The `keywords` parameter is a list of strings that represent the keywords you want
    to search for in the "Targets" and "Comment" fields of the APT Tracker data. These keywords will be
    used to filter the data and find the relevant APT groups
    :type keywords: list
    :return: The function does not return any value.
    """
    try:
        print('[APT Tracker]: Searching by keyword(s) in "Targets" and "Comment" fields...')
        df_name = pd.ExcelFile(filename)
        result = pd.DataFrame()
        for sheet in df_name.sheet_names[1:10]:
            df_sheet = pd.read_excel(filename, sheet_name=sheet, skiprows=1)
            data = df_sheet[['Common Name', 'Toolset / Malware', 'Targets', 'Comment']]
            df_search = pd.DataFrame()
            for word in keywords:
                df_search = pd.concat(
                    [df_search,
                     data[data['Targets'].str.contains(word, case=False) | data['Comment'].str.contains(word,
                                                                                                        case=False)]])
            result = pd.concat([result, df_search])
        if not result.empty:
            result = result.sort_values(by='Common Name')
            result = result.fillna('-')
            with pd.ExcelWriter('APT Groups list from APT Tracker.xlsx', engine='xlsxwriter') as file:
                result.to_excel(file, sheet_name='APT Groups', index=False)
                workbook = file.book
                format_border = workbook.add_format({'border': 1})
                format_wrap = workbook.add_format({'valign': 'top', 'text_wrap': True})
                worksheet = file.sheets['APT Groups']
                worksheet.autofilter(f"A1:D{str(result.shape[0])}")
                worksheet.conditional_format(f"A1:D{str(result.shape[0] + 1)}",
                                             {'type': 'no_blanks', 'format': format_border})
                worksheet.set_column('A:A', 40, format_wrap)
                worksheet.set_column('B:D', 70, format_wrap)
            print('[APT Tracker]: Found!')
        else:
            print('[APT Tracker]: APT Groups not found.')
        return
    except Exception as e:
        print(e)


def get_groups_ttps_from_mitre(groups: list, apt_aliases: list):
    """
    The function `get_groups_ttps_from_mitre` searches for APT groups in a given list and downloads JSON
    files containing information about the groups from the MITRE ATT&CK website.
    
    :param groups: The `groups` parameter is a list of dictionaries that represent APT groups. Each
    dictionary contains information about an APT group, such as its name, aliases, and external
    references
    :type groups: list
    :param apt_aliases: The `apt_aliases` parameter is a list of strings representing the aliases or
    names of APT (Advanced Persistent Threat) groups. These aliases are used to search for corresponding
    APT groups in the `groups` list
    :type apt_aliases: list
    :return: The function does not explicitly return anything.
    """
    try:
        for apt_alias in apt_aliases:
            print(f"[MITRE]: Searching APT group '{apt_alias}'...")
            apt_group = list(filter(lambda x: apt_alias.lower() in [str.lower(i) for i in x['aliases']], groups))
            if apt_group:
                group_link = apt_group[0]['external_references'][0]['url']
                group_id = apt_group[0]['external_references'][0]['external_id']
                json_name = f"{group_id}-enterprise-layer.json"
                url = f"{group_link}/{json_name}"
                req = requests.get(url)
                with open(f'jsons/{json_name}', 'wb') as file:
                    file.write(req.content)
                print('[MITRE]: Found! JSON files have been downloaded to the ./jsons/ directory.')
            else:
                print(f"[MITRE]: Group '{apt_alias}' not found")
        return
    except Exception as e:
        print(e)


def get_all_groups_from_mitre(filename: str):
    """
    The function `get_all_groups_from_mitre` reads a JSON file (enterprise-attack.json), filters out intrusion-set objects that
    are deprecated or revoked, and returns a list of the remaining groups.
    
    :param filename: The `filename` parameter is a string that represents the name or path of the file
    from which the data will be read
    :type filename: str
    :return: a list of groups that meet certain criteria.
    """
    try:
        with open(filename, encoding='utf-8') as f:
            data = json.load(f)
        groups = list(filter(lambda x: x['type'] == 'intrusion-set' and not (
                ("x_mitre_deprecated" in x and x["x_mitre_deprecated"]) or ("revoked" in x and x["revoked"])),
                             data['objects']))
        return groups
    except Exception as e:
        print(e)


def main(arguments):
    """
    The main function is a Python script that performs various operations related to APT groups and
    operations, including updating files, searching for keywords, and retrieving TTPs for specific APT
    groups.
    
    :param arguments: The `arguments` parameter is a dictionary that contains the command line arguments
    passed to the script
    :return: the string 'Bye!'
    """
    try:
        if not os.path.exists('jsons'):
            os.mkdir('jsons')
        files = {
            'tracker': ('APT Groups and Operations.xlsx', update_apt_groups),
            'mitre': ('enterprise-attack.json', update_matrix)
        }
        for key in files:
            if not os.path.isfile(files[key][0]) or arguments.update:
                files[key][1](files[key][0])
        if len(sys.argv) == 1:
            choice = ''
            while choice not in (1, 2, 3, 4, 5, 0):
                print_menu()
                try:
                    choice = int(input('\nEnter your choice: '))
                except:
                    print('Wrong input. Please enter a number ...')
            if choice in (1, 2, 3):
                groups = get_all_groups_from_mitre(files['mitre'][0])
                if choice == 1:
                    keywords = input('Enter keywords to search: ').split(',')
                    search_groups_from_mitre(groups, [str.strip(i) for i in keywords])
                elif choice == 2:
                    keywords = input('Enter keywords to search: ').split(',')
                    search_groups_from_tracker(files['tracker'][0], [str.strip(i) for i in keywords])
                elif choice == 3:
                    apt_groups = input('Enter APT groups: ').split(',')
                    get_groups_ttps_from_mitre(groups, [str.strip(i) for i in apt_groups])
            elif choice == 4:
                update_apt_groups(files['tracker'][0])
            elif choice == 5:
                update_matrix(files['mitre'][0])
            elif choice == 0:
                return 'Bye!'
            else:
                print('Wrong input. Please enter a number ...')
        else:
            groups = get_all_groups_from_mitre(files['mitre'][0])
            if args.keywords:
                if args.mitre:
                    search_groups_from_mitre(groups, args.keywords)
                if args.tracker:
                    search_groups_from_tracker(files['tracker'][0], args.keywords)
            elif args.groups:
                get_groups_ttps_from_mitre(groups, args.groups)
        return 'Bye!'
    except Exception as e:
        print(e)


if __name__ == "__main__":
    try:
        args = parse_arguments()
        print(main(args))
    except Exception as e:
        print(e)
