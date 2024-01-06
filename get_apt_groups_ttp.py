import argparse
import os
import pandas as pd
import requests
import sys
import wget

from mitreattack.stix20 import MitreAttackData


def parse_arguments():
    """ Parse command line arguments.

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
    """ Displays a console menu with options for different operations. """
    menu_options = {
        1: 'Get APT groups from MITRE',
        2: 'Get APT groups from APT Tracker .xlsx',
        3: 'Get APT groups TTPs from MITRE',
        4: 'Update APT Tracker .xlsx',
        5: 'Update MITRE Enterprise Matrix .json',
        0: 'Exit'
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")


def bar_progress(current, total, width=80):
    """ Updates and displays a progress bar for the wget download process. """
    progress_message = "Progress: %d%%" % (current / total * 100)
    sys.stdout.write("\r" + progress_message)
    sys.stdout.flush()


def update_apt_groups(apt_filename: str):
    """ Update 'APT Groups and Operations.xlsx' file from Google Drive. """
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
    """ Update 'enterprise-attack.json' file from MITRE GitHub. """
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


def get_groups_from_mitre(filename: str, keywords: list):
    """ Searches for APT groups in the 'enterprise-attack.json' file based on user-entered keywords. """
    try:
        print('[MITRE]: Searching by keyword(s) in the Description field...')
        mitre_attack_data = MitreAttackData(filename)
        groups = mitre_attack_data.get_groups()
        result = []
        for group in groups:
            if 'description' in group.keys():
                for word in keywords:
                    if word.lower() in group.description.lower():
                        result.append(dict(group))
        if result:
            df = pd.DataFrame(result)
            df['created'] = df['created'].dt.tz_localize(None)
            df['modified'] = df['modified'].dt.tz_localize(None)
            df.iloc[:, 5:10].to_excel('APT Groups list from MITRE.xlsx', sheet_name='APT Groups', index=False)
            print('[MITRE]: Found!')
        else:
            print('[MITRE]: APT Groups not found.')
    except Exception as e:
        print(e)


def get_groups_from_tracker(filename: str, keywords: list):
    """ Searches for APT groups in the 'APT Groups and Operations.xlsx' file based on user-entered keywords. """
    try:
        print('[APT Tracker]: Searching by keyword(s) in the Description field...')
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
            result.to_excel("APT Groups list from APT Tracker.xlsx", sheet_name='APT Groups', index=False)
            print('[APT Tracker]: Found!')
        else:
            print('[APT Tracker]: APT Groups not found.')
        return
    except Exception as e:
        print(e)


def get_groups_ttps_from_mitre(filename: str, apt_groups: list):
    """ Downloads TTP information of specified APT groups (json file) from the MITRE website. """
    try:
        mitre_attack_data = MitreAttackData(filename)
        for apt in apt_groups:
            print(f"[MITRE]: Searching APT group '{apt}'...")
            group = mitre_attack_data.get_groups_by_alias(apt)
            if group:
                group_link = group[0].external_references[0].url
                group_id = group[0].external_references[0].external_id
                json_name = f"{group_id}-enterprise-layer.json"
                url = f"{group_link}/{json_name}"
                req = requests.get(url)
                with open(f'jsons/{json_name}', 'wb') as file:
                    file.write(req.content)
                print('[MITRE]: Found!')
            else:
                print(f"[MITRE]: Group '{apt}' not found")
    except Exception as e:
        print(e)


def main(arguments):
    """ Interacts with the user to execute various functions based on user choices. """
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
                    choice = int(input('Enter your choice: '))
                except:
                    print('Wrong input. Please enter a number ...')

            if choice == 1:
                keywords = input('Enter keywords to search: ').split(',')
                get_groups_from_mitre(files['mitre'][0], [str.strip(i) for i in keywords])
            elif choice == 2:
                keywords = input('Enter keywords to search: ').split(',')
                get_groups_from_tracker(files['tracker'][0], [str.strip(i) for i in keywords])
            elif choice == 3:
                apt_groups = input('Enter APT groups: ').split(',')
                get_groups_ttps_from_mitre(files['mitre'][0], [str.strip(i) for i in apt_groups])
            elif choice == 4:
                update_apt_groups(files['tracker'][0])
            elif choice == 5:
                update_matrix(files['mitre'][0])
            elif choice == 0:
                return 'Bye!'
            else:
                print('Wrong input. Please enter a number ...')
        else:
            if args.keywords:
                if args.mitre:
                    get_groups_from_mitre(files['mitre'][0], args.keywords)
                if args.tracker:
                    get_groups_from_tracker(files['tracker'][0], args.keywords)
            elif args.groups:
                get_groups_ttps_from_mitre(files['mitre'][0], args.groups)
        return 'Done!'
    except Exception as e:
        print(e)


if __name__ == "__main__":
    try:
        args = parse_arguments()
        print(main(args))
    except Exception as e:
        print(e)
