#!/usr/bin/python3
import fnmatch
import getpass
import json
import sys
import threading
import time
from enum import Enum

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs


class cp_host(Enum):
    vs = 'CpmiVsClusterNetobj'
    vsx = 'CpmiVsxClusterNetobj'
    ha = 'CpmiGatewayCluster'
    single = 'simple-gateway'
    mgmt = 'checkpoint-host'


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/-\\':
                yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False
        time.sleep(self.delay)
        if exception is not None:
            return False

cp_version = {'1.7': 'R81', '1.6.1': 'R80.40 JHF Take 78', '1.6': 'R80.40', '1.5': 'R80.30', \
  '1.4': 'R80.20.M2', '1.3': 'R80.20', '1.2': 'R80.20.M1', '1.1': 'R80.10', '1': 'R80'}


def cp_api_call(api_call, api_call_parameters, session_ro=False) -> dict:
    # getting details from the user
    api_server = input("Enter server IPv4 address/hostname/FQDN: ")
    username = input(
        "Enter username or press <Enter> for API-KEY (MDS/SMS R80.40+): ")
    api_key = ""
    password = ""
    if sys.stdin.isatty():
        if username != "":
            password = getpass.getpass("Enter password: ")
        else:
            api_key = getpass.getpass("Paste your API Key: ")
    else:
        print(
            f"{bcolors.WARNING}***Attention*** Your input will be shown on the screen!{bcolors.ENDC}"
        )
        if username != "":
            password = input("Enter password: ")
        else:
            api_key = input("Paste your API Key: ")

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:
        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        #client.debug_file = "api_calls.json"

        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print(
                f"{bcolors.FAIL}Could not get the server's fingerprint - Check connectivity with the server.{bcolors.ENDC}"
            )
            exit(1)

        # login to server:
        if api_key == "":
            login_res = client.login(username, password, read_only=session_ro)
        else:
            login_res = client.login_with_api_key(api_key,
                                                  read_only=session_ro)

        if login_res.success is False:
            print(
                f"{bcolors.FAIL}[-] API login failed:\n{login_res.error_message}{bcolors.ENDC}"
            )
            exit(1)
        else:
            print(f"{bcolors.OKGREEN}[+] API login successful")
            cp_api_version = login_res.data['api-server-version']
            print(f"  \_API Version: {cp_api_version}{bcolors.ENDC}")
            if cp_api_version in cp_version:
                print(
                    f"{bcolors.OKGREEN}  \_Version: {cp_version[cp_api_version]}{bcolors.ENDC}"
                )

        # Execute the API call and loop over all results pages
        print(
            f"{bcolors.OKGREEN}[+] API call execution in progress, patience grasshopper ..."
        )
        total = -1
        dict_res = {}
        offset = api_call_parameters['offset']
        with Spinner():
            while total != offset:
                api_call_parameters['offset'] = offset
                tmp_res = client.api_call(api_call, api_call_parameters)
                if tmp_res.success is False:
                    print(
                        f"{bcolors.FAIL}[-] Failed to get the anwer:\n{tmp_res.error_message}{bcolors.ENDC}"
                    )
                    exit(1)
                if total == -1:
                    dict_res = tmp_res.data
                else:
                    for key, value in dict_res.items():
                        if key == 'objects':
                            value.extend(tmp_res.data[key])
                        else:
                            value = tmp_res.data[key]
                offset = tmp_res.data['to']
                total = tmp_res.data['total']
    return dict_res


def process_licensing(tmp_dict):
    data_raw = tmp_dict
    dict_results = {}
    try:
        for key in data_raw['objects']:
            obj_domain_name = key['domain']['name']
            obj_type = key['type']
            obj_name = key['name']
            # Instantiate dicts for Domain, MDS, VS, HA, and Single GW
            if obj_domain_name not in dict_results:
                dict_results[obj_domain_name] = {}
                for mds in ['OnMDSPrimary', 'OnMDSStandby']:
                    dict_results[obj_domain_name][mds] = False
                dict_results[obj_domain_name]['CountTotal'] = 0
                for gw in ['VS', 'HA', 'GW']:
                    dict_results[obj_domain_name][gw] = {}
                    dict_results[obj_domain_name][gw]['Members'] = []
                    dict_results[obj_domain_name][gw]['Count'] = 0
            # Mark CMA availability for Primary and Standby MDS
            if 'management-blades' in key and 'network-policy-management' in key[
                    'management-blades']:
                dict_results[obj_domain_name]['OnMDSPrimary'] = True
                dict_results[obj_domain_name][
                    'OnMDSStandby'] = True if 'secondary' in key[
                        'management-blades'] else False
            # Go over all GWs and add to the dict
            if 'network-security-blades' in key:
                obj_gw_blades = key['network-security-blades']
                if "firewall" in obj_gw_blades and obj_gw_blades[
                        'firewall'] == True:
                    cluster_members = key['cluster-member-names'] if 'cluster-member-names' in key else []
                    # Go over VS GW
                    if obj_type == cp_host.vs.value:
                        if len(fnmatch.filter(cluster_members,
                                              '*_' + obj_name)) > 0:
                            dict_results[obj_domain_name]['VS'][
                                'Members'] += cluster_members
                            dict_results[obj_domain_name]['VS'][
                                'Count'] += len(cluster_members)
                            dict_results[obj_domain_name]['CountTotal'] += len(
                                cluster_members)
                    # Go over HA GW Cluster
                    elif obj_type == cp_host.ha.value:
                        dict_results[obj_domain_name]['HA'][
                            'Members'] += cluster_members
                        dict_results[obj_domain_name]['HA']['Count'] += len(
                            cluster_members)
                        dict_results[obj_domain_name]['CountTotal'] += len(
                            cluster_members)
                    # Go over Single GW
                    elif obj_type == cp_host.single.value:
                        dict_results[obj_domain_name]['GW']['Members'] += [
                            obj_name
                        ]
                        dict_results[obj_domain_name]['GW']['Count'] += 1
                        dict_results[obj_domain_name]['CountTotal'] += 1
    except Exception as e:
        print(
            f"{bcolors.FAIL}[-] Function: process_licensing - Failed parsing JSON file\n  \_{e}{bcolors.ENDC}"
        )
        exit(1)
    # Instantiate totals
    mds_prim_total = 0
    mds_stand_total = 0
    print(f"{bcolors.OKGREEN}[+] Summary output:\n{bcolors.ENDC}")
    for key, value in sorted(dict_results.items()):
        print(f"{bcolors.HEADER}{bcolors.BOLD}Domain: {key}{bcolors.ENDC}\n\
  {bcolors.OKCYAN}SingleGW: {value['GW']['Count']}\t ClusterXL: {value['HA']['Count']}\tVS: {value['VS']['Count']}\t\
  StandbyMDS: {value['OnMDSStandby']}{bcolors.ENDC}\n\
  {bcolors.OKGREEN}TotalCount: {value['CountTotal']}{bcolors.ENDC}")
        mds_prim_total += value['CountTotal']
        mds_stand_total += value['CountTotal'] if value[
            'OnMDSStandby'] == True else 0
    print(
        f"{bcolors.BOLD}{bcolors.OKGREEN}Primary MDS Total GWs: {mds_prim_total}\tStandby MDS Total GWs: {mds_stand_total}{bcolors.ENDC}"
    )


def banner():
    tmp = """
  _   _  ____ ____  __  __   _     _                    _              
 | \ | |/ ___/ ___||  \/  | | |   (_) ___ ___ _ __  ___(_)_ __   __ _  
 |  \| | |  _\___ \| |\/| | | |   | |/ __/ _ \ '_ \/ __| | '_ \ / _` | 
 | |\  | |_| |___) | |  | | | |___| | (_|  __/ | | \__ \ | | | | (_| | 
 |_| \_|\____|____/|_|  |_| |_____|_|\___\___|_| |_|___/_|_| |_|\__, | 
             ______        __   ____                 |___/  
            / ___\ \      / /  / ___|___  _   _ _ __ | |_   
           | |  _ \ \ /\ / /  | |   / _ \| | | | '_ \| __|  
           | |_| | \ V  V /   | |__| (_) | |_| | | | | |_   
            \____|  \_/\_/     \____\___/ \__,_|_| |_|\__|  
                                                                       
  By: The Machine
  """
    print(tmp)


def main():
    banner()
    file_path = sys.argv[1] if len(sys.argv) == 2 else ""
    tmp_dict = {}
    if file_path == "":
        parameters = {"limit": 500, "offset": 0, "details-level": "full"}
        tmp_dict = cp_api_call('show-gateways-and-servers', parameters, True)
    else:
        try:
            with open(file_path, 'r') as f:
                tmp_dict = json.load(f)
        except OSError as e:
            print(
                f"{bcolors.FAIL}[-] Error reading file {file_path}\n{e}{bcolors.ENDC}"
            )
            exit(1)
        except ValueError as e:
            print(
                f"{bcolors.FAIL}[-] Failed parsing JSON input file\n{e}{bcolors.ENDC}"
            )
            exit(1)
    process_licensing(tmp_dict)


if __name__ == "__main__":
    main()
