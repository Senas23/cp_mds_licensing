#!/usr/bin/python3
import json, sys, fnmatch, getpass
# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs
from enum import Enum

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

def cp_api_call(api_call, api_call_parameters) -> dict:
    # getting details from the user
    api_server = input("Enter server IPv4 address/hostname/FQDN: ")
    username = input("Enter username: ")
    if sys.stdin.isatty():
        password = getpass.getpass("Enter password: ")
    else:
        print("Attention! Your password will be shown on the screen!")
        password = input("Enter password: ")

    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:
        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        #client.debug_file = "api_calls.json"

        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print(f"{bcolors.FAIL}Could not get the server's fingerprint - Check connectivity with the server.{bcolors.ENDC}")
            exit(1)

        # login to server:
        login_res = client.login(username, password)

        if login_res.success is False:
          #print("Login failed:\n{}".format(login_res.error_message))
          print(f"{bcolors.FAIL}[-] API login failed:\n{login_res.error_message}{bcolors.ENDC}")
          exit(1)
        else:
          print(f"{bcolors.OKGREEN}[+] API login successful{bcolors.ENDC}")

        # Execute the API call and loop over all results pages
        print(f"{bcolors.OKGREEN}[+] API call execution in progress, patience grasshopper ...{bcolors.ENDC}")
        total = -1
        dict_res = {}
        offset = api_call_parameters['offset']
        while total != offset:
          api_call_parameters['offset'] = offset
          tmp_res = client.api_call(api_call, api_call_parameters)
          if tmp_res.success is False:
              print(f"{bcolors.FAIL}[-] Failed to get the anwer:\n{tmp_res.error_message}{bcolors.ENDC}")
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
    if 'management-blades' in key and 'network-policy-management' in key['management-blades']:
      dict_results[obj_domain_name]['OnMDSPrimary'] = True
      dict_results[obj_domain_name]['OnMDSStandby'] = True if 'secondary' in key['management-blades'] else False
    # Go over all GWs and add to the dict
    if 'network-security-blades' in key:
      obj_gw_blades = key['network-security-blades']
      if "firewall" in obj_gw_blades and obj_gw_blades['firewall'] == True:
        cluster_members = key['cluster-member-names'] if 'cluster-member-names' in key else []
        # Go over VS GW
        if obj_type == cp_host.vs.value:
          if len(fnmatch.filter(cluster_members, '*_' + obj_name)) > 0:
            dict_results[obj_domain_name]['VS']['Members'] += fnmatch.filter(cluster_members, '*_' + obj_name)
            dict_results[obj_domain_name]['VS']['Count'] += len(cluster_members)
            dict_results[obj_domain_name]['CountTotal'] += len(cluster_members)
        # Go over HA GW Cluster
        elif obj_type == cp_host.ha.value:
          dict_results[obj_domain_name]['HA']['Members'] += cluster_members
          dict_results[obj_domain_name]['HA']['Count'] += len(cluster_members)
          dict_results[obj_domain_name]['CountTotal'] += len(cluster_members)
        # Go over Single GW
        elif obj_type == cp_host.single.value:
          dict_results[obj_domain_name]['GW']['Members'] += [obj_name]
          dict_results[obj_domain_name]['GW']['Count'] += 1
          dict_results[obj_domain_name]['CountTotal'] += 1
      
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
    mds_stand_total += value['CountTotal'] if value['OnMDSStandby'] == True else 0
  print(f"{bcolors.BOLD}{bcolors.OKGREEN}Primary MDS Total GWs: {mds_prim_total}\tStandby MDS Total GWs: {mds_stand_total}{bcolors.ENDC}")

def main():
  file_path = sys.argv[1] if len(sys.argv) == 2 else ""
  tmp_dict = {}
  if file_path == "":
    parameters = {"limit": 500, "offset": 0, "details-level": "full"}
    tmp_dict = cp_api_call('show-gateways-and-servers', parameters)
  else:
    with open(file_path, 'r') as f:
      tmp_dict = json.load(f)
  process_licensing(tmp_dict)

if __name__ == "__main__":
  main()
