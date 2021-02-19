#!/usr/bin/python3
import sys, getpass
# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs

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

def cp_api_login(domain=None) -> APIClient:
    # getting details from the user
    api_server = input("Enter server IPv4 address/hostname/FQDN: ")
    username = input("Enter username or press <Enter> for API-KEY: ")
    api_key = ""
    password = ""
    if sys.stdin.isatty():
        if username != "":
          password = getpass.getpass("Enter password: ")
        else:
          api_key = getpass.getpass("Paste your API Key: ") 
    else:
        print(f"{bcolors.WARNING}***Attention*** Your input will be shown on the screen!{bcolors.ENDC}")
        if username != "":
          password = input("Enter password: ")
        else:
          api_key = input("Paste your API Key: ") 

    client_args = APIClientArgs(server=api_server)

    client = APIClient(client_args)
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
    if api_key == "":
      login_res = client.login(username, password, domain=domain)
    else:
      login_res = client.login_with_api_key(api_key)
    if login_res.success is False:
      print(f"{bcolors.FAIL}[-] API login failed:\n{login_res.error_message}{bcolors.ENDC}")
      exit(1)
    else:
      print(f"{bcolors.OKGREEN}[+] API login successful{bcolors.ENDC}")
    
    return client

def cp_api_logout(client: APIClient) -> dict:
  # Execute the API call and loop over all results pages
  print(f"{bcolors.OKGREEN}[*] Session Logout{bcolors.ENDC}")
  tmp_res = client.api_call("logout")
  if tmp_res.success is False:
      print(f"{bcolors.FAIL}[-] Failed to get the anwer:\n{tmp_res.error_message}{bcolors.ENDC}")
      exit(1)

def cp_get_api_call(client: APIClient, api_call, api_call_parameters) -> dict:
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

def cp_set_api_call(client: APIClient, api_call, api_call_parameters) -> dict:
  # Execute the API call and loop over all results pages
  print(f"{bcolors.OKGREEN}[*] Set API call execution in progress{bcolors.ENDC}")
  tmp_res = client.api_call(api_call, api_call_parameters)
  if tmp_res.success is False:
      print(f"{bcolors.FAIL}[-] Failed to get the anwer:\n{tmp_res.error_message}{bcolors.ENDC}")
      exit(1)
  return tmp_res

def disconnect_sessions(client: APIClient, tmp_dict):
  print(f"[*] Domain: {client.domain}")
  for key in tmp_dict['objects']:
    if key['changes'] == 0 and key['locks'] == 0 and key['state'] == "open" and key['in-work'] == False:
      print(f" \_ UID: {key['uid']}\tUsername: {key['user-name']}\tIP: {key['ip-address']}")
      parameters = {"uid": key['uid']}
      tmp_res = cp_set_api_call(client,"discard", parameters)
      print(f" \_ Response: {tmp_res.data['message']}")

def main():
  client = cp_api_login()
  parameters = {"limit": 500, "offset": 0, "details-level": "full"}
  dict_domains = cp_get_api_call(client, "show-domains", parameters)
  cp_api_logout(client)
  for key in dict_domains['objects']:
    client = cp_api_login(key['name'])
    disconnect_sessions(client, cp_get_api_call(client, 'show-sessions', parameters))
    cp_api_logout(client)
  
if __name__ == "__main__":
  main()
