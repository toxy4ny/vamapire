import requests
import re
import argparse
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

def print_logo():
    logo = r"""
                          _____  ___    _             
                         (  _  )(  _`\ (_)            
 _   _    _ _   ___ ___  | (_) || |_) )| | _ __   __  
( ) ( ) /'_` )/' _ ` _ `\|  _  || ,__/'| |( '__)/'__`\
| \_/ |( (_| || ( ) ( ) || | | || |    | || |  (  ___/
`\___/'`\__,_)(_) (_) (_)(_) (_)(_)    (_)(_)  `\____)
                                                      
               by KL3FT3Z (https://github.com/toxy4ny)                                  
 ##
 ###  
  ####
   #####
   #######
    #######
    ########
    ########
    #########
    ##########
   ############
 ##############
################
 ################
   ##############
    ##############                                              ####
    ##############                                           #####
     ##############                                      #######
     ##############                                 ###########
     ###############                              #############
     ################                           ##############
    #################      #                  ################
    ##################     ##    #           #################
   ####################   ###   ##          #################
        ################  ########          #################
         ################  #######         ###################
           #######################       #####################
            #####################       ###################
              ############################################
               ###########################################
               ##########################################
                ########################################
                ########################################
                 ######################################
                 ######################################
                  ##########################      #####
                  ###  ###################           ##
                  ##    ###############
                  #     ##  ##########
                            ##    ###
                                  ###
                                  ##
                                  #       

This prog checking REST API-endpoints on Server for finds Secrets.           

    """
    print(logo)

class TLSAdapter(HTTPAdapter):
    def __init__(self, minimum_tls_version=None, **kwargs):
        self.minimum_tls_version = minimum_tls_version
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        context = create_urllib3_context()
        if self.minimum_tls_version:
            context.minimum_version = self.minimum_tls_version
        pool_kwargs['ssl_context'] = context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

def fetch_data_from_endpoint(session, url, headers=None):
    response = session.get(url, headers=headers)
    response.raise_for_status()
    return response.text

def find_secrets(data):
    secret_patterns = {
        "AWS key": r'AKIA[0-9A-Z]{16}', 
        "JWT key": r'eyJ[a-zA-Z0-9-_=]+\.eyJ[a-zA-Z0-9-_=]+\.?[a-zA-Z0-9-_.+/=]*', 
        "Bearer token": r'Bearer\s[0-9a-zA-Z\-_\.]+',
        "Basic Auth": r'Basic\s[0-9a-zA-Z\=]+',  
        "OAuth token": r'oauth_[\da-f]+',
        "API key": r'[A-Za-z0-9]{32}', 
        "Password": r'(?i)(password|passwd|pass):\s*.*',
        "How to connect": r'jdbc:[\w:]+//[^\s]+',
        "Login": r'(?i)(login|username|user):\s*.*',
        "Net Hosts": r'[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z]{2,6}', 
    }

    secrets = {}
    for pattern_name, pattern in secret_patterns.items():
        matches = re.findall(pattern, data)
        if matches:
            secrets[pattern_name] = matches
    return secrets

def get_auth_token_with_credentials(base_url, session, username, password):
    auth_url = f"{base_url.rstrip('/')}/login"
    try:
        response = session.post(auth_url, data={"username": username, "password": password})
        response.raise_for_status()
        return response.json().get('access_token')
    except requests.RequestException as e:
        print(f"No catch accsess token: {e}")
        return None

def scan_endpoints(base_url, endpoints, session, token):
    headers = {"Authorization": f"Bearer {token}"}
    results = {}
    for endpoint in endpoints:
        full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        try:
            data = fetch_data_from_endpoint(session, full_url, headers)
            secrets = find_secrets(data)
            if secrets:
                results[full_url] = secrets
        except requests.RequestException as e:
            results[full_url] = f"Bug in requests: {e}"
    return results

def load_endpoints_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            endpoints = [line.strip() for line in file if line.strip()]
        return endpoints
    except IOError as e:
        print(f"Bug in File reading: {e}")
        return []

def main():
    print_logo()  # Вывод логотипа в начале программы

    parser = argparse.ArgumentParser(description="Checking Endpoints and find Secrets.")
    parser.add_argument('--base-url', '-b', required=True, help='URL to API API (http / https)')
    parser.add_argument('--file', '-f', required=True, help='File whit Endpoints')
    parser.add_argument('--username', '-u', help='Name')
    parser.add_argument('--password', '-p', help='Password')
    parser.add_argument('--token', '-t', help='Bearer token for Access')
    args = parser.parse_args()

    if not args.token and (not args.username or not args.password):
        print("Enter token or login/password.")
        return

    endpoints = load_endpoints_from_file(args.file)

    if not endpoints:
        print("No Endpoints for checking.")
        return

    session = requests.Session()

    if args.base_url.startswith('https://'):
        session.mount('https://', TLSAdapter(minimum_tls_version=ssl.TLSVersion.TLSv1_2))
    else:
        session.mount('http://', HTTPAdapter())

    token = args.token
    if not token:
        token = get_auth_token_with_credentials(args.base_url, session, args.username, args.password)
        if not token:
            print("Token for Access not catch:(.")
            return

    results = scan_endpoints(args.base_url, endpoints, session, token)
    secrets_found = False
    for endpoint, result in results.items():
        print(f"Endpoint: {endpoint}")
        if isinstance(result, dict):
            print("Found Secrets:")
            secrets_found = True
            for pattern_name, matches in result.items():
                print(f"  {pattern_name}:")
                for match in matches:
                    print(f"    Found {match}")
        else:
            print(result)
    
    if not secrets_found:
        print("No found Secrets in Endpoints :(.")
            
if __name__ == "__main__":
    main()
