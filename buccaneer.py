import requests
from bs4 import BeautifulSoup
import re
import argparse
import os
from colorama import init, Fore, Style

def print_logo():
    logo = r"""
 ____                                                                  
/\  _`\                                                                
\ \ \L\ \  __  __    ___    ___     __      ___      __     __   _ __  
 \ \  _ <'/\ \/\ \  /'___\ /'___\ /'__`\  /' _ `\  /'__`\ /'__`\/\`'__\
  \ \ \L\ \ \ \_\ \/\ \__//\ \__//\ \L\.\_/\ \/\ \/\  __//\  __/\ \ \/ 
   \ \____/\ \____/\ \____\ \____\ \__/.\_\ \_\ \_\ \____\ \____\\ \_\ 
    \/___/  \/___/  \/____/\/____/\/__/\/_/\/_/\/_/\/____/\/____/ \/_/ 
                                             
                               By KL3FT3Z (https://githib.com/toxy4ny)
        
        
                 uuuuuuu
             uu$$$$$$$$$$$uu
          uu$$$$$$$$$$$$$$$$$uu
         u$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$     $$$     $$$$$$u
        $$$$       u$u       $$$$
        $$$u       u$u       u$$$
        $$$u      u$$$u      u$$$
          $$$$uu$$$   $$$uu$$$$
           $$$$$$$     $$$$$$$ 
            u$$$$$$$u$$$$$$$u
             u$"$"$"$"$"$"$u
  uuu        $$u$ $ $ $ $u$$       uuu
 u$$$$        $$$$$u$u$u$$$       u$$$$
  $$$$$uu       $$$$$$$$$     uu$$$$$$
u$$$$$$$$$$$uu    uuuuu    uuuu$$$$$$$$$$
  $$$$$$$$$$$$$$uuu   uu$$$$$$$$$$$$
              $$$$$$$$$$$uu
           uuuu $$$$$$$$$$uuu
  u$$$uuu$$$$$$$$$uu  $$$$$$$$$$$uuu$$$
  $$$$$$$$$$                $$$$$$$$$$$
   $$$$$$$                      $$$$$$
     $$$$                        $$$$                                                                    
                                                                       
This prog parsing JS-file on Server for finds Secrets.
                       
    """
    print(Style.BRIGHT + Fore.WHITE + logo + Style.RESET_ALL)

def fetch_html(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def extract_js_links(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script', src=True)
    return [script['src'] for script in scripts]

def fetch_js_file(js_url):
    response = requests.get(js_url)
    response.raise_for_status()
    return response.text

def find_secrets(js_content):
    secrets = {
        'JWT Tokens': [],
        'API Tokens': [],
        'AWS Access Key IDs': [],
        'AWS Secret Access Keys': [],
        'GitHub Tokens': [],
        'GitLab Tokens': [],
        'Slack Webhooks': [],
        'Google API Keys': [],
        'Firebase Secret Keys': [],
        'SSH Private Keys': [],
        'CircleCI Tokens': [],
        'Travis CI Tokens': [],
        'OAuth Access Tokens': [],
        'OAuth Refresh Tokens': []
    }
    
    jwt_pattern = r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    secrets['JWT Tokens'].extend(re.findall(jwt_pattern, js_content))

    api_token_pattern = r'[a-zA-Z0-9_-]{20,40}'
    secrets['API Tokens'].extend(re.findall(api_token_pattern, js_content))

    aws_access_key_id_pattern = r'AKIA[0-9A-Z]{16}'
    secrets['AWS Access Key IDs'].extend(re.findall(aws_access_key_id_pattern, js_content))

    aws_secret_access_key_pattern = r'([a-zA-Z0-9/+]{40})'
    secrets['AWS Secret Access Keys'].extend(re.findall(aws_secret_access_key_pattern, js_content))
    
    github_token_pattern = r'(ghp_[A-Za-z0-9]{36})'
    secrets['GitHub Tokens'].extend(re.findall(github_token_pattern, js_content))
    
    gitlab_token_pattern = r'(glpat-[A-Za-z0-9-]{20,})'
    secrets['GitLab Tokens'].extend(re.findall(gitlab_token_pattern, js_content))

    slack_webhook_pattern = r'https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+'
    secrets['Slack Webhooks'].extend(re.findall(slack_webhook_pattern, js_content))

    google_api_key_pattern = r'AIza[0-9A-Za-z-_]{35}'
    secrets['Google API Keys'].extend(re.findall(google_api_key_pattern, js_content))

    firebase_secret_pattern = r'[A-Za-z0-9:_-]{40,}'
    secrets['Firebase Secret Keys'].extend(re.findall(firebase_secret_pattern, js_content))

    ssh_private_key_pattern = r'-----BEGIN [A-Z]+ PRIVATE KEY-----\n(?:[A-Za-z0-9+/=\n]+)-----END [A-Z]+ PRIVATE KEY-----'
    secrets['SSH Private Keys'].extend(re.findall(ssh_private_key_pattern, js_content))

    circleci_token_pattern = r'[0-9a-f]{40}'
    secrets['CircleCI Tokens'].extend(re.findall(circleci_token_pattern, js_content))

    travis_ci_token_pattern = r'[a-f0-9]{40}'
    secrets['Travis CI Tokens'].extend(re.findall(travis_ci_token_pattern, js_content))

    oauth_access_token_pattern = r'(ya29\.[A-Za-z0-9-_]+)'
    secrets['OAuth Access Tokens'].extend(re.findall(oauth_access_token_pattern, js_content))
    oauth_refresh_token_pattern = r'1/[A-Za-z0-9-_]+'
    secrets['OAuth Refresh Tokens'].extend(re.findall(oauth_refresh_token_pattern, js_content))

    return secrets

def analyze_site_for_secrets(url):
    html = fetch_html(url)
    js_links = extract_js_links(html)
    
    all_secrets = {
        'JWT Tokens': [],
        'API Tokens': [],
        'AWS Access Key IDs': [],
        'AWS Secret Access Keys': [],
        'GitHub Tokens': [],
        'GitLab Tokens': [],
        'Slack Webhooks': [],
        'Google API Keys': [],
        'Firebase Secret Keys': [],
        'SSH Private Keys': [],
        'CircleCI Tokens': [],
        'Travis CI Tokens': [],
        'OAuth Access Tokens': [],
        'OAuth Refresh Tokens': []
    }
    
    for js_link in js_links:
        if not js_link.startswith(('http://', 'https://')):
            js_link = requests.compat.urljoin(url, js_link)
        js_content = fetch_js_file(js_link)
        secrets = find_secrets(js_content)
        
        for key in all_secrets:
            all_secrets[key].extend(secrets[key])

    return all_secrets

def analyze_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    
    for url in urls:
        url = url.strip()
        if not url:
            continue
        print(Fore.RED + f"Analyzing {url}" + Style.RESET_ALL)
        secrets_found = analyze_site_for_secrets(ensure_http_protocol(url))
        for category, secrets in secrets_found.items():
            if secrets:
                print(Fore.GREEN + f"{category}:" + Style.RESET_ALL)
                for secret in secrets:
                    print(Fore.WHITE + f"  {secret}" + Style.RESET_ALL)
                print()

def ensure_http_protocol(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def main():
    init(autoreset=True)
    print_logo()
    parser = argparse.ArgumentParser(description='Analyze a website or multiple websites from a file for JWT tokens and API secrets in JavaScript files.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', type=str, help='The URL of the website to analyze')
    group.add_argument('-f', '--file', type=str, help='Path to a file containing a list of URLs to analyze')
    args = parser.parse_args()
    
    if args.url:
        url = ensure_http_protocol(args.url)
        print(Fore.RED + f"Analyzing {url}" + Style.RESET_ALL)
        secrets_found = analyze_site_for_secrets(url)
        for category, secrets in secrets_found.items():
            if secrets:
                print(Fore.GREEN + f"{category}:" + Style.RESET_ALL)
                for secret in secrets:
                    print(Fore.WHITE + f"  {secret}" + Style.RESET_ALL)
                print()
    
    if args.file:
        if not os.path.exists(args.file):
            print(Fore.RED + f"File {args.file} not found." + Style.RESET_ALL)
            return
        analyze_domains_from_file(args.file)

if __name__ == '__main__':
    main()
