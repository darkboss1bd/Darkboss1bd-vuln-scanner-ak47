import requests
import sys
import argparse
from urllib.parse import parse_qs, urlencode
from colorama import init, Fore, Style

init(autoreset=True)

def banner():
    print(Fore.RED + Style.BRIGHT + r"""
######     #    ######  #    # ######  #######  #####   #####     #   ######  ######  
#     #   # #   #     # #   #  #     # #     # #     # #     #   ##   #     # #     # 
#     #  #   #  #     # #  #   #     # #     # #       #        # #   #     # #     # 
#     # #     # ######  ###    ######  #     #  #####   #####     #   ######  #     # 
#     # ####### #   #   #  #   #     # #     #       #       #    #   #     # #     # 
#     # #     # #    #  #   #  #     # #     # #     # #     #    #   #     # #     # 
######  #     # #     # #    # ######  #######  #####   #####   ##### ######  ######  
    """ + Fore.CYAN + Style.BRIGHT + """
    =============================================
    |        DARKBOSS1BD Vulnerability Scanner   |
    |           Developed with ❤️ by DARKBOSS1BD          |
    =============================================
    """)

def check_connection(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Connection successful! Status Code: {response.status_code}")
            return response
        else:
            print(Fore.RED + f"[-] Website returned status code: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[-] Connection error: {str(e)}")
        sys.exit(1)

def check_sqli(url):
    vulnerabilities = []
    if '?' not in url:
        return ["[!] URL has no parameters (SQLi test skipped)"]
    
    base_url, params_str = url.split('?', 1)
    params = parse_qs(params_str, keep_blank_values=True)
    
    for param in params.keys():
        test_params = params.copy()
        test_params[param] = "'"
        test_url = base_url + '?' + urlencode(test_params, doseq=True)
        
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            error_patterns = ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation', 'quoted string']
            if response.status_code == 500 or any(pattern in response.text.lower() for pattern in error_patterns):
                vulnerabilities.append(Fore.YELLOW + f"SQL Injection vulnerability in parameter: '{param}'")
        except:
            pass
    
    return vulnerabilities if vulnerabilities else ["[✓] No SQL Injection vulnerabilities found"]

def check_xss(url):
    vulnerabilities = []
    if '?' not in url:
        return ["[!] URL has no parameters (XSS test skipped)"]
    
    base_url, params_str = url.split('?', 1)
    params = parse_qs(params_str, keep_blank_values=True)
    xss_payload = "<script>alert(1)</script>"
    
    for param in params.keys():
        test_params = params.copy()
        test_params[param] = xss_payload
        test_url = base_url + '?' + urlencode(test_params, doseq=True)
        
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            if xss_payload in response.text:
                vulnerabilities.append(Fore.YELLOW + f"Reflected XSS vulnerability in parameter: '{param}'")
        except:
            pass
    
    return vulnerabilities if vulnerabilities else ["[✓] No XSS vulnerabilities found"]

def check_security_headers(url):
    response = requests.get(url, timeout=10, verify=False)
    headers = response.headers
    missing_headers = []
    
    if 'Strict-Transport-Security' not in headers:
        missing_headers.append(Fore.RED + "HSTS header missing (Prevents SSL stripping attacks)")
    
    if 'X-Content-Type-Options' not in headers or headers['X-Content-Type-Options'].lower() != 'nosniff':
        missing_headers.append(Fore.RED + "X-Content-Type-Options missing (MIME sniffing protection)")
    
    if 'X-Frame-Options' not in headers:
        missing_headers.append(Fore.RED + "X-Frame-Options missing (Clickjacking protection)")
    
    if 'Content-Security-Policy' not in headers:
        missing_headers.append(Fore.RED + "Content-Security-Policy missing (XSS protection)")
    
    return missing_headers if missing_headers else ["[✓] Security headers are properly configured"]

def check_server_info(url):
    response = requests.get(url, timeout=10, verify=False)
    server_header = response.headers.get('Server', '')
    
    if server_header:
        return [Fore.YELLOW + f"Server information disclosed: {server_header}"]
    return ["[✓] No server version disclosure"]

def check_directory_listing(url):
    common_paths = ['/', '/images/', '/img/', '/uploads/', '/files/']
    vulnerabilities = []
    
    base_url = url.split('?')[0]
    if not base_url.endswith('/'):
        base_url += '/'
    
    for path in common_paths:
        test_url = base_url + path
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            if response.status_code == 200 and 'href="' in response.text.lower():
                if any(word in response.text.lower() for word in ['parent directory', 'index of', 'directory listing']):
                    vulnerabilities.append(Fore.YELLOW + f"Directory listing enabled: {test_url}")
        except:
            pass
    
    return vulnerabilities if vulnerabilities else ["[✓] No directory listing vulnerabilities"]

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Website Vulnerability Scanner')
    parser.add_argument('url', type=str, help='Target website URL (e.g., http://example.com)')
    args = parser.parse_args()
    
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print(Fore.CYAN + Style.BRIGHT + f"\n[>] Scanning target: {url}\n")
    check_connection(url)
    
    print(Fore.MAGENTA + "\n[1] Checking for SQL Injection...")
    sqli_results = check_sqli(url)
    
    print(Fore.MAGENTA + "\n[2] Checking for XSS Vulnerabilities...")
    xss_results = check_xss(url)
    
    print(Fore.MAGENTA + "\n[3] Checking Security Headers...")
    headers_results = check_security_headers(url)
    
    print(Fore.MAGENTA + "\n[4] Checking Server Information...")
    server_results = check_server_info(url)
    
    print(Fore.MAGENTA + "\n[5] Checking Directory Listing...")
    dir_results = check_directory_listing(url)
    
    # Print Results
    print(Fore.CYAN + Style.BRIGHT + "\n\n" + "="*50)
    print(Fore.CYAN + Style.BRIGHT + " DARKBOSS1BD SCAN RESULTS SUMMARY ")
    print(Fore.CYAN + Style.BRIGHT + "="*50)
    
    print(Fore.YELLOW + "\n🔍 SQL Injection Test:")
    for res in sqli_results:
        print(f" - {res}")
    
    print(Fore.YELLOW + "\n🔍 XSS Test:")
    for res in xss_results:
        print(f" - {res}")
    
    print(Fore.YELLOW + "\n🔍 Security Headers:")
    for res in headers_results:
        print(f" - {res}")
    
    print(Fore.YELLOW + "\n🔍 Server Information:")
    for res in server_results:
        print(f" - {res}")
    
    print(Fore.YELLOW + "\n🔍 Directory Listing:")
    for res in dir_results:
        print(f" - {res}")
    
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.GREEN + " DARKBOSS1BD Scan completed successfully!")
    print(Fore.CYAN + "="*50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Scan interrupted by user (Ctrl+C)")
        sys.exit(1)
