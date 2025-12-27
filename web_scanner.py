import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


class WebScanner:
    def __init__(self, base_url, max_depth=1):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.visited = set()
        self.vulnerabilities = []
        self.sqli_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'--"]
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SimpleScanner/1.0)"
        })

    def is_same_domain(self, url):
        base_domain = urlparse(self.base_url).netloc
        target_domain = urlparse(url).netloc
        return base_domain == target_domain or target_domain == ""

    def fetch(self, url):
        try:
            resp = self.session.get(url, timeout=10)
            print(f"[+] {resp.status_code} {url}")
            return resp
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
            return None

    # ------------ crawling: links + forms -------------
    def extract_links_and_forms(self, url, html):
        soup = BeautifulSoup(html, "html.parser")

        # collect links
        links = set()
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            if self.is_same_domain(full):
                links.add(full)

        # collect forms
        forms = []
        for form in soup.find_all("form"):
            form_details = {
                "url": url,
                "action": urljoin(url, form.get("action") or ""),
                "method": (form.get("method") or "get").lower(),
                "inputs": []
            }
            for inp in form.find_all("input"):
                form_details["inputs"].append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                })
            forms.append(form_details)

        print(f"    [+] Found {len(links)} links and {len(forms)} forms on this page")
        return links, forms

    # ------------ SQL injection test on URL parameters -------------
    def test_sql_in_url(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return  # no ?param= -> nothing to test

        params = parse_qs(parsed.query)          # e.g. {'id': ['1']}
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        error_signatures = ["sql syntax", "mysql", "sql server", "ora-"]

        for param in params:
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = [payload]   # id=' OR '1'='1
                new_query = urlencode(test_params, doseq=True)
                test_url = base + "?" + new_query

                resp = self.fetch(test_url)
                if not resp:
                    continue

                body = resp.text.lower()
                if any(sig in body for sig in error_signatures):
                    print(f"    [!] Possible SQLi in {param} using payload {payload}")
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "target": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": "Database error message in response"
                    })

    # ------------ main crawl loop -------------
    def crawl(self):
        to_visit = [(self.base_url, 0)]
        all_forms = []

        while to_visit:
            url, depth = to_visit.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)
            resp = self.fetch(url)
            if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            links, forms = self.extract_links_and_forms(url, resp.text)
            all_forms.extend(forms)

            # test current URL for SQL injection
            self.test_sql_in_url(url)

            for link in links:
                if link not in self.visited:
                    to_visit.append((link, depth + 1))

        return all_forms


def main():
    target = input("Enter target URL (e.g. http://testphp.vulnweb.com/): ").strip()
    if not target.startswith("http"):
        print("Please include http:// or https://")
        return

    scanner = WebScanner(target, max_depth=1)  # depth 1 = start page + its direct links
    forms = scanner.crawl()

    print("\n=== SUMMARY ===")
    print(f"Total pages visited: {len(scanner.visited)}")
    print(f"Total forms collected: {len(forms)}")
    print(f"Total vulnerabilities found: {len(scanner.vulnerabilities)}")

    for f in forms:
        print(f"\n[FORM] Page: {f['url']}")
        print(f"       Action: {f['action']}  Method: {f['method']}")
        for inp in f["inputs"]:
            print(f"       Input: name={inp['name']} type={inp['type']}")

    for v in scanner.vulnerabilities:
        print(f"\n[VULN] {v['type']} at {v['target']}")
        print(f"       Param={v['parameter']}  Payload={v['payload']}")
        print(f"       Evidence: {v['evidence']}")


if __name__ == "__main__":
    main()
