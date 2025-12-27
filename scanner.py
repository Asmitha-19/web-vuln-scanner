# scanner_step1.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def main():
    # 1) Get target URL from user
    target_url = input("Enter target URL (e.g. http://testphp.vulnweb.com/): ").strip()
    if not target_url.startswith("http"):
        print("Please include http:// or https:// in the URL")
        return

    # 2) Send GET request
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; SimpleScanner/1.0)"
        }  # user-agent helps avoid simple blocks [web:38]
        response = requests.get(target_url, headers=headers, timeout=10)
        print(f"[+] HTTP {response.status_code} received from {target_url}")
    except Exception as e:
        print(f"[-] Error fetching page: {e}")
        return

    # 3) Parse HTML with BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")  # standard usage [web:37]

    # 4) List all links on the page
    print("\n=== LINKS FOUND ON PAGE ===")
    for a in soup.find_all("a", href=True):  # find_all is common BS4 pattern [web:49]
        full_url = urljoin(target_url, a["href"])
        print(full_url)

    # 5) List all forms and their input fields
    print("\n=== FORMS FOUND ON PAGE ===")
    forms = soup.find_all("form")
    if not forms:
        print("No forms found on this page.")
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").upper()
        print(f"\nForm: action={action}, method={method}")
        inputs = form.find_all("input")
        for inp in inputs:
            name = inp.get("name")
            itype = inp.get("type", "text")
            print(f"   Input: name={name}, type={itype}")

if __name__ == "__main__":
    main()
