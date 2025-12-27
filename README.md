A simple Web Application Vulnerability Scanner built with Python and Flask.  
The tool crawls a target website, discovers internal links and HTML forms, and performs basic security checks for SQL Injection on URL parameters. It injects common payloads, analyses responses for database error signatures, and reports potential vulnerabilities through a clean web dashboard.

Tech stack:
- Python (requests, BeautifulSoup, Flask)
- Simple crawler for same‑domain links
- SQLi testing on query parameters
- Bootstrap‑styled web UI with scan summary and findings

This project is for educational use on authorised test targets (DVWA, testphp.vulnweb.com, etc.) to understand core web security concepts like input validation, injection attacks, and secure coding practices.
Features
Crawls same‑domain links starting from a target URL using requests and BeautifulSoup.
​

Collects HTML forms (action, method, input fields) for analysis.
​

Tests URL query parameters for basic SQL Injection using common payloads.
​

Looks for database error signatures in responses to flag potential SQLi.
​

Flask web UI to start scans and view summary (pages visited, forms, vulnerabilities).
​

Bootstrap‑styled, dark cyber‑theme interface for presentations.
Tech Stack
Python 3

Libraries: requests, beautifulsoup4, Flask

Frontend: HTML, Bootstrap 5 (CDN), custom CSS

Platform: Tested on Windows 10/11 with Python 3.10+
ou should see Flask running on http://127.0.0.1:5000/.
​

Open the scanner UI

Go to http://127.0.0.1:5000/ in your browser.

Enter a target URL (e.g., http://testphp.vulnweb.com/ or any other authorised vulnerable lab).
​

Click Start Scan.

View results

The dashboard shows:

Target URL

Pages visited

Forms collected

Total vulnerabilities found

If potential SQL Injection is detected, each finding displays:

Vulnerability type (SQL Injection)

Exact URL used

Parameter name
Payload that triggered the error
How It Works
1. Crawling
The WebScanner class in web_scanner.py:

Starts from the base URL.

Uses requests.Session to fetch pages and BeautifulSoup to parse HTML.
​

Follows <a href> links within the same domain up to a configurable depth.
​

Collects HTML forms with their actions, methods, and inputs for later use.
​

2. SQL Injection Testing
   For each visited URL:

Parses the query string (e.g., ?id=1&cat=2).

Replaces parameter values with common SQLi payloads such as:

'

' OR '1'='1

" OR "1"="1

'--
​

Sends the modified requests and inspects responses for typical database error messages like sql syntax, mysql, sql server, ora-.
​

If a match is found, records a potential SQL Injection vulnerability with evidence.
Web Dashboard
app.py defines a Flask route / handling GET and POST.
​

On POST, it creates a WebScanner instance, runs crawl(), and passes results to index.html.

index.html uses Bootstrap cards, forms, and a dark theme to render the scan summary and vulnerability list.
​

Limitations
Only tests very basic SQL Injection via URL query parameters.

Does not authenticate or handle login‑protected areas.

No support for XSS, CSRF, or advanced OWASP Top 10 issues yet.
​

Intended for educational and lab use, not as a production‑grade scanner
Ethical Use
This project is for learning and must only be used on systems you own or have explicit permission to test. Running vulnerability scanners against random websites without consent can be illegal and unethical
