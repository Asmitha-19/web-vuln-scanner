from flask import Flask, render_template, request
from web_scanner import WebScanner   # imports your class

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    vulns = None
    target = None

    if request.method == "POST":
        target = request.form.get("target_url").strip()
        if target and not target.startswith("http"):
            target = "http://" + target

        scanner = WebScanner(target, max_depth=1)
        forms = scanner.crawl()
        results = {
            "pages": len(scanner.visited),
            "forms": len(forms),
        }
        vulns = scanner.vulnerabilities

    return render_template("index.html",
                           results=results,
                           vulns=vulns,
                           target=target)

if __name__ == "__main__":
    app.run(debug=True)
