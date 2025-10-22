import requests

# -------------------------
# Vérification des headers
# -------------------------
def check_security_headers(headers):
    expected_headers = {
        "Strict-Transport-Security": "Force HTTPS",
        "X-Frame-Options": "Protection contre le clickjacking",
        "X-Content-Type-Options": "Empêche le MIME sniffing",
        "Content-Security-Policy": "Bloque scripts dangereux",
        "Referrer-Policy": "Contrôle les infos du referer",
        "Permissions-Policy": "Contrôle les permissions navigateur"
    }

    report = {}
    for header, description in expected_headers.items():
        if header in headers:
            report[header] = {"present": True, "value": headers[header], "description": description}
        else:
            report[header] = {"present": False, "value": None, "description": description}

    return report


# -------------------------
# Analyse globale du site
# -------------------------
def analyze_site(url):
    try:
        if not url.startswith("http"):
            url = "https://" + url  # ajoute https par défaut

        response = requests.get(url, timeout=5)
        status = response.status_code
        headers = response.headers

        security_check = check_security_headers(headers)

        # Score simple : +1 point par header présent
        total = len(security_check)
        score = sum(1 for h in security_check.values() if h["present"])
        grade = round((score / total) * 100, 1)

        report = {
            "url": url,
            "status_code": status,
            "secure": url.startswith("https"),
            "headers": dict(headers),
            "security_headers": security_check,
            "score_percent": grade
        }

        return report

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
