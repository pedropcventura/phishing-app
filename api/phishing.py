import sys
import requests
import json
import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse, urlunparse
import whois
from bs4 import BeautifulSoup
import Levenshtein
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import geoip2.database
from transformers import pipeline

# ---------- Normalização de URL ----------
def normalize_url(raw_url: str) -> str:
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    netloc = parsed.netloc
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))

# ---------- Critério C (Heurísticas básicas) ----------
def analyze_basic_heuristics(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname or ''
    parts = domain.split('.')
    subdomain_count = len(parts) - 2
    return {
        'url_length': len(url),
        'digit_substitution': int(bool(re.search(r'[0-9]', domain) and re.search(r'[A-Za-z]', domain))),
        'excessive_subdomains': int(subdomain_count > 3),
        'special_characters': int(bool(re.search(r'[@!$%*+=]', parsed.path + parsed.query)))
    }

# ---------- Idade de domínio via WHOIS ----------
def analyze_domain_age(url: str) -> dict:
    domain = urlparse(url).hostname or ''
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        age_days = (datetime.now() - creation).days
        return {'domain_age_days': age_days}
    except:
        return {'domain_age_days': -1}

# ---------- Detecção de DNS dinâmico ----------
DYNAMIC_PROVIDERS = ['no-ip.org', 'dyndns.com', 'duckdns.org', 'nip.io']
def detect_dynamic_dns(url: str) -> dict:
    domain = urlparse(url).hostname or ''
    return {'dynamic_dns': int(any(domain.endswith(p) for p in DYNAMIC_PROVIDERS))}

# ---------- Análise de certificado SSL ----------
def analyze_ssl_certificate(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_valid = (not_after - datetime.now()).days
                return {'ssl_valid_days': days_valid}
    except:
        return {'ssl_valid_days': -1}

# ---------- Detecção de redirecionamentos suspeitos ----------
def detect_suspicious_redirects(url: str) -> dict:
    try:
        resp = requests.get(url, allow_redirects=True, timeout=5)
        chain_hosts = [urlparse(r.url).hostname for r in resp.history] + [urlparse(resp.url).hostname]
        suspect = int(len(set(chain_hosts)) > 1)
        return {'redirect_suspicious': suspect}
    except:
        return {'redirect_suspicious': -1}

# ---------- Similaridade de domínio (Levenshtein) ----------
KNOWN_BRANDS = ['google.com', 'facebook.com', 'paypal.com', 'amazon.com']
def domain_similarity(url: str) -> dict:
    domain = urlparse(url).hostname or ''
    distances = [Levenshtein.distance(domain, b) for b in KNOWN_BRANDS]
    return {'min_levenshtein': min(distances)}

# ---------- Análise de conteúdo para formulários de login ----------
def analyze_content_for_login(url: str) -> dict:
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        has_pwd = any(form.find('input', {'type': 'password'}) for form in soup.find_all('form'))
        return {'login_form': int(has_pwd)}
    except:
        return {'login_form': -1}

# ---------- País de hospedagem via GeoIP ----------
GEOIP_DB = '/path/to/GeoLite2-Country.mmdb'
def get_ip_country(url: str) -> dict:
    try:
        ip = socket.gethostbyname(urlparse(url).hostname)
        reader = geoip2.database.Reader(GEOIP_DB)
        country = reader.country(ip).country.iso_code
        reader.close()
        return {'country': country}
    except:
        return {'country': 'UNK'}

# ---------- Reputação de host (dummy check) ----------
BAD_IPS = {'1.2.3.4'}  # exemplo
def check_host_reputation(url: str) -> dict:
    try:
        ip = socket.gethostbyname(urlparse(url).hostname)
        return {'bad_ip': int(ip in BAD_IPS)}
    except:
        return {'bad_ip': -1}

# ---------- Detecção de OAuth suspeito ----------
OAUTH_KEYWORDS = ['oauth', 'auth', 'token', 'scope']
def detect_oauth_legitimacy(url: str) -> dict:
    try:
        resp = requests.get(url, timeout=5)
        text = resp.text.lower()
        suspicious = any(k in text for k in OAUTH_KEYWORDS)
        return {'oauth_suspicious': int(suspicious)}
    except:
        return {'oauth_suspicious': -1}

# ---------- Verificação no PhishTank ----------
def check_phishtank(url: str) -> dict:
    """
    Consulta PhishTank e retorna flags de database e valid.
    """
    headers = {"User-Agent": "phishtank/seu_usuario"}
    payload = {"url": url, "format": "json"}
    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers=headers,
            timeout=5
        )
        results = resp.json().get("results")
        if not results:
            return {"phish_in_database": 0, "phish_valid": 0}
        return {
            "phish_in_database": int(results.get("in_database", False)),
            "phish_valid": int(results.get("valid", False))
        }
    except Exception:
        return {"phish_in_database": -1, "phish_valid": -1}

# -------------- Machine learning model --------------
# Carrega o modelo em memória (faz download na primeira vez)
hf_phish_clf = pipeline(
    "text-classification",
    model="ealvaradob/bert-finetuned-phishing",
    tokenizer="ealvaradob/bert-finetuned-phishing",
    return_all_scores=False   # só o label mais provável
)
def detect_phishing_hf(url: str) -> dict:
    """
    Retorna {'label': 'phishing'|'legit', 'score': float}
    """
    # O pipeline espera texto; passamos a URL como string
    out = hf_phish_clf(url)[0]
    # Exemplo de `out`: {'label': 'LABEL_1', 'score': 0.87}
    label = out["label"]
    print(label)
    # No modelo em questão, LABEL_1 = phishing, LABEL_0 = legitimate
    is_phish = 1 if (label == "phishing") else 0
    return {"hf_phishing": is_phish, "hf_confidence": out["score"]}


# ---------- Explicação da decisão ----------
def explain_decision(features: dict) -> dict:
    positive = []
    negative = []

    # Modelo de IA
    if features["hf_phishing"] == 1:
        negative.append("ML model detected phishing")
    else:
        positive.append("ML model detected legitimate URL")

    # Heurísticas
    if features["domain_age_days"] > 1000:
        positive.append(f"Domain age > 1000 days ({features['domain_age_days']})")
    elif 0 < features["domain_age_days"] <= 1000:
        negative.append(f"Young domain ({features['domain_age_days']} days)")
    if features["dynamic_dns"] == 1:
        negative.append("Uses dynamic DNS provider")
    if features["redirect_suspicious"] == 1:
        negative.append("Suspicious redirections detected")
    if features["login_form"] == 1:
        negative.append("Login form detected (possible phishing attempt)")
    if features["oauth_suspicious"] == 1:
        negative.append("OAuth keywords detected")
    if features["phish_in_database"] == 1:
        negative.append("PhishTank reports this URL exists")
    if features["bad_ip"] == 1:
        negative.append("IP is flagged as bad")
    if features["excessive_subdomains"] == 1:
        negative.append("Excessive subdomains detected")
    if features["special_characters"] == 1:
        negative.append("Special characters detected in URL")

    return {
        "positive_factors": positive,
        "negative_factors": negative
    }

# def calculate_risk_score(features: dict) -> int:
#     """
#     Calcula score de risco priorizando extremamente a classificação do modelo de ML.
#     """
#     ml_score = features["hf_confidence"]
#     ml_label = features["hf_phishing"]  # 1 = phishing, 0 = legit

#     # Modelo diz phishing
#     if ml_label == 1 and ml_score >= 0.8:
#         return 5    # phishing com muita certeza
#     if ml_label == 1 and ml_score < 0.8:
#         return 15   # phishing incerto

#     # Modelo diz legítimo
#     if ml_label == 0 and ml_score >= 0.98:
#         return 100   # máxima confiança → não penalizar
#     elif ml_label == 0 and ml_score >= 0.90:
#         base_score = 95   # muito confiante → penalizar minimamente
#     else:
#         base_score = 75   # confiança baixa → penalizar normalmente

#     # Penalidades (apenas se modelo permitiu)
#     penalties = {
#         "redirect_suspicious": 5,
#         "login_form": 5,
#         "oauth_suspicious": 3,
#         "phish_in_database": 10,
#         "bad_ip": 15,
#         "excessive_subdomains": 3,
#         "special_characters": 3,
#         "dynamic_dns": 5
#     }

#     for key, penalty in penalties.items():
#         if features.get(key, 0) == 1:
#             base_score -= penalty

#     return max(0, min(100, base_score))
def calculate_risk_score(features: dict) -> int:
    """
    Versão definitiva: prioriza o modelo de ML, mas protege contra domínios inexistentes,
    heurísticas falhas e lookalike phishing patterns.
    """
    ml_score = features["hf_confidence"]
    ml_label = features["hf_phishing"]  # 1 = phishing, 0 = legit

    # Proteção extra: se o domínio não existir ou não puder ser resolvido
    if (
        features["domain_age_days"] == -1 and
        features["ssl_valid_days"] == -1 and
        features["bad_ip"] == -1
    ):
        return 5  # Domínio suspeito/não existe → risco extremo

    # Modelo diz phishing
    if ml_label == 1 and ml_score >= 0.8:
        return 5    # phishing com muita certeza
    if ml_label == 1 and ml_score < 0.8:
        return 15   # phishing incerto

    # Modelo diz legítimo
    if ml_label == 0 and ml_score >= 0.98:
        base_score = 100   # máxima confiança → não penalizar
    elif ml_label == 0 and ml_score >= 0.90:
        base_score = 95    # muito confiante → penalizar minimamente
    else:
        base_score = 75    # confiança baixa → penalizar normalmente

    # Penalidades (apenas se modelo permitiu)
    penalties = {
        "redirect_suspicious": 5,
        "login_form": 5,
        "oauth_suspicious": 3,
        "phish_in_database": 10,
        "bad_ip": 15,
        "excessive_subdomains": 3,
        "special_characters": 3,
        "dynamic_dns": 5
    }

    for key, penalty in penalties.items():
        value = features.get(key, 0)
        if value == 1:
            base_score -= penalty
        elif value == -1:
            base_score -= 15  # penalidade extra para heurística falha

    return max(0, min(100, base_score))

def risk_level(score: int) -> str:
    """
    Classificação do score em níveis para facilitar dashboards.
    """
    if score >= 90:
        return "Very Low"
    elif score >= 75:
        return "Low"
    elif score >= 50:
        return "Moderate"
    elif score >= 25:
        return "High"
    else:
        return "Very High"




# ---------- Extração de features para ML ----------
def extract_features(url: str) -> dict:
    print("===========================================")
    f = {}
    f.update(analyze_basic_heuristics(url))
    f.update(analyze_domain_age(url))
    f.update(detect_dynamic_dns(url))
    f.update(analyze_ssl_certificate(url))
    f.update(detect_suspicious_redirects(url))
    f.update(domain_similarity(url))
    f.update(analyze_content_for_login(url))
    f.update(get_ip_country(url))
    f.update(check_host_reputation(url))
    f.update(detect_oauth_legitimacy(url))
    f.update(check_phishtank(url))
    f.update(detect_phishing_hf(url))

    explanation = explain_decision(f)
    risk_score = calculate_risk_score(f)
    risk_lvl = risk_level(risk_score)

    f["risk_score"] = risk_score
    f["explanation"] = explanation
    f["risk_level"] = risk_lvl

    return f


# ---------- Main ----------
if __name__ == '__main__':
    # Modo único: sempre extrai e exibe features
    raw = sys.argv[1] if len(sys.argv) > 1 else ''
    url = normalize_url(raw)
    features = extract_features(url)
    print(json.dumps(features, indent=2, ensure_ascii=False))