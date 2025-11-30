#!/usr/bin/env python3
import sys
import json
import struct
import math
from urllib.parse import urlparse

# Constants & heuristics
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co"}
BAD_TLDS = {".ru", ".xyz", ".top", ".click", ".shop"}

# Lightweight ML-style domain legitimacy model
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "shop", "link", "ru", "cn", "work"
}

BRAND_KEYWORDS = [
    "google", "paypal", "microsoft", "apple", "amazon",
    "office", "outlook", "bank", "secure", "login"
]

def domain_features(domain: str):
    d = (domain or "").lower()
    feats = {}

    feats["len"] = len(d)
    feats["dot_count"] = d.count(".")
    feats["hyphen_count"] = d.count("-")
    feats["digit_count"] = sum(c.isdigit() for c in d)
    feats["digit_ratio"] = (
        feats["digit_count"] / feats["len"] if feats["len"] else 0.0
    )

    labels = d.split(".") if d else []
    feats["label_count"] = len(labels)
    tld = labels[-1] if labels else ""
    feats["suspicious_tld"] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    feats["contains_brand_keyword"] = 1.0 if any(k in d for k in BRAND_KEYWORDS) else 0.0

    vowels = "aeiou"
    vowel_count = sum(c in vowels for c in d)
    feats["vowel_ratio"] = (
        vowel_count / feats["len"] if feats["len"] else 0.0
    )

    return feats

def domain_legitimacy_score(domain: str) -> float:

    f = domain_features(domain)

    z = 0.0
    z += 0.5   # baseline "probably OK"

    if f["suspicious_tld"]:
        z += -2.0

    z += -1.0 * f["digit_ratio"]
    z += -0.3 * f["hyphen_count"]

    short_len = min(f["len"], 20)
    z += 0.05 * short_len
    if f["len"] > 30:
        z += -0.05 * (f["len"] - 30)

    if f["label_count"] > 4:
        z += -0.4 * (f["label_count"] - 4)

    z += 0.4 * f["contains_brand_keyword"]

    return 1.0 / (1.0 + math.exp(-z))


# Helper functions
def parse_domain(addr: str):
    if not addr or "@" not in addr:
        return ""
    return addr.split("@")[-1].strip().lower()


def extract_sender_domains(email):
    headers = email.get("headers", {})

    from_field = headers.get("from") or email.get("author") or [""]
    reply_field = headers.get("reply-to") or [""]
    return_field = headers.get("return-path") or [""]

    from_field = from_field[0] if isinstance(from_field, list) else from_field
    reply_field = reply_field[0] if isinstance(reply_field, list) else reply_field
    return_field = return_field[0] if isinstance(return_field, list) else return_field

    def safe_extract(addr):
        if not isinstance(addr, str):
            return ""
        parts = addr.split()
        if not parts:
            return ""
        return parse_domain(parts[-1].strip("<>"))

    return (
        safe_extract(from_field),
        safe_extract(reply_field),
        safe_extract(return_field),
    )


# Link evaluation using the ML-style domain scoring
def evaluate_links(email):
    suspicious_links = []
    links = email.get("links", []) or []

    for link in links:
        href = link.get("href") or ""
        try:
            domain = urlparse(href).netloc.lower()
        except:
            domain = ""

        reasons = []

        # Basic protocol / shortener heuristics
        if href.startswith("http://"):
            reasons.append("uses HTTP instead of HTTPS")

        if any(domain.endswith(s) for s in SHORTENERS):
            reasons.append("URL shortener")

        if any(domain.endswith(tld) for tld in BAD_TLDS):
            reasons.append("suspicious TLD")

        # ML-model judgment
        if domain:
            score = domain_legitimacy_score(domain)
            if score < 0.4:  # threshold you can tune
                reasons.append(f"domain looks suspicious (score={score:.2f})")

        if reasons:
            suspicious_links.append({
                "href": href,
                "domain": domain,
                "reasons": reasons
            })

    return suspicious_links


# Main scoring logic
def score_email(email):
    reasons = []

    # Auth headers
    auth = " ".join(email.get("headers", {}).get("authentication-results", [])).lower()
    if "spf=fail" in auth:
        reasons.append("SPF failed")
    if "dkim=fail" in auth or "dkim=none" in auth:
        reasons.append("DKIM missing or failed")
    if "dmarc=fail" in auth:
        reasons.append("DMARC failed")

    # Sender domains
    from_d, reply_d, return_d = extract_sender_domains(email)

    if from_d:
        sender_score = domain_legitimacy_score(from_d)
        if sender_score < 0.4:
            reasons.append(
                f"sender domain looks suspicious (score={sender_score:.2f}): {from_d}"
            )

    if reply_d and reply_d != from_d:
        reasons.append("reply-to domain differs from sender")

    # Body flags
    body = (
        (email.get("plainText") or "") +
        (email.get("textFromHtml") or "") +
        (email.get("rawSnippet") or "")
    ).lower()

    if "external sender" in body:
        reasons.append("external sender banner detected")

    # Links
    suspicious_links = evaluate_links(email)
    if suspicious_links:
        reasons.append("one or more links appear suspicious")

    # Trust score
    MAX_RISK = 10
    trust_score = max(0.0, 1.0 - len(reasons) / MAX_RISK)

    if trust_score < 0.3:
        risk = "high"
    elif trust_score < 0.7:
        risk = "medium"
    else:
        risk = "low"

    return {
        "trustScore": round(trust_score, 2),
        "riskLevel": risk,
        "reasons": reasons,
        "suspiciousLinks": suspicious_links
    }


# Native messaging I/O
# May work but unsure
def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        return None
    message_length = struct.unpack("I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)

def send_message(msg):
    encoded = json.dumps(msg).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def main():
    # Works both as native messaging host OR as standalone import
    if sys.stdin.isatty():
        return  # direct mode (import) — not native messaging

    while True:
        incoming = read_message()
        if incoming is None:
            break
        result = score_email(incoming)
        send_message(result)


if __name__ == "__main__":
    main()
