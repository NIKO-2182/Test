import pandas as pd
from urllib.parse import urlparse
import whois
import datetime
import socket
import re

def extract_urls_from_text(message):
    """Extract URLs from text message using regex"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, message)

def extract_features(url):
    """Extract features from URL for phishing detection"""
    try:
        # Parse URL properly
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else url.split("//")[-1].split("/")[0]
    except:
        domain = url

    features = {}

    shorteners = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 
        'ow.ly', 'is.gd', 'buff.ly', 'tiny.cc', 
        'rb.gy', 'cutt.ly', 'tny.im'
    }
    features["Shortining_Service"] = 1 if any(s in domain.lower() for s in shorteners) else 0

    
    features["having_At_Symbol"] = 1 if "@" in parsed.netloc else 0
    features["double_slash_redirecting"] = 1 if "//" in url.split("://")[1] else 0
    features["Prefix_Suffix"] = 1 if "-" in domain else 0
    
    
    features["URLURL_Length"] = 1 if len(url) > 54 else 0

    features["having_Sub_Domain"] = len(domain.split(".")) - 1

    features["SSLfinal_State"] = 0 if url.startswith("https") else 1

    features["Domain_registeration_length"] = len(domain)

    suspicious_words = ["login", "signin", "verify", "account", "update", "confirm", "secure"]
    features["Request_URL"] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    features["URL_of_Anchor"] = 1 if "#" in url or "anchor" in url.lower() else 0

  
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            if age < 180:  # Domain less than 6 months old
                features["age_of_domain"] = 2
            elif age < 365:  # Domain less than 1 year old
                features["age_of_domain"] = 1
            else:
                features["age_of_domain"] = 0
        else:
            features["age_of_domain"] = 2
    except:
        features["age_of_domain"] = 2

     
    try:
        socket.gethostbyname(domain)
        features["DNSRecord"] = 1
    except:
        features["DNSRecord"] = 0

    path_length = len(url.split("/")) - 3 if len(url.split("/")) > 3 else 0
    features["web_traffic"] = min(path_length, 5)  # Cap at 5

    features["Google_Index"] = int(bool(re.search(r'google|search|index', url.lower())))

    columns = [
        "URLURL_Length", "Shortining_Service", "having_At_Symbol",
        "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain",
        "SSLfinal_State", "Domain_registeration_length", "Request_URL",
        "URL_of_Anchor", "age_of_domain", "DNSRecord", "web_traffic",
        "Google_Index"
    ]
    
    final_features = [features[col] for col in columns]
    return pd.DataFrame([final_features], columns=columns)