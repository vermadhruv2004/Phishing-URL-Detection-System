import re
import ipaddress
import socket
try:
    import whois
except ImportError:
    whois = None

from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url if url.startswith("http") else "http://" + url
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.hostname

        try:
            self.whois_info = whois.whois(self.domain)
        except:
            self.whois_info = None

    # 1. Using IP address
    def using_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1

    # 2. Long URL
    def long_url(self):
        return 1 if len(self.url) < 54 else -1

    # 3. Shortened URL
    def short_url(self):
        services = r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd"
        return -1 if re.search(services, self.url) else 1

    # 4. '@' symbol
    def symbol_at(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting '//'
    def redirecting(self):
        return -1 if self.url.count("//") > 1 else 1

    # 6. Prefix/Suffix '-'
    def prefix_suffix(self):
        return -1 if "-" in self.domain else 1

    # 7. Subdomains
    def subdomains(self):
        dots = self.domain.count(".")
        if dots <= 1:
            return 1
        elif dots == 2:
            return 0
        else:
            return -1

    # 8. HTTPS
    def https(self):
        return 1 if self.parsed.scheme == "https" else -1

    # 9. Non-standard port
    def non_standard_port(self):
        return -1 if self.parsed.port else 1

    # 10. Age of domain
    def age_of_domain(self):
        try:
            creation = self.whois_info.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age_days = (date.today() - creation.date()).days
            return 1 if age_days >= 180 else -1
        except:
            return -1

    # 11. DNS record
    def dns_record(self):
        try:
            socket.gethostbyname(self.domain)
            return 1
        except:
            return -1

    def getFeaturesList(self):
        return [
            self.using_ip(),        # UsingIP
            self.long_url(),        # LongURL
            self.short_url(),       # ShortURL
            self.symbol_at(),       # Symbol@
            self.redirecting(),     # Redirecting//
            self.prefix_suffix(),   # PrefixSuffix-
            self.subdomains(),      # SubDomains
            self.https(),            # HTTPS
            self.non_standard_port(),# NonStdPort
            self.age_of_domain(),   # AgeofDomain
            self.dns_record()       # DNSRecording
        ]
