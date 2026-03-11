import requests
import tldextract
import re
import math


class URLAnalyzer:

    def __init__(self,url):

        if not url.startswith(("http://","https://")):
            url = "http://" + url

        self.url = url
        ext = tldextract.extract(url)
        self.domain = f"{ext.domain}.{ext.suffix}"

    def entropy(self):

        prob = [float(self.domain.count(c)) / len(self.domain)
                for c in dict.fromkeys(list(self.domain))]

        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])

        return round(entropy,2)

    def ip_in_url(self):

        return bool(re.search(r"\d+\.\d+\.\d+\.\d+",self.url))

    def keyword_check(self):

        keywords = ["login","secure","verify","account","update"]

        return any(k in self.url.lower() for k in keywords)

    def redirect_chain(self):

        try:

            r = requests.get(self.url,allow_redirects=True,timeout=5)

            chain = [resp.url for resp in r.history]

            chain.append(r.url)

            return chain

        except:

            return [self.url]

    def metadata(self):

        return {
            "url":self.url,
            "domain":self.domain,
            "entropy":self.entropy(),
            "has_ip":self.ip_in_url(),
            "has_keywords":self.keyword_check(),
            "redirect_chain":self.redirect_chain()
        }