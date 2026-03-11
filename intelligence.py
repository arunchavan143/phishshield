import socket
import requests


def resolve_ip(domain):

    try:
        return socket.gethostbyname(domain)
    except:
        return None


def ip_info(ip):

    try:

        r = requests.get(f"https://ipinfo.io/{ip}/json",timeout=5)

        data = r.json()

        return {
            "ip":ip,
            "org":data.get("org"),
            "city":data.get("city"),
            "country":data.get("country"),
            "loc":data.get("loc")
        }

    except:
        return None