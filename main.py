import re
import datetime
import logging
from concurrent.futures import ThreadPoolExecutor

import argparse
import requests
import geoip2.database
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

from model import Base, Proxy
from constants import DATABASE_URL, github_repos_with_proxies
from exceptions import InvalidCountryCodeError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ProxyScraper:
    def __init__(self, github_repos: list = None):
        self.geoip_db = self._load_geoip_db()
        # create the engine
        engine = create_engine(DATABASE_URL)
        # create the table in the database
        Base.metadata.create_all(engine)
        # create a session factory
        self.Session = sessionmaker(bind=engine)

        headers = {
            'User-agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'keep-alive'}
        self.requests_session = requests.Session()
        self.requests_session.headers = headers

        if not github_repos:
            # https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt >> prxchk/proxy-list/main/socks5.txt
            self.proxy_from_github_repos = github_repos_with_proxies[:4]
        else:
            self.proxy_from_github_repos = github_repos

    def _get_session(self):
        """creates and returns a new database session."""
        return self.Session()

    def _load_geoip_db(self):
        reader = geoip2.database.Reader('./GeoLite2-Country.mmdb')
        return reader

    def _remove_duplicate_proxies(self, proxies: list):
        """remove duplicates from a list of Proxy objects based on the host attribute."""
        unique_hosts = set()
        unique_proxies = []
        for proxy in proxies:
            if proxy.host not in unique_hosts:
                unique_hosts.add(proxy.host)
                unique_proxies.append(proxy)
        return unique_proxies

    def get_country_code_from_ip(self, ip_address: str):
        try:
            response = self.geoip_db.country(ip_address)
            country_code = response.country.iso_code
            return country_code
        except Exception as exc:
            logger.debug(exc)
            return None

    def parse_proxies(self):
        # spys.one
        new_proxies = self.parse_spys_proxy()

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(self.parse_github_repo_proxies, self.proxy_from_github_repos))

        for r in results:
            new_proxies.extend(r)

        with self._get_session() as db:
            # get proxies from db
            proxies_from_db = [i.host for i in db.query(Proxy).all()]
            logger.info(f"Got {len(proxies_from_db)} proxies from db!")

            # remove already existing proxies
            new_proxies = [i for i in self._remove_duplicate_proxies(new_proxies) if i.host not in proxies_from_db]

            # add proxies to db
            db.add_all(new_proxies)
            db.commit()

            logger.info(f"Added {len(new_proxies)} new proxies to db!")

        return new_proxies

    def parse_github_repo_proxies(self, repo_url: str):
        """
        https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt
        OR
        hookzof/socks5_list/master/proxy.txt
        """
        logger.info(f"Getting free proxy from {repo_url}")
        if "https://" not in repo_url:
            repo_url = "https://raw.githubusercontent.com/" + repo_url
        proxies = []
        response = self.requests_session.get(repo_url)
        if response.status_code == 200:

            tmp_proxies = [i.strip().split("|")[0] if "|" in i else i.strip() for i in response.text.split("\n") if ":" in i]
            for p in tmp_proxies:
                source = repo_url.split("githubusercontent.com/")[1].split("/")[0]

                country = self.get_country_code_from_ip(p.split(":")[0])
                proxies.append(Proxy(host=p.split(":")[0],
                                     port=int(p.split(":")[1]),
                                     country_code=country,
                                     date_added=datetime.datetime.utcnow(),
                                     source=source))

        return proxies

    def parse_spys_proxy(self):
        logger.info("Getting free proxy from spys.one")
        proxies = []
        url = "https://spys.one/en/socks-proxy-list/"
        response = self.requests_session.get(url)
        if response.status_code == 200:
            pattern = re.compile(r'onmouseout.*?spy14>(.*?)<s.*?write.*?nt>\"\+(.*?)\)</scr.*?en(.*?)-', re.S)
            info = re.findall(pattern, response.text)
            port_passwd = {}
            port_code = (re.findall('table><script type="text/javascript">(.*)</script>', response.text))[0].split(';')
            for code in port_code:
                ii = re.findall(r'\w+=\d+', code)
                for i in ii:
                    kv = i.split('=')
                    if len(kv[1]) == 1:
                        k = kv[0]
                        v = kv[1]
                        port_passwd[k] = v
                    else:
                        pass

            for i in info:
                port_word = re.findall(r'\((\w+)\^', i[1])
                port_digital = ''
                for port_number in port_word:
                    port_digital += port_passwd[port_number]

                country = self.get_country_code_from_ip(i[0])
                proxies.append(Proxy(host=i[0],
                                     port=int(port_digital),
                                     country_code=country,
                                     date_added=datetime.datetime.utcnow(),
                                     source="spys.one"))

        return proxies


class DbManager:
    def __init__(self):
        # create the engine
        engine = create_engine(DATABASE_URL)
        # create the table in the database
        Base.metadata.create_all(engine)
        # create a session factory
        self.Session = sessionmaker(bind=engine)

    def _get_session(self):
        """creates and returns a new database session."""
        return self.Session()

    def get_last_10_proxies(self, limit: int = 60):
        """fetch and display the last 10 proxies added."""
        proxies = self._get_session().query(Proxy).order_by(Proxy.date_added.desc()).limit(limit).all()
        logger.info("{:<20} {:<6} {:<12} {:<10}".format("HOST", "PORT", "COUNTRY CODE", "DATE ADDED"))
        logger.info("-" * 55)
        for proxy in proxies:
            logger.info("{:<20} {:<6} {:<12} {:<10}".format(proxy.host, proxy.port, proxy.country_code, proxy.date_added.strftime("%Y-%m-%d")))

    def search_proxies_by_country(self, country_code: str = None, limit: int = 60):
        """search for proxies by country code."""
        if not country_code:
            country_code = input("Enter 2 letter country code: ")

        if len(country_code) > 3:
            raise InvalidCountryCodeError(f"Country code '{country_code}' is invalid. It must be at most 3 characters long.")

        proxies = self._get_session().query(Proxy).filter(Proxy.country_code == country_code).order_by(Proxy.date_added.desc()).limit(limit).all()
        logger.info("{:<20} {:<6} {:<12} {:<10}".format("HOST", "PORT", "COUNTRY CODE", "DATE ADDED"))
        logger.info("-" * 65)
        for proxy in proxies:
            logger.info("{:<20} {:<6} {:<12} {:<10}".format(proxy.host, proxy.port, proxy.country_code, proxy.date_added.strftime("%Y-%m-%d")))


def main():
    parser = argparse.ArgumentParser(description="Proxy management script.")
    parser.add_argument("action", choices=["scrape", "list", "search"], help="Action to perform.")

    scraper = ProxyScraper()
    db_manager = DbManager()

    # mapping action to its respective function
    actions = {"scrape": scraper.parse_proxies,
               "list": db_manager.get_last_10_proxies,
               "search": db_manager.search_proxies_by_country}

    args = parser.parse_args()

    try:
        # best way to use argparse lol
        actions[args.action]()
    except InvalidCountryCodeError as err:
        logger.info(err)


if __name__ == "__main__":
    main()
