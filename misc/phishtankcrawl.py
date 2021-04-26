import requests
from bs4 import BeautifulSoup
import pandas as pd
import time
from RESTAPI.urlclass import LiveUrl

counter = 1
long_counter = 103
extra_counter = []

url = "https://phishtank.com/phish_search.php"
page_amt = 250
columns = ["url", "link", "loc", "ext", "static", "uniq", "label"]
url_df = pd.DataFrame(columns=columns)
# requests = cloudscraper.create_scraper()

header = {
    "cookie": "PHPSESSID=5n70ph287ds5j2o7u5756hg274; cf-clearance=7b8529f7317513c868924ba5f3b7109c7cc6f6a3-1619100897-0-250; cf_chl_prog=a9; __cfduid=d539785a552ae62fb8e832870ae6a3a171618985224;",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
    "referer": "https://phishtank.com/phish_search.php"
    # "sc-ch-ua": '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"'
}

cookies = {
    "cookie": "PHPSESSID=5n70ph287ds5j2o7u5756hg274; cf-clearance=7b8529f7317513c868924ba5f3b7109c7cc6f6a3-1619100897-0-250; cf_chl_prog=a9; __cfduid=d539785a552ae62fb8e832870ae6a3a171618985224"
}

for page in range(long_counter, page_amt):
    print(page)
    try:
        print("[*] Processing page " + str(page))
        params = {"page": page, "active": "y", "valid": "y", "Search": "Search"}
        resp = requests.get(url, params=params)
        html_soup = BeautifulSoup(resp.text, "html.parser")
        table_data = html_soup.find_all('td')
        for item in range(1, len(table_data), 5):
            phish_link = table_data[item].contents[0]
            if b'\xc2\xa0' in phish_link.encode():
                continue
            elif "..." in phish_link:
                continue
                full_link = "https://phishtank.com/" + table_data[item-1].a['href']
                resp = requests.get(full_link, headers=header)
                link_soup = BeautifulSoup(resp.text, "html.parser")
                full_phish_link = link_soup.find_all('span')[2].get_text()
                print(resp.text)
                if "Ray ID" in full_phish_link:
                    print("[x] Limit at page " + str(page))
                    time.sleep(500)
                url_phish = LiveUrl(full_phish_link)
                if url_phish.dns:
                    df = url_df.append({"url": full_phish_link, "link": url_phish.link_count, "loc": url_phish.get_linkperc("loc"), "ext": url_phish.get_linkperc("ext"), "static": url_phish.get_linkperc("static"), "uniq": url_phish.get_uniqlocal(), "label": 1}, ignore_index=True)
                    df.to_csv("phish.csv", mode='a', header=False, index=False)
                    time.sleep(0.2)
            else:
                try:
                    url_phish = LiveUrl(phish_link)
                    if url_phish.dns:
                        df = url_df.append({"url": phish_link, "link": url_phish.link_count, "loc": url_phish.get_linkperc("loc"), "ext": url_phish.get_linkperc("ext"), "static": url_phish.get_linkperc("static"), "uniq": url_phish.get_uniqlocal(), "label": 1}, ignore_index=True)
                        df.to_csv("phish.csv",mode='a', header=False, index=False)
                    time.sleep(0.5)
                except Exception as e:
                    print(e)
                    continue
    except Exception as e:
        print(e)
        pass
#
# Last stop page 59
