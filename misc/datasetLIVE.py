import pandas as pd
from RESTAPI.urlclass import LiveUrl

legit = pd.read_csv("smalllegitsample.csv").truncate(before=468)

columns = ["url", "link", "loc", "ext", "static", "uniq", "label"]
url_df = pd.DataFrame(columns=columns)

counter = 819
for url in legit['URL']:
    print("[*] Processing URL " + str(counter))
    counter += 1
    try:
        url_phish = LiveUrl(url)
        df = url_df.append({"url": url, "link": url_phish.link_count, "loc": url_phish.get_linkperc("loc"),
                            "ext": url_phish.get_linkperc("ext"), "static": url_phish.get_linkperc("static"),
                            "uniq": url_phish.get_uniqlocal(), "label": 0}, ignore_index=True)
        df.to_csv("benign.csv", mode='a', header=False, index=False)
    except Exception as e:
        print(e)
        continue

#Last stop URL ?