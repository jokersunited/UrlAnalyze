from urllib.parse import urlparse
import tldextract
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

class Url:
    def __init__(self, url, tag):
        # print(url)
        self.tag = tag
        self.url_str = url
        self.urlparse = urlparse(url)
        self.domaininfo = tldextract.extract(self.url_str)

    def get_len(self):
        return len(self.url_str)

    def is_https(self):
        return True if self.urlparse.scheme == 'https' else False

    def get_subdomaincount(self):
        return len(self.domaininfo.subdomain.split("."))

    def get_domain(self):
        return self.urlparse.netloc

bad_df = pd.read_csv("C:\\Users\\jshww\\Documents\\InternCSA2\\IWSP CSA\\URLNET GITHUB\\phishing_url_detection\\dataset\\New folder\\big_bad.min.csv").dropna()
good_df = pd.read_csv("C:\\Users\\jshww\\Documents\\InternCSA2\\IWSP CSA\\URLNET GITHUB\\phishing_url_detection\\dataset\\New folder\\big_good.min.csv").dropna()

bad_objects = [Url(url, label) for url, label in zip(bad_df['url'], bad_df['label'])]
good_objects = [Url(url, label) for url, label in zip(good_df['url'], good_df['label'])]
bad_df = pd.DataFrame([obj.get_len() for obj in bad_objects], columns=['length']).value_counts().to_frame('count')
good_df = pd.DataFrame([obj.get_len() for obj in good_objects], columns=['length']).value_counts().to_frame('count')

print(good_df)
print(bad_df)

fig, axes = plt.subplots(1, 2, figsize=(15, 5))

ax = sns.lineplot(ax=axes[0], x="length", y='count', data=bad_df)
ax.xaxis.set_major_locator(ticker.MultipleLocator(100))

ax2 = sns.lineplot(ax=axes[1], x="length", y='count', data=good_df)
ax2.xaxis.set_major_locator(ticker.MultipleLocator(50))

# print([obj.get_len() for obj in bad_objects])
#
# plt.plot([obj.get_len() for obj in bad_objects])
#
# plt.plot([obj.get_len() for obj in good_objects])
#
plt.xlim(0)
plt.show()

# print(bad_objects)

# # url = Url("https://drive.google.com/drive/folders/1LUiqM453awErf3hMsZAtNBPj_MwkscRS")
# url = Url("https://www.o2billingfailure.com/Login/index?id=11a7288c6298f7d8d80ff1e0ea70d86011a7288c6298f7d8d80ff1e0ea70d860&session=11a7288c6298f7d8d80ff1e0ea70d86011a7288c6298f7d8d80ff1e0ea70d860", 1)
# print(url.is_https())
# print(url.get_domain())
# print(url.get_subdomaincount())
# print(url.get_len())
# print(url.domaininfo)
# print(url.urlparse)
