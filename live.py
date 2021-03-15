from urllib.parse import urlparse
import pandas as pd
import ssl, OpenSSL, re, whois, tldextract, time, socket, json
from datetime import datetime
from langdetect import detect_langs
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import base64

def get_status(logs):
    statuses = []
    for log in logs:
        if log['message']:
            d = json.loads(log['message'])
            if d['message'].get('method') == "Network.responseReceived":
                statuses.append(d['message']['params']['response']['status'])
    return statuses

def gen_char_dict():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-;.!?:'\"/\|_@#$%^&*~`+-=<>()[]{}"
    char_dict = {}
    char_dict["null"] = 0
    for i, char in enumerate(alphabet):
        char_dict[char] = i + 1
    char_dict["UNK"] = len(alphabet)+1
    return char_dict

char_dict = gen_char_dict()

user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36'
options = webdriver.ChromeOptions()
options.add_argument(f'user-agent={user_agent}')
options.add_argument('--headless')

capabilities = options.to_capabilities()
capabilities['goog:loggingPrefs'] = {'performance': 'ALL'}

service = webdriver.chrome.service.Service(ChromeDriverManager().install())
service.start()

def strip_proto(s):
    return s.replace("https://", "").replace("http://", "").replace("www.", "")

def get_encoding_proto(url, length):
    url = strip_proto(url)
    enc_list = []
    url_str = url if len(url) <= length else url[:length]

    for char in url_str:
        if char in char_dict.keys():
            enc_list.append(char_dict[char])
        else:
            enc_list.append(char_dict["UNK"])

    for null in range(0, length - len(url_str)):
        enc_list.append(0)

    return enc_list

top_domains = list(pd.read_csv('./RESTAPI/top250domains.csv')['domain'])
feature_list = ['length', 'subcount', 'proto', 'pathdir', 'pathlen', 'querylen', 'queryparam', 'isip', 'pathspecial',
                'domainspecial', 'hyphencount', 'domlen', 'digi2letter', 'atchar']


# feature_list = ['length', 'subcount', 'proto', 'pathdir', 'pathlen', 'querylen', 'queryparam', 'pathspecial', 'domlen', 'digi2letter']

class Url:
    def __init__(self, url, tag):
        self.tag = tag
        self.url_str = url
        self.urlparse = urlparse(url)
        self.domaininfo = tldextract.extract(self.url_str)

    #======================= Lexical Features ========================
    def is_ip(self):
        return True if self.urlparse.netloc.replace('.', '').isnumeric() else False

    def get_len(self):
        return len(self.url_str)

    def get_proto(self):
        return True if self.urlparse.scheme == 'https' else False

    def get_domain(self):
        return self.urlparse.netloc

    def get_domain_hyphen(self):
        return self.urlparse.netloc.count("-") / self.get_subdomaincount()

    def get_domainlen(self):
        return len(self.urlparse.netloc)

    def get_subdomaincount(self):
        return len(self.domaininfo.subdomain.split("."))

    def get_topdomain(self):
        return True if self.domaininfo.registered_domain in top_domains else False

    def get_pathlen(self):
        return len(self.urlparse.path)

    def get_pathdirs(self):
        if self.urlparse.path == '/':
            return 0
        else:
            return len(self.urlparse.path.split('/')) - 1

    def get_querylen(self):
        return len(self.urlparse.query)

    def get_queryparams(self):
        if self.urlparse.query == '':
            return 0
        else:
            return len(self.urlparse.query.split('&'))

    def get_specialchar(self, type='domain'):
        domain = self.urlparse.netloc.replace('.', '')
        path = self.urlparse.path.replace('/', '')
        query = self.urlparse.path.replace('&', '').replace('=', '')
        special_char_re = r'[^a-zA-Z0-9\.]'
        if type == 'domain':
            return (len(''.join(re.findall(special_char_re, domain)))) / (len(domain) + 1)
        elif type == 'path':
            return (len(''.join(re.findall(special_char_re, path)))) / (len(path) + 1)

    def get_at_char(self):
        return True if '@' in self.url_str else False

    def digit_to_letter(self):
        letter_re = r'[a-zA-Z]'
        number_re = r'[0-9]'
        return (len(''.join(re.findall(number_re, self.url_str)))) / (
                    len(''.join(re.findall(letter_re, self.url_str))) + 1)

    # def get_cnn(self):
    #   res = model_char(tf.constant([get_encoding_proto(self.url_str, 200)]))
    #   return float(res[0][1])

    def generate_df(self):
        rf_df = pd.DataFrame(columns=feature_list)
        rf_df['length'] = [self.get_len()]
        rf_df['subcount'] = [self.get_subdomaincount()]
        rf_df['proto'] = [self.get_proto()]
        rf_df['pathdir'] = [self.get_pathdirs()]
        rf_df['pathlen'] = [self.get_pathlen()]
        rf_df['querylen'] = [self.get_querylen()]
        rf_df['queryparam'] = [self.get_queryparams()]
        rf_df['isip'] = [self.is_ip()]
        rf_df['pathspecial'] = [self.get_specialchar('path')]
        rf_df['domainspecial'] = [self.get_specialchar('domain')]
        rf_df['digi2letter'] = [self.digit_to_letter()]
        rf_df['hyphencount'] = [self.get_domain_hyphen()]
        rf_df['domlen'] = [self.get_domainlen()]
        rf_df['atchar'] = [self.get_at_char()]
        # rf_df['topdomain'] = [self.get_topdomain()]
        # rf_df['cnn'] = [self.get_cnn()]
        # rf_df['expiration'] = [self.get_expiration_time()]
        # rf_df['label'] = [self.tag]s
        return rf_df

class LiveUrl(Url):
    def __init__(self, url, tag):
        global service, capabilities
        super().__init__(url, tag)
        print("[*] Getting info for " + url)
        self.dns = self.get_dns()

        self.link_dict = None
        self.uniq_dom = None

        if self.dns is True:
            self.driver = webdriver.Remote(service.service_url, desired_capabilities=capabilities)
            self.driver.set_window_size(1920, 2400)
            self.driver.get(self.url_str)
            self.final_url = self.driver.current_url
            print(self.final_url)

            print(get_status(self.driver.get_log('performance')))

            self.screenshot = self.get_64snapshot()
            self.whois = whois.whois(self.url_str)
            self.cert = self.get_cert()
            print(self.cert)

            print(self.get_lang())
            print(self.get_links_uniqdom())
            self.get_uniqlocal()

        self.driver.quit()
            # print(self.cert.has_expired())
            # print(self.cert.get_pubkey())

    # ======================= Live Features ========================

    def get_dns(self):
        try:
            socket.gethostbyname(self.urlparse.netloc)
            print(socket.gethostbyname(self.urlparse.netloc))
        except socket.gaierror:
            return False
        else:
            return True

    def get_64snapshot(self):
        ss = self.driver.get_screenshot_as_base64()
        # self.driver.save_screenshot(str(self.urlparse.netloc) + '.png')
        return "data:image/png;base64,"+ss

    def get_dates(self, key='expiration'):
        w = self.whois
        if key == 'expiration':
            if type(w.expiration_date) is list:
                date = w.expiration_date[0]
            else:
                date = w.expiration_date
            t = date - datetime.today()
            t = t.days
        elif key == 'creation':
            if type(w.creation_date) is list:
                date = w.creation_date[0]
            else:
                date = w.creation_date
            t = datetime.today() - date
            t = t.days
        else:
            t = None
        return t

    def get_cert(self):
        conn = ssl.create_connection((self.urlparse.netloc, 443))
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sock = context.wrap_socket(conn, server_hostname=self.urlparse.netloc)
        cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        # cert = ssl.get_server_certificate((self.urlparse.netloc, 443))
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        return cert

    def get_lang(self):
        res_source = self.driver.page_source
        html_re = r'(<style.*>[^<]*<\/style>|<script.*>[^<]*<\/script>|<[^>]*>)'
        body_text = re.sub(html_re, '', res_source)
        t = detect_langs(body_text)
        return t

    def get_links_uniqdom(self):
        soup = BeautifulSoup(self.driver.page_source, features='lxml')
        links = soup.find_all('a')
        link_dict = {'loc': [], 'ext': [], 'static': [], 'mail': []}
        uniq_dom = {}
        link_count = 0
        for link in links:
            link = link.get('href')
            link_count += 1
            if link is None or len(link) == 0 or link[0] == "#" or link[0] == "?" or "javascript:" in link:
                link_dict['static'].append(link)
            elif 'mailto:' in link:
                mail_dom = link.split("@")[1]
                link_dict['mail'].append(mail_dom)
            elif link[0] == "/" or tldextract.extract(link).registered_domain == self.domaininfo.registered_domain or "://" not in link:
                link_dict['loc'].append(link)
            else:
                base_dom = tldextract.extract(link).registered_domain
                if base_dom not in uniq_dom:
                    uniq_dom.update({base_dom: 1})
                else:
                    uniq_dom[base_dom] += 1
                link_dict['ext'].append(link)
        print("loc %:" + str(len(link_dict['loc'])/link_count*100))
        print("ext %:" + str(len(link_dict['ext'])/link_count*100))
        print("static %:" + str(len(link_dict['static'])/link_count*100))
        for key, value in uniq_dom.items():
            print(str(key) + ": " + str((value/(len(link_dict['loc']) + len(link_dict['ext'])))*(len(link_dict['ext'])/link_count + len(link_dict['static'])/link_count)))
        print(link_dict)
        print(uniq_dom)
        self.link_dict = link_dict
        self.uniq_dom = uniq_dom
        return None

    def get_uniqlocal(self):
        uniq_loc = list(dict.fromkeys(self.link_dict['loc']))
        print(uniq_loc)
        print(len(uniq_loc)/len(self.link_dict['loc']))




# new_phish = Url("https://changewill.setamazonup.xyz/signim/", 1)
# new_phish = LiveUrl("https://centralcrconsulta.com/", 1)
new_benign = LiveUrl("https://services.runescape.com-vzla.ru/m=forum/forums.ws634,826,296,28381439,1136", 0)
new_benign = LiveUrl("https://puffsandpeaks.com", 0)
# print(new_phish.get_dates(key='creation'))
# print(new_phish.get_dates(key='expiration'))
# print("\n")
# print(new_benign.get_dates(key='creation'))
# print(new_benign.get_dates(key='expiration'))
# print(new_benign.get_val())
# print(new_phish.get_val())
# print(new_phish.get_lang())
# print(new_phish.get_lang())
# print(new_phish.get_lang())
# print(new_benign.get_cert())
# print(new_phish.get_links_uniqdom())
# new_phish.get_links()
