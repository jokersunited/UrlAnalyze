from urllib.parse import urlparse
import pandas as pd
import ssl, OpenSSL, re, whois, tldextract, time, socket, json, requests
from datetime import datetime
from langdetect import detect_langs
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup

from ocspchecker import ocspchecker


def get_status(logs):
    """
    Extract page responses form selenium logs
    :param logs: Log object from selenium
    :return: List of [status, url, type] for each request
    """
    statuses = []
    lol = json.dumps(logs)
    for log in logs:
        if log['message']:
            d = json.loads(log['message'])
            if d['message'].get('method') == "Network.responseReceived":
                statuses.append(
                    [d['message']['params']['response']['status'], d['message']['params']['response']['url'],
                     d['message']['params']['type']])
    return statuses


# Generate a dictionary with character mapping
def gen_char_dict():
    """
    Generates a character dictionary with integer mapping
    :return: Dictionary of characters mapped to an integer
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-;.!?:'\"/\|_@#$%^&*~`+-=<>()[]{}"
    char_dict = {}
    char_dict["null"] = 0
    for i, char in enumerate(alphabet):
        char_dict[char] = i + 1
    char_dict["UNK"] = len(alphabet) + 1
    return char_dict


char_dict = gen_char_dict()

############## Initialise Selenium ##############

# Initialse parameters for Selenium headless chrome browser
user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36'
options = webdriver.ChromeOptions()
options.add_argument(f'user-agent={user_agent}')
options.add_argument('--headless')
options.add_argument('ignore-certificate-errors')

# Enable performance logging to trace requests and response information
capabilities = options.to_capabilities()
capabilities['goog:loggingPrefs'] = {'performance': 'ALL'}

# Start a selenium service so can call it and we don't need to create an instance for every URL
service = webdriver.chrome.service.Service(ChromeDriverManager().install())
service.start()


# Remove protocol from URL
def strip_proto(s):
    """
    Removes protocol text from URLs
    :param s: String to remove protocol
    :return: String with protocol removed
    """
    return s.replace("https://", "").replace("http://", "").replace("www.", "")


# Map the URL to its respective character encoding integer
def get_encoding_proto(url, length):
    """
    Maps the URL to its respective character encoding integer
    :param url: String representation of the URL
    :param length: Max length of the URL
    :return: List of integers representing the characters of the URL
    """
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


# Read the top domains from the specified CSV file
top_domains = list(pd.read_csv('./RESTAPI/top250domains.csv')['domain'])

# Declare the features to be used in the RF Classifier
feature_list = ['length', 'subcount', 'proto', 'pathdir', 'pathlen', 'querylen', 'queryparam', 'isip', 'pathspecial',
                'domainspecial', 'hyphencount', 'domlen', 'digi2letter', 'atchar']


class Url:
    def __init__(self, url, tag=None):
        """
        URL class to store information of URLs
        :param url: String representation of URL
        :param tag: Label if it is phishing or not, None if unknown
        """
        self.tag = tag
        self.url_str = url
        self.urlparse = urlparse(url)
        self.domaininfo = tldextract.extract(self.url_str)

    # ======================= Lexical Features ========================
    def is_ip(self):
        """
        Checks if URL is an IP address
        :return: True if URL is an IP address and False if not
        """
        return True if self.urlparse.netloc.replace('.', '').isnumeric() else False

    def get_len(self):
        """
        Get length of URL
        :return: Integer value of the length of the URL
        """
        return len(self.url_str)

    def get_proto(self):
        """
        Get the protocol used by the URL, if it is HTTPS or not
        :return: True if HTTPS is used, False if not
        """
        return True if self.urlparse.scheme == 'https' else False

    def get_domain(self):
        """
        Get the full domain of the URL
        :return: String representation of the full domain
        """
        return str(self.urlparse.netloc)

    def get_domain_hyphen(self):
        """
        Get the ratio of hypens to subdomain count
        :return: Float value of the ratio
        """
        return self.urlparse.netloc.count("-") / self.get_subdomaincount()

    def get_domainlen(self):
        """
        Get the total length of the domain
        :return: Integer value of the total domain length
        """
        return len(self.urlparse.netloc)

    def get_subdomaincount(self):
        """
        Get the number of subdomains in the URL
        :return: Integer value of the number of subdomains
        """
        return len(self.domaininfo.subdomain.split("."))

    def get_topdomain(self):
        """
        Check if registered domain is in the top list of domains
        :return: Returns True if registered domain is in the top list of domains and False if not
        """
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
        print("\n[*] Getting info for " + url)
        self.dns = self.get_dns()

        self.link_dict = None
        self.uniq_dom = None
        self.link_count = 0
        self.spoof = {}

        if self.dns is True:
            self.driver = webdriver.Remote(service.service_url, desired_capabilities=capabilities)
            self.driver.set_window_size(1920, 2400)
            self.driver.get(self.url_str)
            self.final_url = self.driver.current_url

            self.screenshot = self.get_64snapshot()
            self.whois = whois.whois(self.url_str)
            if self.urlparse.scheme == 'https':
                self.cert = self.get_cert()
            else:
                self.cert = None

            # self.flagged_dict = self.check_text(phishwords=wordFrame)
            # self.get_flaggedpercent()

            # print(self.get_lang())
            self.get_links_uniqdom()
            # print(self.cert.has_expired())

            self.print_cmdreport()

        self.driver.quit()
        # print(self.cert.has_expired())
        # print(self.cert.get_pubkey())

    def print_cmdreport(self):
        print("\n===== Page Info =====")
        print("Destination URL: " + str(self.final_url))
        print("Destination Title: " + str(self.driver.title))
        print("Language: " + str(self.get_lang()))

        print("\n===== Domain Info =====")
        print(self.whois)
        print("Registrar: " + str(self.whois.registrar))
        if type(self.whois.creation_date) is list:
            print("Creation Date: " + str(self.whois.creation_date[0]))
        else:
            print("Creation Date: " + str(self.whois.creation_date))
        if type(self.whois.expiration_date) is list:
            print("Expiry Date: " + str(self.whois.expiration_date[0]))
        else:
            print("Expiry Date: " + str(self.whois.expiration_date))
        print("Abuse Emails: ")
        if type(self.whois.emails) is list:
            for x in self.whois.emails: print("- " + str(x))
        else:
            print("- " + str(self.whois.emails))

        print("\n===== Cert Info =====")
        if self.cert is not None:
            print("Cert Issuer: " + str(self.cert.get_issuer().CN) + " " + str(self.cert.get_issuer().O))
            print("Cert Expired?: " + str(self.cert.has_expired()))
            ocsp_request = ocspchecker.get_ocsp_status(self.final_url)
            ocsp_status = [i for i in ocsp_request if "OCSP Status:" in i][0]
            print("Cert Validity: " + str(ocsp_status.split(":")[1][1:]))
        else:
            print("No SSL Cert Found!")

        print("\n===== Initiated Requests =====")
        for index, item in enumerate(get_status(self.driver.get_log('performance'))):
            print("Request " + str(index + 1) + ": " + str(item[0]) + ', ' + item[2] + ', ' + item[1])
        if self.link_count != 0:
            print("\n===== Hyperlink Info =====")
            print("Total links: " + str(self.link_count))
            print("\nloc %:" + str(len(self.link_dict['loc']) / self.link_count * 100))
            print("ext %:" + str(len(self.link_dict['ext']) / self.link_count * 100))
            print("static %:" + str(len(self.link_dict['static']) / self.link_count * 100))

            if len(self.uniq_dom.keys()) > 0:
                print("\nUnique external domains: ")
                for key in self.uniq_dom.keys():
                    print("- " + key)
            if len(self.link_dict['loc']) > 0:
                print("\nUnique local links %: " + str(self.get_uniqlocal() * 100))
            else:
                print("\nNo Local Links!")

            print("\n===== Potential Spoof Domain Scores =====")
            for key, value in self.spoof.items():
                if value > 0.4: print(key + ": " + str(value))

        else:
            print("\nNo hyperlinks on page!")

    # ======================= Live Features ========================

    def get_dns(self):
        try:
            self.addr_info = socket.getaddrinfo(self.urlparse.netloc, None)
            print(addr_info)
        except socket.gaierror:
            return False
        else:
            return True

    def get_64snapshot(self):
        ss = self.driver.get_screenshot_as_base64()
        self.driver.save_screenshot('./images/' + str(self.urlparse.netloc) + '.png')
        return "data:image/png;base64," + ss

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

    def clean_text(self):
        res_source = self.driver.page_source
        html_re = r'(<style.*>[^<]*<\/style>|<script[\s\S]*?><\/script>|<script.*>[\s\S]*?<\/script>|<[^>]*>)'
        body_text = re.sub(html_re, '', res_source)
        text_list = body_text.replace("\n", " ").replace("\t", " ").split(" ")
        clean_text = [x for x in text_list if x]
        return clean_text

    def get_lang(self):
        res_source = self.driver.page_source
        html_re = r'(<style.*>[^<]*<\/style>|<script[\s\S]*?><\/script>|<script.*>[\s\S]*?<\/script>|<[^>]*>)'
        body_text = re.sub(html_re, '', res_source)
        t = detect_langs(body_text)
        return t

    def get_links_uniqdom(self):
        soup = BeautifulSoup(self.driver.page_source, features='lxml')
        links = soup.find_all('a')
        link_dict = {'loc': [], 'ext': [], 'static': [], 'mail': []}
        uniq_dom = {}
        for link in links:
            link = link.get('href')
            self.link_count += 1
            if link is None or len(link) == 0 or link[0] == "#" or link[0] == "?" or "javascript:" in link:
                link_dict['static'].append(link)
            elif 'mailto:' in link:
                mail_dom = link.split("@")[1]
                link_dict['mail'].append(mail_dom)
            elif link[0] == "/" or tldextract.extract(
                    link).registered_domain == self.domaininfo.registered_domain or "://" not in link:
                link_dict['loc'].append(link)
            else:
                base_dom = tldextract.extract(link).registered_domain
                if base_dom not in uniq_dom:
                    uniq_dom.update({base_dom: 1})
                else:
                    uniq_dom[base_dom] += 1
                link_dict['ext'].append(link)
        for key, value in uniq_dom.items():
            self.spoof.update({str(key): (value / (len(link_dict['loc']) + len(link_dict['ext']))) * (
                        len(link_dict['ext']) / self.link_count + len(link_dict['static']) / self.link_count)})
            # print(str(key) + ": " + str((value/(len(link_dict['loc']) + len(link_dict['ext'])))*(len(link_dict['ext'])/link_count + len(link_dict['static'])/link_count)))
        self.link_dict = link_dict
        self.uniq_dom = uniq_dom

    def get_uniqlocal(self):
        uniq_loc = list(dict.fromkeys(self.link_dict['loc']))
        return len(uniq_loc) / len(self.link_dict['loc'])


# new_phish = Url("https://changewill.setamazonup.xyz/signim/", 1)
# new_phish = LiveUrl("https://centralcrconsulta.com/", 1)
# new_benign = LiveUrl("https://services.runescape.com-vzla.ru/m=forum/forums.ws634,826,296,28381439,1136", 0)
# new_benign = LiveUrl("https://acc-recover-police.langsung-barbar.xyz/", 0)
# new_benign = LiveUrl("https://www.linechecks.info/", 0)
new_benign = LiveUrl("https://www.puffsandpeaks.com", 0)
# new_benign = LiveUrl("https://revoked.badssl.com/", 0)
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
