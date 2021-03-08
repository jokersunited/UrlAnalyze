from urllib.parse import urlparse
import tldextract
import pandas as pd
import ssl, OpenSSL
import re, whois
from datetime import datetime
from googletrans import Translator

def gen_char_dict():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-;.!?:'\"/\|_@#$%^&*~`+-=<>()[]{}"
    char_dict = {}
    char_dict["null"] = 0
    for i, char in enumerate(alphabet):
        char_dict[char] = i + 1
    char_dict["UNK"] = len(alphabet)+1
    return char_dict

char_dict = gen_char_dict()

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
        # print(url)
        self.tag = tag
        self.url_str = url
        self.urlparse = urlparse(url)
        self.domaininfo = tldextract.extract(self.url_str)
        self.whois = whois.whois(self.url_str)
        self.cert = self.get_cert()

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

    #======================= Live Features ========================
    def get_dates(self, key='expiration'):
        w = self.whois
        if key == 'expiration':
            if type(w.expiration_date) is list:
                date = w.expiration_date[0]
            else:
                date = w.expiration_date
            time = date - datetime.today()
            t = time.days
        elif key == 'creation':
            if type(w.creation_date) is list:
                date = w.creation_date[0]
            else:
                date = w.creation_date
            time = datetime.today() - date
            t = time.days
        return t

    def get_cert(self):

        conn = ssl.create_connection((self.urlparse.netloc, 443))
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sock = context.wrap_socket(conn, server_hostname=self.urlparse.netloc)
        self.cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        self.cert = ssl.get_server_certificate((self.urlparse.netloc, 443))
        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert)
        return self.cert

    def get_val(self):
        print(self.cert)
        date = datetime.today() - datetime.strptime(self.cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        return True if date.days < 0 else False

    def get_lang(self):

        t = Translator().detect("hello world!")
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


# new_phish = Url("https://changewill.setamazonup.xyz/signim/", 1)
new_phish = Url("https://facebook.com", 1)
new_benign = Url("https://puffsandpeaks.com", 0)
# print(new_phish.get_dates(key='creation'))
# print(new_phish.get_dates(key='expiration'))
# print("\n")
# print(new_benign.get_dates(key='creation'))
# print(new_benign.get_dates(key='expiration'))
print(new_benign.get_val())
print(new_phish.get_val())
