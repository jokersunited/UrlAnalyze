import json
from urllib.parse import urlparse
import tldextract
import pandas as pd
import re

top_domains = list(pd.read_csv('./top250domains.csv')['domain'])
feature_list = ['length', 'subcount', 'proto', 'pathdir', 'pathlen', 'querylen', 'queryparam', 'isip', 'pathspecial',
                'domainspecial', 'hyphencount', 'domlen', 'digi2letter', 'atchar']

class Url:
    def __init__(self, url):
        # print(url)
        self.url_str = url
        self.urlparse = urlparse(url)
        self.domaininfo = tldextract.extract(self.url_str)
        self.df = self.generate_df()

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
        return rf_df


    def generate_raw_json(self):
        return json.loads(self.df.iloc[0].to_json())


