# Exraction of features from the URL
#  0   having_IP_Address
#  1   URL_Length
#  2   Shortining_Service
#  3   having_At_Symbol
#  4   double_slash_redirecting
#  5   Prefix_Suffix
#  6   having_Sub_Domain
#  7   URL_Depth
#  8   Domain_registeration_length
#  9   Favicon
#  10  port
#  11  HTTPS_token
#  12  Request_URL
#  13  URL_of_Anchor
#  14  Links_in_tags
#  15  SFH
#  16  Submitting_to_email
#  17  Abnormal_URL
#  18  Redirect
#  19  on_mouseover
#  20  RightClick
#  21  popUpWidnow
#  22  Iframe
#  23  age_of_domain
#  24  DNSRecord
#  25  web_traffic

# Above fetatures function returns
# 1 if the URL is Phishing,
# -1 if the URL is Legitimate and
# 0 if the URL is Suspicious

import re
import whois
import datetime
import requests
import ipaddress
from dns import resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.parsedurl = urlparse(self.url)
        self.domain = self.parsedurl.netloc

        try:
            self.whois = whois.whois(self.domain)
        except:
            self.whois = None

        try:
            self.request = requests.get(self.url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
            self.soup = BeautifulSoup(self.request.content, 'html.parser')
        except:
            self.request = None
            self.soup = None

        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
            r"tr\.im|link\.zip\.net"

    def getFeaturesDict(self):
        return {
            "having_IP_Address": self.having_IP_Address(),
            "URL_Length": self.URL_Length(),
            "Shortining_Service": self.Shortining_Service(),
            "having_At_Symbol": self.having_At_Symbol(),
            "double_slash_redirecting": self.double_slash_redirecting(),
            "Prefix_Suffix": self.Prefix_Suffix(),
            "having_Sub_Domain": self.having_Sub_Domain(),
            "URL_Depth": self.URL_Depth(),
            "Domain_registeration_length": self.Domain_registeration_length(),
            "Favicon": self.Favicon(),
            "port": self.port(),
            "HTTPS_token": self.HTTPS_token(),
            "Request_URL": self.Request_URL(),
            "URL_of_Anchor": self.URL_of_Anchor(),
            "Links_in_tags": self.Links_in_tags(),
            "SFH": self.SFH(),
            "Submitting_to_email": self.Submitting_to_email(),
            "Abnormal_URL": self.Abnormal_URL(),
            "Redirect": self.Redirect(),
            "on_mouseover": self.on_mouseover(),
            "RightClick": self.RightClick(),
            "popUpWidnow": self.popUpWidnow(),
            "Iframe": self.Iframe(),
            "age_of_domain": self.age_of_domain(),
            "DNSRecord": self.DNSRecord(),
            "web_traffic": self.web_traffic()
        }

    """#### ** IP Address in the URL **
    Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name. If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone is trying to steal personal information with this URL.
    If the domain part of URL has IP address, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def having_IP_Address(self):
        try:
            ipaddress.ip_address(self.domain)
            return 1
        except:
            return -1

    """#### ** Length of URL **
    Computes the length of the URL. Phishers can use long URL to hide the doubtful part in the address bar. In this project, if the length of the URL is greater than or equal 54 characters then the URL classified as phishing otherwise legitimate.
    If the length of URL >= 54 , the value assigned to this feature is 1 (phishing) or else 0 (suspicious) else -1 (legitimate).
    """

    def URL_Length(self):
        if len(self.url) < 54:
            return -1
        elif len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        else:
            return 1

    """#### ** Using URL Shortening Services “TinyURL” **
    URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL. 
    If the URL is using Shortening Services, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Shortining_Service(self):
        if re.search(self.shortening_services, self.url):
            return 1
        else:
            return -1

    """#### ** "@" Symbol in URL **
    Checks for the presence of '@' symbol in the URL. Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol. 
    If the URL has '@' symbol, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def having_At_Symbol(self):
        if '@' in self.url:
            return 1
        else:
            return -1

    """#### ** Redirection "//" in URL **
    Checks the presence of "//" in the URL. The existence of “//” within the URL path means that the user will be redirected to another website. The location of the “//” in URL is computed.
    If the "//" is anywhere in the URL apart from after the protocal, thee value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def double_slash_redirecting(self):
        if re.search(r'https?://[^\s]*//', self.url):
            return 1
        else:
            return -1

    """#### ** Prefix or Suffix "-" in Domain **
    Checking the presence of '-' in the domain part of URL. The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. 
    If the URL has '-' symbol in the domain part of the URL, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Prefix_Suffix(self):
        if '-' in self.domain:
            return 1
        else:
            return -1

    """#### ** SubDomains **    
    If the URL has more than 2 subdomains, the value assigned to this feature is 1 (phishing) or else 0 (suspicious) else -1 (legitimate).
    """

    def having_Sub_Domain(self):
        count = self.domain.count('.')
        if count <= 2:
            return -1
        elif count > 2 and count <= 3:
            return 0
        else:
            return 1

    """#### ** Depth of URL **
    Computes the depth of the URL. This feature calculates the number of sub pages in the given url based on the '/'.
    The value of feature is a numerical based on the URL.
    """

    def URL_Depth(self):
        depth = 0
        subdirs = self.parsedurl.path.split('/')
        for subdir in subdirs:
            if subdir:
                depth += 1
        return depth

    """#### ** End Period of Domain **
    This feature can be extracted from WHOIS database. For this feature, the remaining domain time is calculated by finding the different between expiration time & current time. The end period considered for the legitimate domain is 6 months or more for this project. 
    If end period of domain < 6 months, the vlaue of this feature is 1 (phishing) else -1 (legitimate).
    """

    def Domain_registeration_length(self):
        if self.whois is None:
            return 1

        try:
            if type(self.whois['expiration_date']) is list:
                expiration_date = self.whois['expiration_date'][0]
            else:
                expiration_date = self.whois['expiration_date']

            registration_length = abs(
                (expiration_date - datetime.datetime.now()).days)
            if registration_length / 30 >= 6:
                return -1
            else:
                return 1
        except:
            return 1

    """#### ** Favicon **
    Checks for the presence of favicon in the website. The presence of favicon in the website can be used as a feature to detect phishing websites.
    If the website has favicon, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Favicon(self):
        try:
            if re.findall(r'favicon', self.soup.text) or \
                    self.soup.find('link', rel='shortcut icon') or \
                    self.soup.find('link', rel='icon'):
                return -1
            else:
                return 1
        except:
            return 1

    """#### ** Non-Standard Port **
    Checks for the use of non-standard port. Phishers often use non-standard ports in the URL in order to make it look like a legitimate one.
    If the URL uses non-standard port, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def port(self):
        if self.parsedurl.port:
            return 1
        else:
            return -1

    """#### ** "http/https" in Domain name **
    Checks for the presence of "http/https" in the domain part of the URL. The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.
    If the URL has "http/https" in the domain part, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def HTTPS_token(self):
        if 'https' in self.domain:
            return 1
        else:
            return -1

    """### ** Request_URL **
    The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected. In our dataset, we find that legitimate websites have been redirected one time max. On the other hand, phishing websites containing this feature have been redirected at least 4 times.
    """

    def Request_URL(self):
        try:
            if len(self.request.history) <= 1:
                return -1
            elif len(self.request.history) <= 3:
                return 0
            else:
                return 1
        except:
            return -1

    """#### ** URL_of_Anchor **
    The presence of “<a>” HTML tag in the URL is a strong indicator of phishing websites. This feature checks for the presence of “<a>” tag in the URL.
    If the URL has “<a>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def URL_of_Anchor(self):
        try:
            count = 0
            for i in self.soup.find_all('a'):
                if i.has_attr('href'):
                    count += 1
            if count == 0:
                return 1
            else:
                return -1
        except:
            return 1

    """#### ** Links_in_tags **
    The presence of “<link>” HTML tag in the URL is a strong indicator of phishing websites. This feature checks for the presence of “<link>” tag in the URL.
    If the URL has “<link>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Links_in_tags(self):
        try:
            count = 0
            for i in self.soup.find_all('link'):
                if i.has_attr('href'):
                    count += 1
            if count == 0:
                return 1
            else:
                return -1
        except:
            return 1

    """#### ** SFH **
    The presence of “<form>” HTML tag in the URL is a strong indicator of phishing websites. This feature checks for the presence of “<form>” tag in the URL.
    If the URL has “<form>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def SFH(self):
        try:
            if self.soup.find('form'):
                return 1
            else:
                return -1
        except:
            return 0

    """#### ** Submitting_to_email **
    The presence of “mailto:” in the URL is a strong indicator of phishing websites. This feature checks for the presence of “mailto:” in the URL.
    If the URL has “mailto:” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Submitting_to_email(self):
        try:
            if self.soup.find('mailto:'):
                return 1
            else:
                return -1
        except:
            return 0

    """#### ** Abnormal_URL **
    The presence of “<script>” HTML tag in the URL is a strong indicator of phishing websites. This feature checks for the presence of “<script>” tag in the URL.
    If the URL has “<script>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Abnormal_URL(self):
        try:
            if re.findall(r'script|javascript|alert|onmouseover|onload|onerror|onclick|onmouse', self.url):
                return 1
            else:
                return -1
        except:
            return -1

    """#### ** Redirect **
    The presence of “<meta>” HTML tag in the URL is a strong indicator of phishing websites. This feature checks for the presence of “<meta>” tag in the URL.
    If the URL has “<meta>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Redirect(self):
        try:
            if self.soup.find('meta', attrs={'http-equiv': 'refresh'}):
                return 1
            else:
                return -1
        except:
            return -1

    """### **3.3.2. Status Bar Customization**
    Phishers may use JavaScript to show a fake URL in the status bar to users. To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event, and check if it makes any changes on the status bar
    If the response is empty or onmouseover is found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
    """

    def on_mouseover(self):
        try:
            if re.findall(r"onmouseover", self.soup.text):
                return 1
            else:
                return -1
        except:
            return -1

    """### ** Disabling Right Click **
    Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.
    If the response is empty or onmouseover is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
    """

    def RightClick(self):
        try:
            if re.findall(r"contextmenu|event.button ?== ?2", self.soup.text):
                return 1
            else:
                return -1
        except:
            return -1

    """### ** PopUp Window **
    Phishers may use JavaScript to open a fake webpage in a new window to trick users. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “window.open” in the webpage source code and check if the pop-up window is opened.
    If the response is empty or onmouseover is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
    """

    def popUpWidnow(self):
        try:
            if re.findall(r"alert\(|onMouseOver|window.open", self.soup.text):
                return 1
            else:
                return -1
        except:
            return -1

    """### ** IFrame Redirection **
    IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders. In this regard, phishers make use of the “frameBorder” attribute which causes the browser to render a visual delineation. 
    If the iframe is empty or repsonse is not found then, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Iframe(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.soup.text):
                return 1
            else:
                return -1
        except:
            return -1

    """#### ** Age of Domain **
    This feature can be extracted from WHOIS database. Most phishing websites live for a short period of time. The minimum age of the legitimate domain is considered to be 12 months for this project. Age here is nothing but different between creation and expiration time.
    If age of domain > 12 months, the vlaue of this feature is 1 (phishing) else -1 (legitimate).
    """

    def age_of_domain(self):
        if self.whois is None:
            return 1

        try:
            if type(self.whois['creation_date']) is list:
                creation_date = self.whois['creation_date'][0]
            else:
                creation_date = self.whois['creation_date']

            ageofdomain = abs((datetime.datetime.now() - creation_date).days)
            if ageofdomain / 30 > 12:
                return -1
            else:
                return 1
        except:
            return 1

    """#### ** DNS Record **
    For phishing websites, either the claimed identity is not recognized by the WHOIS database or no records founded for the hostname. 
    If the DNS record is empty or not found then, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def DNSRecord(self):
        try:
            resolver.resolve(self.domain, 'A')
            return -1
        except:
            return 1

    """#### ** Web Traffic **
    This feature measures the popularity of the website by determining the number of visitors and the number of pages they visit. However, since phishing websites live for a short period of time, they may not be recognized by the Alexa database (Alexa the Web Information Company., 1996). By reviewing our dataset, we find that in worst scenarios, legitimate websites ranked among the top 100,000. Furthermore, if the domain has no traffic or is not recognized by the Alexa database, it is classified as “Phishing”.
    If the rank of the domain < 100000, the vlaue of this feature is 1 (phishing) else -1 (legitimate).
    """

    def web_traffic(self):
        try:
            alexadata = BeautifulSoup(requests.get(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + self.domain, timeout=10).content, 'lxml')
            rank = int(alexadata.find('reach')['rank'])
            if rank < 100000:
                return -1
            else:
                return 1
        except:
            return 1
