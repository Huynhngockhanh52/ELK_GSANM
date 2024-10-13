import re
from urllib.parse import urlparse

class PreURL:
    # Đếm số lượng dấu chấm (.) trong URL.
    @staticmethod
    def count_dot(url):
        return url.count('.')

    # Đếm số lượng thư mục trong URL (số lượng dấu /).
    @staticmethod
    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')

    # Đếm số lần xuất hiện của ký tự // trong URL.
    @staticmethod
    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')

    # Đếm số lần xuất hiện của từ khóa http trong URL.
    @staticmethod
    def count_http(url):
        return url.count('http')

    # Đếm số lượng ký tự % trong URL.
    @staticmethod
    def count_per(url):
        return url.count('%')

    # Đếm số lượng dấu hỏi (?) trong URL.
    @staticmethod
    def count_ques(url):
        return url.count('?')

    # Đếm số lượng dấu gạch ngang (-).
    @staticmethod
    def count_hyphen(url):
        return url.count('-')

    # Đếm số lượng dấu = trong URL.
    @staticmethod
    def count_equal(url):
        return url.count('=')

    # Kiểm tra xem URL có sử dụng các dịch vụ rút gọn liên kết không (như bit.ly, goo.gl).
    @staticmethod
    def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net',
                          url)
        return 1 if match else 0

    # URL length
    @staticmethod
    def url_length(url):
        return len(str(url))

    # Hostname Length
    @staticmethod
    def hostname_length(url):
        return len(urlparse(url).netloc)

    # Tính điểm cho URL dựa trên sự xuất hiện của các từ khóa nghi ngờ (như SELECT, DROP, admin, v.v.).
    @staticmethod
    def suspicious_words(url):
        score_map = {
            'error': 30,
            'errorMsg': 30,
            'id': 10,
            'errorID': 30,
            'SELECT': 50,
            'FROM': 50,
            'WHERE': 50,
            'DELETE': 50,
            'USERS': 50,
            'DROP': 50,
            'CREATE': 50,
            'INJECTED': 50,
            'TABLE': 50,
            'alert': 30,
            'javascript': 20,
            'cookie': 25,
            '--': 30,
            '.exe': 30,
            '.php': 20,
            '.js': 10,
            'admin': 10,
            'administrator': 10,
            '\'': 30,
            'password': 15,
            'login': 15,
            'incorrect': 20,
            'pwd': 15,
            'tamper': 25,
            'vaciar': 20,
            'carrito': 25,
            'wait': 30,
            'delay': 35,
            'set': 20,
            'steal': 35,
            'hacker': 35,
            'proxy': 35,
            'location': 30,
            'document.cookie': 40,
            'document': 20,
            'set-cookie': 40,
            'create': 40,
            'cmd': 40,
            'dir': 30,
            'shell': 40,
            'reverse': 30,
            'bin': 20,
            'cookiesteal': 40,
            'LIKE': 30,
            'UNION': 35,
            'include': 30,
            'file': 20,
            'tmp': 25,
            'ssh': 40,
            'exec': 30,
            'cat': 25,
            'etc': 30,
            'fetch': 25,
            'eval': 30,
            'wait': 30,
            'malware': 45,
            'ransomware': 45,
            'phishing': 45,
            'exploit': 45,
            'virus': 45,
            'trojan': 45,
            'backdoor': 45,
            'spyware': 45,
            'rootkit': 45,
            'credential': 30,
            'inject': 30,
            'script': 25,
            'iframe': 25,
            'src=': 25,
            'onerror': 30,
            'prompt': 20,
            'confirm': 20,
            'eval': 25,
            'expression': 30,
            'function\(': 20,
            'xmlhttprequest': 30,
            'xhr': 20,
            'window.': 20,
            'document.': 20,
            'cookie': 25,
            'click': 15,
            'mouseover': 15,
            'onload': 20,
            'onunload': 20,
        }

        matches = re.findall(r'(?i)' + '|'.join(score_map.keys()), url)
        total_score = sum(score_map.get(match.lower(), 0) for match in matches)
        return total_score

    # Đếm số lượng ký tự số trong URL.
    @staticmethod
    def digit_count(url):
        return sum(i.isnumeric() for i in url)

    # Đếm số lượng ký tự chữ cái trong URL.
    @staticmethod
    def letter_count(url):
        return sum(i.isalpha() for i in url)

    # Đếm số lượng ký tự đặc biệt không phải chữ hoặc số.
    @staticmethod
    def count_special_characters(url):
        special_characters = re.sub(r'[a-zA-Z0-9\s]', '', url)
        return len(special_characters)

    # Tính số lượng tham số trong phần query của URL.
    @staticmethod
    def number_of_parameters(url):
        params = urlparse(url).query
        return 0 if params == '' else len(params.split('&'))

    # Tính số lượng đoạn trong URL (phần sau dấu #).
    @staticmethod
    def number_of_fragments(url):
        frags = urlparse(url).fragment
        return len(frags.split('#')) - 1 if frags != '' else 0

    # Kiểm tra xem URL có được mã hóa hay không (bằng cách tìm %).
    @staticmethod
    def is_encoded(url):
        return int('%' in url.lower())

    # Tính tỷ lệ ký tự không bình thường so với tổng số ký tự trong URL.
    @staticmethod
    def unusual_character_ratio(url):
        total_characters = len(url)
        unusual_characters = re.sub(r'[a-zA-Z0-9\s\-._]', '', url)
        unusual_count = len(unusual_characters)
        ratio = unusual_count / total_characters if total_characters > 0 else 0
        return ratio
